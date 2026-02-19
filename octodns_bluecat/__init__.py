# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Russell Sutherland, University of Toronto
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
octodns_bluecat — BlueCat Address Manager (BAM) REST API v2 provider for octodns.

Auth:   POST /api/v2/sessions  →  Bearer token
Scope:  All DNS records are view-scoped; `view` must be set in provider config.
Paging: GET endpoints return  {"data": [...], "count": N, "totalCount": N}
        We use ?offset=&limit= pagination everywhere.
"""

from __future__ import annotations

import logging
from time import time
from typing import Any

from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

__VERSION__ = "0.0.1"
__all__ = ["BlueCatProvider"]

# ── BAM record‑type → octodns type mapping ─────────────────────────────────

_BAM_TO_OCTO: dict[str, str] = {
    "ARecord": "A",
    "AAAARecord": "AAAA",
    "AliasRecord": "CNAME",
    "MXRecord": "MX",
    "TXTRecord": "TXT",
    "NSRecord": "NS",
    "PTRRecord": "PTR",
    "SRVRecord": "SRV",
    "CAARecord": "CAA",
    # GenericRecord is handled separately via recordType field
}

# GenericRecord subtypes we support (recordType field value → octodns type)
_GENERIC_RR_TO_OCTO: dict[str, str] = {
    "A": "A",
    "AAAA": "AAAA",
    "CNAME": "CNAME",
    "MX": "MX",
    "TXT": "TXT",
}

_OCTO_TO_BAM: dict[str, str] = {v: k for k, v in _BAM_TO_OCTO.items()}

# record types this provider can read *and* write
SUPPORTS = set(_BAM_TO_OCTO.values())
# BAM v2 does not expose SSHFP/TLSA/NAPTR/DNSKEY/DS natively
SUPPORTS.discard("PTR")          # read-only; managed by DHCP deployment in BAM


class BlueCatClientException(ProviderException):
    pass


class BlueCatClientAuthException(BlueCatClientException):
    pass


class BlueCatClient:
    """
    Thin wrapper around the BAM REST API v2.

    Key design decisions
    --------------------
    * One requests.Session per provider instance, shared across calls.
    * Bearer token is re-fetched automatically when it expires or a 401 is
      received (happens during long-running syncs).
    * All list endpoints are paginated with limit/offset; callers get a plain
      Python list back.
    * Every mutating call raises BlueCatClientException on non-2xx status so
      that octodns can surface the error cleanly.
    """

    DEFAULT_PAGE_SIZE = 100
    # BAM tokens are valid for 24 h by default; we refresh 5 min early.
    TOKEN_TTL_BUFFER = 300

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        confname: str,
        view: str,
        page_size: int = DEFAULT_PAGE_SIZE,
        timeout: int = 30,
    ) -> None:
        self.log = logging.getLogger(f"BlueCatClient[{base_url}]")
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.confname = confname
        self.view = view
        self.page_size = page_size
        self.timeout = timeout

        self._token: str | None = None
        self._token_expiry: float = 0.0

        # persistent HTTP session with retry on transient failures
        self._session = Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist={429, 500, 502, 503, 504},
            allowed_methods={"GET", "POST", "PUT", "PATCH", "DELETE"},
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retry))
        self._session.mount("http://", HTTPAdapter(max_retries=retry))

    # ── auth ────────────────────────────────────────────────────────────────

    def _authenticate(self) -> None:
        """Obtain a session credential from BAM and store as Basic auth token.

        BAM v2 returns basicAuthenticationCredentials (Base64 user:pass string)
        which is used as the Authorization: Basic header for all subsequent calls.
        The apiTokenExpirationDateTime field is used to schedule proactive refresh.
        """
        url = f"{self.base_url}/api/v2/sessions"
        resp = self._session.post(
            url,
            json={"username": self.username, "password": self.password},
            timeout=self.timeout,
        )
        if resp.status_code == 401:
            raise BlueCatClientAuthException(
                f"BAM authentication failed for user '{self.username}'"
            )
        resp.raise_for_status()
        body = resp.json()
        # Use basicAuthenticationCredentials for Basic auth on all subsequent calls
        self._token = body["basicAuthenticationCredentials"]
        expiry_str = body.get("apiTokenExpirationDateTime")
        if expiry_str:
            from datetime import datetime
            expiry_dt = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            self._token_expiry = expiry_dt.timestamp() - self.TOKEN_TTL_BUFFER
        else:
            self._token_expiry = time() + 86400 - self.TOKEN_TTL_BUFFER
        self.log.debug("_authenticate: credentials acquired, expires at %s", expiry_str)

    def _ensure_token(self) -> str:
        if self._token is None or time() >= self._token_expiry:
            self.log.debug("_ensure_token: (re)authenticating")
            self._authenticate()
        return self._token  # type: ignore[return-value]

    # ── low‑level HTTP ──────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Basic {self._ensure_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"octodns-bluecat/{__VERSION__}",
            # Required for write operations on BAM 9.5+
            "x-bcn-change-control-comment": "change from octodns-bluecat",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json: Any = None,
        retry_auth: bool = True,
    ) -> Any:
        url = f"{self.base_url}/api/v2{path}"
        resp = self._session.request(
            method,
            url,
            headers=self._headers(),
            params=params,
            json=json,
            timeout=self.timeout,
        )
        if resp.status_code == 401 and retry_auth:
            self.log.warning("_request: 401 received, refreshing token")
            self._token = None
            return self._request(method, path, params=params, json=json, retry_auth=False)
        if not resp.ok:
            raise BlueCatClientException(
                f"BAM API error {resp.status_code} {method} {path}: {resp.text[:400]}"
            )
        if resp.status_code == 204:
            return None
        return resp.json()

    def _get(self, path: str, params: dict | None = None) -> Any:
        return self._request("GET", path, params=params)

    def _post(self, path: str, body: Any) -> Any:
        return self._request("POST", path, json=body)

    def _put(self, path: str, body: Any) -> Any:
        return self._request("PUT", path, json=body)

    def _delete(self, path: str) -> None:
        self._request("DELETE", path)

    # ── paginated list ───────────────────────────────────────────────────────

    def _list_all(self, path: str, params: dict | None = None) -> list[dict]:
        """
        Fetch every page from a BAM list endpoint and return a flat list.

        BAM v2 envelope: {"data": [...], "count": N, "totalCount": N}
        """
        params = dict(params or {})
        params.setdefault("limit", self.page_size)
        offset = 0
        results: list[dict] = []

        while True:
            params["offset"] = offset
            page = self._get(path, params=params)
            data = page.get("data", [])
            results.extend(data)
            total = page.get("totalCount", len(data))
            offset += len(data)
            if offset >= total or not data:
                break

        return results

    # ── view / zone helpers ──────────────────────────────────────────────────

    def _conf_id(self) -> int:
        """Resolve configuration name → BAM configuration id (cached)."""
        if hasattr(self, "_cached_conf_id"):
            return self._cached_conf_id  # type: ignore[attr-defined]
        confs = self._list_all("/configurations", {"name": self.confname})
        for c in confs:
            if c.get("name") == self.confname:
                self._cached_conf_id: int = c["id"]
                return self._cached_conf_id
        raise BlueCatClientException(
            f"BAM configuration '{self.confname}' not found. "
            f"Available: {[x.get('name') for x in confs]}"
        )

    def _view_id(self) -> int:
        """Resolve view name → BAM view id (cached after first call)."""
        if hasattr(self, "_cached_view_id"):
            return self._cached_view_id  # type: ignore[attr-defined]
        views = self._list_all(
            f"/configurations/{self._conf_id()}/views",
            {"name": self.view}
        )
        for v in views:
            if v.get("name") == self.view:
                self._cached_view_id: int = v["id"]
                return self._cached_view_id
        raise BlueCatClientException(
            f"BAM view '{self.view}' not found. "
            f"Available: {[x.get('name') for x in views]}"
        )

    def _get_all_zones(self) -> dict[str, int]:
        """
        Fetch all zones for this configuration+view and return a dict of
        absoluteName → id.  Result is cached for the lifetime of the client
        so the expensive query only runs once per sync.

        BAM absoluteName values are opaque strings (e.g. 'the_clown.123') —
        we do not attempt any encoding/decoding, just match directly.
        """
        if hasattr(self, "_cached_zones"):
            return self._cached_zones
        params = {
            "limit": 5000,
            "fields": "absoluteName,id",
            "filter": (
                f"configuration.id:eq({self._conf_id()}) and "
                f"view.id:eq({self._view_id()}) and "
                f"type:eq('Zone')"
            ),
        }
        zones = self._list_all("/zones", params)
        self._cached_zones: dict[str, int] = {
            z["absoluteName"]: z["id"] for z in zones if "absoluteName" in z
        }
        self.log.debug("_get_all_zones: cached %d zones", len(self._cached_zones))
        return self._cached_zones

    def _zone_id(self, fqdn: str) -> int | None:
        """
        Resolve a zone FQDN to a BAM zone id.
        Matches against absoluteName in the zone cache.
        Returns None when the zone does not exist in BAM.
        """
        name = fqdn.rstrip(".")
        return self._get_all_zones().get(name)

    def _ensure_zone(self, fqdn: str) -> int:
        """Return zone id, creating the zone in BAM if it doesn't exist."""
        zone_id = self._zone_id(fqdn)
        if zone_id is not None:
            return zone_id
        self.log.info("_ensure_zone: creating zone %s in view %s", fqdn, self.view)
        body = {"name": fqdn.rstrip("."), "deployable": True}
        resp = self._post(f"/views/{self._view_id()}/zones", body)
        # Bust the cache so the new zone is visible
        if hasattr(self, "_cached_zones"):
            del self._cached_zones
        return resp["id"]

    # ── record CRUD ──────────────────────────────────────────────────────────

    def records_for_zone(self, zone_fqdn: str) -> list[dict]:
        """Return all resource records in *zone_fqdn* (may be empty list)."""
        zone_id = self._zone_id(zone_fqdn)
        if zone_id is None:
            return []
        return self._list_all(f"/zones/{zone_id}/resourceRecords")

    def create_record(self, zone_fqdn: str, rr_body: dict) -> dict:
        zone_id = self._ensure_zone(zone_fqdn)
        return self._post(f"/zones/{zone_id}/resourceRecords", rr_body)

    def update_record(self, record_id: int, rr_body: dict) -> dict:
        return self._put(f"/resourceRecords/{record_id}", rr_body)

    def delete_record(self, record_id: int) -> None:
        self._delete(f"/resourceRecords/{record_id}")

    def _ex_zone_id(self) -> int:
        """Return the id of the ExternalHostsZone for the current view (cached)."""
        if not hasattr(self, "_ex_zone_id_cache"):
            view_id = self._view_id()
            resp = self._get(f"/views/{view_id}/zones", params={
                "filter": "type:eq('ExternalHostsZone')",
                "limit": 1,
            })
            data = resp.get("data", [])
            if not data:
                raise BlueCatClientException("No ExternalHostsZone found in view")
            self._ex_zone_id_cache = data[0]["id"]
            self.log.debug("_ex_zone_id: %d", self._ex_zone_id_cache)
        return self._ex_zone_id_cache

    def create_ex_host(self, hostname: str) -> int:
        """Create or retrieve an ExternalHostRecord and return its id."""
        ex_zone_id = self._ex_zone_id()
        # Check if one already exists with this name
        resp = self._get(f"/zones/{ex_zone_id}/resourceRecords", params={
            "filter": f"name:eq('{hostname}')",
            "limit": 1,
        })
        data = resp.get("data", [])
        if data:
            return data[0]["id"]
        # Create a new one in the ExternalHostsZone
        result = self._post(f"/zones/{ex_zone_id}/resourceRecords", {
            "type": "ExternalHostRecord",
            "name": hostname,
        })
        return result["id"]

    def delete_zone(self, zone_fqdn: str) -> None:
        zone_id = self._zone_id(zone_fqdn)
        if zone_id is not None:
            self._delete(f"/zones/{zone_id}")


# ── record conversion helpers ────────────────────────────────────────────────


def _name_from_bam(bam_name: str, zone_fqdn: str) -> str:
    """
    BAM returns absolute or relative owner names.
    Normalise to the relative form octodns expects ('' for apex).
    """
    zone_dot = zone_fqdn.rstrip(".") + "."
    abs_name = bam_name if bam_name.endswith(".") else bam_name + "."
    if abs_name == zone_dot:
        return ""
    if abs_name.endswith("." + zone_dot):
        return abs_name[: -(len(zone_dot) + 1)]
    # already relative
    return bam_name.rstrip(".")


def _bam_rr_to_octodns_data(rr: dict, zone_fqdn: str) -> dict | None:
    """
    Convert a single BAM resource‑record object to the dict format that
    octodns Record.new() understands, or None when the type is unsupported.

    BAM v2 RR shape (abridged):
    {
        "id": 12345,
        "name": "www",                 # relative or absolute owner
        "type": "ARecord",
        "ttl": 300,
        "rdata": "192.0.2.1",          # A/AAAA/CNAME/PTR/NS
        # OR for structured types:
        "rdata": {
            "priority": 10, "exchange": "mail.example.com."   # MX
            "weight": 5, "port": 443, "target": "sip.example.com."  # SRV
            "flags": 0, "tag": "issue", "value": "letsencrypt.org"  # CAA
        }
    }
    """
    bam_type = rr.get("type", "")

    # GenericRecord wraps the real DNS type in recordType field
    if bam_type == "GenericRecord":
        record_type = rr.get("recordType", "")
        octo_type = _GENERIC_RR_TO_OCTO.get(record_type)
        if octo_type is None:
            return None
        # rdata is a plain string for GenericRecord
        rdata_str = rr.get("rdata", "")
        ttl = rr.get("ttl", 300)
        if octo_type == "A":
            return {"ttl": ttl, "type": "A", "values": [rdata_str]}
        if octo_type == "AAAA":
            return {"ttl": ttl, "type": "AAAA", "values": [rdata_str]}
        if octo_type == "CNAME":
            # AliasRecord stores the target in linkedRecord.absoluteName
            if rr.get("type") == "AliasRecord":
                linked = rr.get("linkedRecord", {})
                target = linked.get("absoluteName", "")
                if not target:
                    return None
                return {"ttl": ttl, "type": "CNAME", "value": _ensure_dot(target)}
            return {"ttl": ttl, "type": "CNAME", "value": _ensure_dot(rdata_str)}
        if octo_type == "TXT":
            return {"ttl": ttl, "type": "TXT", "values": [rdata_str]}
        if octo_type == "MX":
            # GenericRecord MX rdata format: "10 mail.example.com."
            parts = rdata_str.split(None, 1)
            return {
                "ttl": ttl,
                "type": "MX",
                "values": [{"preference": int(parts[0]), "exchange": _ensure_dot(parts[1])}],
            }
        return None

    # AliasRecord is BAM's CNAME — target is in linkedRecord.absoluteName
    if bam_type == "AliasRecord":
        linked = rr.get("linkedRecord", {})
        target = linked.get("absoluteName", "")
        if not target:
            return None
        ttl = rr.get("ttl") or 3600
        return {"ttl": ttl, "type": "CNAME", "value": _ensure_dot(target)}

    # Native MXRecord — priority is top-level, exchange in linkedRecord.absoluteName
    if bam_type == "MXRecord":
        linked = rr.get("linkedRecord", {})
        exchange = linked.get("absoluteName", "")
        if not exchange:
            return None
        ttl = rr.get("ttl") or 3600
        priority = int(rr.get("priority", 10))
        return {
            "ttl": ttl,
            "type": "MX",
            "values": [{"preference": priority, "exchange": _ensure_dot(exchange)}],
        }

    # Native TXTRecord — value is in "text" field
    if bam_type == "TXTRecord":
        text = rr.get("text", "")
        ttl = rr.get("ttl") or 3600
        return {"ttl": ttl, "type": "TXT", "values": [text]}

    octo_type = _BAM_TO_OCTO.get(bam_type)
    if octo_type is None:
        return None

    ttl = rr.get("ttl", 300)
    rdata = rr.get("rdata")

    if octo_type == "A":
        values = rdata if isinstance(rdata, list) else [rdata]
        return {"ttl": ttl, "type": "A", "values": values}

    if octo_type == "AAAA":
        values = rdata if isinstance(rdata, list) else [rdata]
        return {"ttl": ttl, "type": "AAAA", "values": values}

    if octo_type == "CNAME":
        target = rdata if isinstance(rdata, str) else rdata.get("target", "")
        if not target.endswith("."):
            target += "."
        return {"ttl": ttl, "type": "CNAME", "value": target}

    if octo_type == "NS":
        values = rdata if isinstance(rdata, list) else [rdata]
        values = [v if v.endswith(".") else v + "." for v in values]
        return {"ttl": ttl, "type": "NS", "values": values}

    if octo_type == "TXT":
        # BAM may return a single string or list
        if isinstance(rdata, list):
            values = rdata
        else:
            values = [rdata]
        return {"ttl": ttl, "type": "TXT", "values": values}

    if octo_type == "MX":
        if isinstance(rdata, list):
            mx_list = [
                {"preference": int(r["priority"]), "exchange": _ensure_dot(r["exchange"])}
                for r in rdata
            ]
        else:
            mx_list = [
                {
                    "preference": int(rdata["priority"]),
                    "exchange": _ensure_dot(rdata["exchange"]),
                }
            ]
        return {"ttl": ttl, "type": "MX", "values": mx_list}

    if octo_type == "SRV":
        if isinstance(rdata, list):
            srv_list = [
                {
                    "priority": int(r["priority"]),
                    "weight": int(r["weight"]),
                    "port": int(r["port"]),
                    "target": _ensure_dot(r["target"]),
                }
                for r in rdata
            ]
        else:
            srv_list = [
                {
                    "priority": int(rdata["priority"]),
                    "weight": int(rdata["weight"]),
                    "port": int(rdata["port"]),
                    "target": _ensure_dot(rdata["target"]),
                }
            ]
        return {"ttl": ttl, "type": "SRV", "values": srv_list}

    if octo_type == "CAA":
        if isinstance(rdata, list):
            caa_list = [
                {"flags": int(r["flags"]), "tag": r["tag"], "value": r["value"]}
                for r in rdata
            ]
        else:
            caa_list = [
                {
                    "flags": int(rdata["flags"]),
                    "tag": rdata["tag"],
                    "value": rdata["value"],
                }
            ]
        return {"ttl": ttl, "type": "CAA", "values": caa_list}

    return None


def _ensure_dot(s: str) -> str:
    return s if s.endswith(".") else s + "."


def _octodns_record_to_bam_rr(record: Record, zone: "octodns.zone.Zone") -> list[dict]:
    """
    Expand an octodns Record into one or more BAM resource‑record dicts.

    For types where BAM stores one row per value (A, AAAA, TXT …) we emit a
    single RR with a list rdata so the caller can decide whether to send them
    individually or as a batch (BAM v2 supports both).

    For structured types (MX, SRV, CAA) we emit one dict per value so each
    can be POSTed separately, which is what BAM expects.
    """
    name = record.name  # '' for apex
    ttl = record.ttl
    rec_type = record._type

    base = {"name": name, "ttl": ttl}

    if rec_type == "A":
        return [{**base, "type": "GenericRecord", "recordType": "A", "rdata": v} for v in record.values]

    if rec_type == "AAAA":
        return [{**base, "type": "GenericRecord", "recordType": "AAAA", "rdata": v} for v in record.values]

    if rec_type == "CNAME":
        # Caller must resolve ExternalHostRecord id before POSTing
        target = record.value.rstrip(".")
        return [{**base, "type": "AliasRecord", "_cname_target": target}]

    if rec_type == "NS":
        return [{**base, "type": "NSRecord", "rdata": v} for v in record.values]

    if rec_type == "TXT":
        return [{**base, "type": "TXTRecord", "text": v.replace('\\;', ';')} for v in record.values]

    if rec_type == "MX":
        # Caller must resolve ExternalHostRecord id before POSTing
        return [
            {
                **base,
                "type": "MXRecord",
                "priority": mx.preference,
                "_mx_exchange": mx.exchange.rstrip("."),
            }
            for mx in record.values
        ]

    if rec_type == "SRV":
        return [
            {
                **base,
                "type": "SRVRecord",
                "rdata": {
                    "priority": srv.priority,
                    "weight": srv.weight,
                    "port": srv.port,
                    "target": srv.target,
                },
            }
            for srv in record.values
        ]

    if rec_type == "CAA":
        return [
            {
                **base,
                "type": "CAARecord",
                "rdata": {"flags": caa.flags, "tag": caa.tag, "value": caa.value},
            }
            for caa in record.values
        ]

    raise BlueCatClientException(f"Unsupported record type for write: {rec_type}")


# ── Provider ─────────────────────────────────────────────────────────────────


class BlueCatProvider(BaseProvider):
    """
    octodns provider for BlueCat Address Manager (BAM) REST API v2.

    Config example
    --------------
    providers:
      bluecat:
        class: octodns_bluecat.BlueCatProvider
        base_url: https://bam.corp.example.com
        username: env/BLUECAT_USER
        password: env/BLUECAT_PASS
        view: InternalView        # BAM DNS view name — required
        page_size: 100            # optional, default 100
        timeout: 30               # HTTP timeout in seconds, default 30
    """

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_POOL_VALUES = False
    SUPPORTS = SUPPORTS

    def __init__(
        self,
        id: str,
        base_url: str,
        username: str,
        password: str,
        confname: str,
        view: str,
        page_size: int = BlueCatClient.DEFAULT_PAGE_SIZE,
        timeout: int = 30,
        *args,
        **kwargs,
    ) -> None:
        self.log = logging.getLogger(f"BlueCatProvider[{id}]")
        self.log.debug(
            "__init__: id=%s base_url=%s confname=%s view=%s", id, base_url, confname, view
        )
        super().__init__(id, *args, **kwargs)

        self._client = BlueCatClient(
            base_url=base_url,
            username=username,
            password=password,
            confname=confname,
            view=view,
            page_size=page_size,
            timeout=timeout,
        )

    # ── populate (read) ──────────────────────────────────────────────────────

    def list_zones(self) -> list:
        """Return all zone names (with trailing dot) from the configured view."""
        zones = self._client._get_all_zones()
        return [f"{name}." for name in zones.keys()]

    def populate(self, zone, target=False, lenient=False):
        """
        Fetch all resource records for *zone* from BAM and add them to the
        octodns Zone object.

        Parameters
        ----------
        zone    : octodns.zone.Zone
        target  : bool  – when True we are the sync target; only used to
                          decide whether to log a warning if the zone is absent.
        lenient : bool  – if True pass lenient=True when creating Records so
                          that unknown/broken data is tolerated.

        Returns
        -------
        bool  – True if the zone existed in BAM, False otherwise.
        """
        self.log.debug("populate: name=%s target=%s", zone.name, target)

        before = len(zone.records)

        # Distinguish "zone missing" from "zone empty" by checking existence first
        zone_exists = self._client._zone_id(zone.name) is not None
        if not zone_exists:
            self.log.debug("populate: zone %s not found in BAM", zone.name)
            return False

        raw_records = self._client.records_for_zone(zone.name)

        # Group BAM rows by (owner‑name, octo‑type) so that multi-value records
        # (A, AAAA, MX …) are collapsed into a single octodns Record.
        grouped: dict[tuple[str, str], dict] = {}

        for rr in raw_records:
            bam_type = rr.get("type", "")
            if bam_type == "GenericRecord":
                octo_type = _GENERIC_RR_TO_OCTO.get(rr.get("recordType", ""))
            elif bam_type == "AliasRecord":
                octo_type = "CNAME"
            elif bam_type == "MXRecord":
                octo_type = "MX"
            elif bam_type == "TXTRecord":
                octo_type = "TXT"
            else:
                octo_type = _BAM_TO_OCTO.get(bam_type)
            if octo_type is None:
                self.log.debug("populate: skipping unsupported type %s", rr.get("type"))
                continue

            # Prefer absoluteName for accurate owner resolution
            if "absoluteName" in rr:
                abs_name = rr["absoluteName"].rstrip(".")
                zone_part = zone.name.rstrip(".")
                if abs_name == zone_part:
                    owner = ""
                elif abs_name.endswith("." + zone_part):
                    owner = abs_name[: -(len(zone_part) + 1)]
                else:
                    owner = _name_from_bam(rr.get("name", ""), zone.name)
            else:
                owner = _name_from_bam(rr.get("name", ""), zone.name)
            key = (owner, octo_type)
            data = _bam_rr_to_octodns_data(rr, zone.name)
            if data is None:
                continue

            if key not in grouped:
                grouped[key] = data
            else:
                # Merge additional values into existing entry
                existing = grouped[key]
                for field in ("values", "value"):
                    if field in data:
                        if "values" not in existing:
                            existing["values"] = [existing.pop("value", None)]
                        new_vals = data[field] if isinstance(data[field], list) else [data[field]]
                        existing["values"].extend(new_vals)

        for (owner, octo_type), data in grouped.items():
            rec = Record.new(
                zone,
                owner,
                data,
                source=self,
                lenient=lenient,
            )
            zone.add_record(rec, lenient=lenient)

        added = len(zone.records) - before
        self.log.info("populate: zone %s — added %d record(s)", zone.name, added)
        return True

    # ── apply (write) ────────────────────────────────────────────────────────

    def _apply(self, plan):
        """
        Execute the change plan produced by octodns against BAM.

        BAM does not have a concept of "update a record set" — each individual
        row must be deleted and re-created.  We therefore implement Update as
        delete-all-existing + create-all-new.
        """
        desired_zone = plan.desired
        zone_fqdn = desired_zone.name

        self.log.debug("_apply: zone=%s changes=%d", zone_fqdn, len(plan.changes))

        # Build an index of current BAM rows keyed by (owner, octo_type) so we
        # can look up the BAM record ids when deleting.
        existing_rows = self._client.records_for_zone(zone_fqdn)
        id_index: dict[tuple[str, str], list[int]] = {}
        for rr in existing_rows:
            octo_type = _BAM_TO_OCTO.get(rr.get("type", ""))
            if octo_type is None:
                continue
            owner = _name_from_bam(rr.get("name", ""), zone_fqdn)
            id_index.setdefault((owner, octo_type), []).append(rr["id"])

        for change in plan.changes:
            change_type = change.__class__.__name__

            if change_type == "Create":
                self._apply_create(zone_fqdn, change.new, desired_zone)

            elif change_type == "Update":
                self._apply_delete(change.existing, id_index, zone_fqdn)
                self._apply_create(zone_fqdn, change.new, desired_zone)

            elif change_type == "Delete":
                self._apply_delete(change.existing, id_index, zone_fqdn)

    def _apply_create(self, zone_fqdn: str, record: Record, zone) -> None:
        self.log.debug(
            "_apply_create: %s %s", record._type, record.fqdn
        )
        for rr_body in _octodns_record_to_bam_rr(record, zone):
            # Resolve ExternalHostRecord for CNAME (AliasRecord)
            if rr_body.get("type") == "AliasRecord":
                target = rr_body.pop("_cname_target")
                ex_id = self._client.create_ex_host(target)
                rr_body["linkedRecord"] = {"id": ex_id, "type": "ExternalHostRecord"}
            # Resolve ExternalHostRecord for MX
            elif "_mx_exchange" in rr_body:
                exchange = rr_body.pop("_mx_exchange")
                ex_id = self._client.create_ex_host(exchange)
                rr_body["linkedRecord"] = {"id": ex_id, "type": "ExternalHostRecord"}
            self._client.create_record(zone_fqdn, rr_body)

    def _apply_delete(
        self,
        record: Record,
        id_index: dict[tuple[str, str], list[int]],
        zone_fqdn: str,
    ) -> None:
        owner = record.name
        octo_type = record._type
        key = (owner, octo_type)
        self.log.debug("_apply_delete: %s %s", octo_type, record.fqdn)
        for rec_id in id_index.get(key, []):
            self._client.delete_record(rec_id)
