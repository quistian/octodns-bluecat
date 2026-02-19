"""
Tests for octodns_bluecat.BlueCatProvider

Uses responses to mock the BAM REST API v2; fixtures are stored as JSON under
tests/fixtures/bluecat/ so that real BAM responses can be dropped in later.

Run:  pytest tests/ -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest
import responses as rsps_lib

from octodns.provider.plan import Plan
from octodns.record import Record
from octodns.zone import Zone

from octodns_bluecat import (
    BlueCatClient,
    BlueCatClientAuthException,
    BlueCatClientException,
    BlueCatProvider,
    _bam_rr_to_octodns_data,
    _name_from_bam,
    _octodns_record_to_bam_rr,
)

# ── fixture helpers ───────────────────────────────────────────────────────────

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "bluecat"


def load_fixture(name: str) -> Any:
    with open(FIXTURE_DIR / name) as f:
        return json.load(f)


BASE_URL = "https://bam.example.com"
VIEW = "InternalView"

# canonical session fixture
SESSION_RESP = load_fixture("session.json")
VIEWS_RESP = load_fixture("views.json")
ZONES_RESP = load_fixture("zones.json")
ZONES_ALL_RESP = {
    "data": [
        {"id": 1001, "absoluteName": "unit.tests"},
    ],
    "count": 1,
    "totalCount": 1,
}
RECORDS_RESP = load_fixture("records_unit_tests.json")


# ── helper to register all common BAM mocks ──────────────────────────────────


def register_auth(rsps):
    rsps.add(
        rsps_lib.POST,
        f"{BASE_URL}/api/v2/sessions",
        json=SESSION_RESP,
        status=200,
    )


CONF_RESP = {
    "data": [{"id": 99, "name": "TestConfig", "type": "Configuration"}],
    "count": 1,
    "totalCount": 1,
}

def register_conf(rsps):
    rsps.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v2/configurations",
        json=CONF_RESP,
        status=200,
    )

def register_views(rsps):
    rsps.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v2/configurations/99/views",
        json=VIEWS_RESP,
        status=200,
    )


def register_zones(rsps, zone_name="unit.tests"):
    rsps.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v2/zones",
        json=ZONES_ALL_RESP,
        status=200,
    )


def register_records(rsps, zone_id=1001):
    rsps.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v2/zones/{zone_id}/resourceRecords",
        json=RECORDS_RESP,
        status=200,
    )


def make_provider(**kwargs) -> BlueCatProvider:
    defaults = dict(
        id="bluecat_test",
        base_url=BASE_URL,
        username="testuser",
        password="secret",
        confname="TestConfig",
        view=VIEW,
    )
    defaults.update(kwargs)
    return BlueCatProvider(**defaults)


# ── unit tests: helpers ───────────────────────────────────────────────────────


class TestNameFromBam:
    def test_relative_name(self):
        assert _name_from_bam("www", "unit.tests.") == "www"

    def test_apex_absolute(self):
        assert _name_from_bam("unit.tests.", "unit.tests.") == ""

    def test_apex_no_dot(self):
        assert _name_from_bam("unit.tests", "unit.tests.") == ""

    def test_sub_absolute(self):
        assert _name_from_bam("sub.unit.tests.", "unit.tests.") == "sub"

    def test_sub_no_trailing_dot(self):
        assert _name_from_bam("sub.unit.tests", "unit.tests.") == "sub"


class TestBamRrToOctodnsData:
    def test_a_record(self):
        rr = {"type": "ARecord", "ttl": 300, "rdata": "1.2.3.4"}
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result == {"ttl": 300, "type": "A", "values": ["1.2.3.4"]}

    def test_aaaa_record(self):
        rr = {"type": "AAAARecord", "ttl": 300, "rdata": "2001:db8::1"}
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result == {"ttl": 300, "type": "AAAA", "values": ["2001:db8::1"]}

    def test_cname_adds_dot(self):
        rr = {"type": "AliasRecord", "ttl": 300, "linkedRecord": {"absoluteName": "www.example.com"}}
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result["value"].endswith(".")

    def test_mx_record(self):
        # Native MXRecord: priority is top-level, exchange in linkedRecord.absoluteName
        rr = {
            "type": "MXRecord",
            "ttl": 300,
            "priority": 10,
            "linkedRecord": {"absoluteName": "mail.example.com"},
        }
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result["values"][0]["preference"] == 10
        assert result["values"][0]["exchange"] == "mail.example.com."

    def test_txt_record(self):
        rr = {"type": "TXTRecord", "ttl": 600, "text": "v=spf1 include:example.com ~all"}
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result["type"] == "TXT"
        assert "v=spf1" in result["values"][0]

    def test_srv_record(self):
        rr = {
            "type": "SRVRecord",
            "ttl": 300,
            "rdata": {"priority": 10, "weight": 20, "port": 5060, "target": "sip.example.com."},
        }
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result["values"][0]["port"] == 5060

    def test_caa_record(self):
        rr = {
            "type": "CAARecord",
            "ttl": 3600,
            "rdata": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
        }
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result["values"][0]["tag"] == "issue"

    def test_unsupported_type_returns_none(self):
        rr = {"type": "HINFORecord", "ttl": 300, "rdata": "cpu os"}
        assert _bam_rr_to_octodns_data(rr, "unit.tests.") is None

    def test_generic_record_a(self):
        rr = {
            "type": "GenericRecord",
            "recordType": "A",
            "ttl": 3600,
            "name": "p278_do_not_remove",
            "absoluteName": "p278_do_not_remove.unit.tests",
            "rdata": "10.140.0.0",
        }
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result == {"ttl": 3600, "type": "A", "values": ["10.140.0.0"]}

    def test_generic_record_cname(self):
        rr = {
            "type": "GenericRecord",
            "recordType": "CNAME",
            "ttl": 300,
            "name": "alias",
            "absoluteName": "alias.unit.tests",
            "rdata": "target.example.com",
        }
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result["type"] == "CNAME"
        assert result["value"] == "target.example.com."

    def test_generic_record_txt(self):
        rr = {
            "type": "GenericRecord",
            "recordType": "TXT",
            "ttl": 300,
            "name": "txt",
            "absoluteName": "txt.unit.tests",
            "rdata": "v=spf1 include:example.com ~all",
        }
        result = _bam_rr_to_octodns_data(rr, "unit.tests.")
        assert result["type"] == "TXT"
        assert "v=spf1" in result["values"][0]

    def test_generic_record_unsupported_subtype_returns_none(self):
        rr = {
            "type": "GenericRecord",
            "recordType": "DNAME",
            "ttl": 300,
            "rdata": "example.com.",
        }
        assert _bam_rr_to_octodns_data(rr, "unit.tests.") is None


class TestOctodnsRecordToBamRr:
    """Round-trip: octodns Record → BAM RR dicts."""

    def _make_record(self, zone_name, name, data):
        if not zone_name.endswith("."):
            zone_name = zone_name + "."
        zone = Zone(zone_name, [])
        return Record.new(zone, name, data)

    def test_a_produces_one_rr_per_value(self):
        rec = self._make_record("unit.tests.", "www", {"type": "A", "ttl": 300, "values": ["1.2.3.4", "1.2.3.5"]})
        zone = Zone("unit.tests.", [])
        rrs = _octodns_record_to_bam_rr(rec, zone)
        assert len(rrs) == 2
        assert all(r["type"] == "GenericRecord" and r["recordType"] == "A" for r in rrs)

    def test_cname(self):
        rec = self._make_record("unit.tests.", "alias", {"type": "CNAME", "ttl": 300, "value": "www.unit.tests."})
        zone = Zone("unit.tests.", [])
        rrs = _octodns_record_to_bam_rr(rec, zone)
        assert len(rrs) == 1
        assert rrs[0]["type"] == "AliasRecord"
        assert rrs[0]["_cname_target"] == "www.unit.tests"

    def test_mx(self):
        rec = self._make_record(
            "unit.tests",
            "",
            {
                "type": "MX",
                "ttl": 300,
                "values": [
                    {"preference": 10, "exchange": "smtp.unit.tests."},
                    {"preference": 20, "exchange": "smtp2.unit.tests."},
                ],
            },
        )
        zone = Zone("unit.tests.", [])
        rrs = _octodns_record_to_bam_rr(rec, zone)
        assert len(rrs) == 2
        assert rrs[0]["priority"] == 10
        assert rrs[0]["_mx_exchange"] == "smtp.unit.tests"

    def test_srv(self):
        rec = self._make_record(
            "unit.tests",
            "_sip._tcp",
            {
                "type": "SRV",
                "ttl": 300,
                "values": [{"priority": 10, "weight": 20, "port": 5060, "target": "sip.unit.tests."}],
            },
        )
        zone = Zone("unit.tests.", [])
        rrs = _octodns_record_to_bam_rr(rec, zone)
        assert rrs[0]["rdata"]["port"] == 5060

    def test_unsupported_raises(self):
        # Patch a record with a fake type
        rec = self._make_record("unit.tests.", "www", {"type": "A", "ttl": 300, "values": ["1.2.3.4"]})
        rec._type = "SSHFP"  # force unsupported
        zone = Zone("unit.tests.", [])
        with pytest.raises(BlueCatClientException):
            _octodns_record_to_bam_rr(rec, zone)


# ── unit tests: client ────────────────────────────────────────────────────────


class TestBlueCatClientAuth:
    @rsps_lib.activate
    def test_authenticate_success(self):
        rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v2/sessions", json=SESSION_RESP)
        client = BlueCatClient(BASE_URL, "u", "p", "TestConfig", VIEW)
        token = client._ensure_token()
        assert token == "test-bearer-token-abc123"  # basicAuthenticationCredentials value

    @rsps_lib.activate
    def test_authenticate_bad_credentials(self):
        rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v2/sessions", status=401, json={"error": "Unauthorized"})
        client = BlueCatClient(BASE_URL, "u", "wrong", "TestConfig", VIEW)
        with pytest.raises(BlueCatClientAuthException):
            client._ensure_token()

    @rsps_lib.activate
    def test_token_refresh_on_401(self):
        """Client transparently re-authenticates when a 401 is received mid-session."""
        rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v2/sessions", json=SESSION_RESP)
        rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v2/views", status=401, json={})
        rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v2/sessions", json=SESSION_RESP)
        rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v2/views", json=VIEWS_RESP)

        client = BlueCatClient(BASE_URL, "u", "p", "TestConfig", VIEW)
        # prime the token so the first GET uses the existing (expired) one
        client._ensure_token()
        result = client._get("/views", {"name": VIEW})
        assert result["data"][0]["name"] == VIEW


class TestBlueCatClientPagination:
    @rsps_lib.activate
    def test_list_all_multiple_pages(self):
        """_list_all must follow offset pagination until totalCount is reached."""
        register_auth(rsps_lib)

        page1 = {
            "data": [{"id": i, "name": f"rec{i}", "type": "ARecord", "ttl": 300, "rdata": f"1.2.3.{i}"}
                     for i in range(3)],
            "count": 3,
            "totalCount": 5,
        }
        page2 = {
            "data": [{"id": i, "name": f"rec{i}", "type": "ARecord", "ttl": 300, "rdata": f"1.2.3.{i}"}
                     for i in range(3, 5)],
            "count": 2,
            "totalCount": 5,
        }

        rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v2/zones/1001/resourceRecords", json=page1)
        rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v2/zones/1001/resourceRecords", json=page2)

        client = BlueCatClient(BASE_URL, "u", "p", "TestConfig", VIEW, page_size=3)
        client._token = "tok"  # skip auth
        client._token_expiry = 99999999999
        result = client._list_all("/zones/1001/resourceRecords")
        assert len(result) == 5


# ── integration-style tests: provider populate ────────────────────────────────


class TestBlueCatProviderPopulate:
    @rsps_lib.activate
    def test_populate_returns_true_for_existing_zone(self):
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        register_zones(rsps_lib)
        register_records(rsps_lib)

        provider = make_provider()
        zone = Zone("unit.tests.", [])
        exists = provider.populate(zone)
        assert exists is True

    @rsps_lib.activate
    def test_populate_adds_expected_record_types(self):
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        register_zones(rsps_lib)
        register_records(rsps_lib)

        provider = make_provider()
        zone = Zone("unit.tests.", [])
        provider.populate(zone)

        types_present = {(r.name, r._type) for r in zone.records}
        assert ("www", "A") in types_present
        assert ("aaaa", "AAAA") in types_present
        assert ("alias", "CNAME") in types_present
        assert ("", "MX") in types_present
        assert ("txt", "TXT") in types_present
        assert ("_sip._tcp", "SRV") in types_present
        assert ("", "CAA") in types_present

    @rsps_lib.activate
    def test_populate_merges_multivalue_a(self):
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        register_zones(rsps_lib)
        register_records(rsps_lib)

        provider = make_provider()
        zone = Zone("unit.tests.", [])
        provider.populate(zone)

        www = next(r for r in zone.records if r.name == "www" and r._type == "A")
        assert len(www.values) == 2
        assert "1.2.3.4" in www.values
        assert "1.2.3.5" in www.values

    @rsps_lib.activate
    def test_populate_returns_false_when_zone_not_found(self):
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        # zone lookup returns empty
        rsps_lib.add(
            rsps_lib.GET,
            f"{BASE_URL}/api/v2/zones",
            json={"data": [], "count": 0, "totalCount": 0},
        )

        provider = make_provider()
        zone = Zone("nonexistent.example.com.", [])
        exists = provider.populate(zone)
        assert exists is False

    @rsps_lib.activate
    def test_populate_lenient_skips_bad_records(self):
        """lenient=True should not crash on malformed BAM data."""
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        register_zones(rsps_lib)

        bad_records = {
            "data": [
                {"id": 9999, "name": "bad", "type": "UNKNOWN_TYPE_XYZ", "ttl": 300, "rdata": "???"}
            ],
            "count": 1,
            "totalCount": 1,
        }
        rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v2/zones/1001/resourceRecords", json=bad_records)

        provider = make_provider()
        zone = Zone("unit.tests.", [])
        # Should not raise
        provider.populate(zone, lenient=True)
        assert len(zone.records) == 0


# ── integration-style tests: provider _apply ─────────────────────────────────


class TestBlueCatProviderApply:
    """
    Test the write path by intercepting HTTP calls and inspecting payloads.
    Uses responses library for HTTP mocking, same as populate tests.
    """

    def _make_plan(self, changes):
        """Build a minimal Plan-like object."""
        plan = MagicMock(spec=Plan)
        plan.changes = changes
        plan.desired = MagicMock()
        plan.desired.name = "unit.tests."
        return plan

    @rsps_lib.activate
    def test_apply_create(self):
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        register_zones(rsps_lib)
        # Existing records — empty so no deletes needed
        rsps_lib.add(
            rsps_lib.GET,
            f"{BASE_URL}/api/v2/zones/1001/resourceRecords",
            json={"data": [], "count": 0, "totalCount": 0},
        )
        # POST for each value
        rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v2/zones/1001/resourceRecords", json={"id": 3001}, status=201)
        rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v2/zones/1001/resourceRecords", json={"id": 3002}, status=201)

        provider = make_provider()
        zone = Zone("unit.tests.", [])
        new_rec = Record.new(zone, "new", {"type": "A", "ttl": 300, "values": ["5.5.5.5", "6.6.6.6"]})

        change = MagicMock()
        change.__class__.__name__ = "Create"
        change.new = new_rec

        plan = self._make_plan([change])
        provider._apply(plan)

        # Both POST calls must have been made
        post_calls = [c for c in rsps_lib.calls if c.request.method == "POST" and "resourceRecords" in c.request.url]
        assert len(post_calls) == 2

    @rsps_lib.activate
    def test_apply_delete(self):
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        register_zones(rsps_lib)

        existing_recs = {
            "data": [
                {"id": 4001, "name": "old", "type": "ARecord", "ttl": 300, "rdata": "9.9.9.9"}
            ],
            "count": 1,
            "totalCount": 1,
        }
        rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v2/zones/1001/resourceRecords", json=existing_recs)
        rsps_lib.add(rsps_lib.DELETE, f"{BASE_URL}/api/v2/resourceRecords/4001", status=204)

        provider = make_provider()
        zone = Zone("unit.tests.", [])
        old_rec = Record.new(zone, "old", {"type": "A", "ttl": 300, "values": ["9.9.9.9"]})

        change = MagicMock()
        change.__class__.__name__ = "Delete"
        change.existing = old_rec

        plan = self._make_plan([change])
        provider._apply(plan)

        delete_calls = [c for c in rsps_lib.calls if c.request.method == "DELETE"]
        assert len(delete_calls) == 1
        assert "4001" in delete_calls[0].request.url

    @rsps_lib.activate
    def test_apply_update_delete_then_create(self):
        """Update = delete old rows + create new rows."""
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        register_zones(rsps_lib)

        existing_recs = {
            "data": [
                {"id": 5001, "name": "upd", "type": "ARecord", "ttl": 300, "rdata": "1.1.1.1"}
            ],
            "count": 1,
            "totalCount": 1,
        }
        rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v2/zones/1001/resourceRecords", json=existing_recs)
        rsps_lib.add(rsps_lib.DELETE, f"{BASE_URL}/api/v2/resourceRecords/5001", status=204)
        rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v2/zones/1001/resourceRecords", json={"id": 5002}, status=201)

        provider = make_provider()
        zone = Zone("unit.tests.", [])
        old_rec = Record.new(zone, "upd", {"type": "A", "ttl": 300, "values": ["1.1.1.1"]})
        new_rec = Record.new(zone, "upd", {"type": "A", "ttl": 300, "values": ["2.2.2.2"]})

        change = MagicMock()
        change.__class__.__name__ = "Update"
        change.existing = old_rec
        change.new = new_rec

        plan = self._make_plan([change])
        provider._apply(plan)

        methods = [c.request.method for c in rsps_lib.calls]
        assert "DELETE" in methods
        assert "POST" in methods


# ── edge cases ────────────────────────────────────────────────────────────────


class TestEdgeCases:
    @rsps_lib.activate
    def test_view_not_found_raises(self):
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        rsps_lib.add(
            rsps_lib.GET,
            f"{BASE_URL}/api/v2/configurations/99/views",
            json={"data": [], "count": 0, "totalCount": 0},
        )

        client = BlueCatClient(BASE_URL, "u", "p", "TestConfig", "NonExistentView")
        client._token = "tok"
        client._token_expiry = 99999999999

        with pytest.raises(BlueCatClientException, match="not found"):
            client._view_id()

    @rsps_lib.activate
    def test_non_200_raises(self):
        register_auth(rsps_lib)
        # Use 422 (not in the retry list) so the adapter doesn't retry
        rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v2/views", status=422, json={"error": "Unprocessable"})

        client = BlueCatClient(BASE_URL, "u", "p", "TestConfig", VIEW)
        client._token = "tok"
        client._token_expiry = 99999999999
        with pytest.raises(BlueCatClientException):
            client._get("/views")

    @rsps_lib.activate
    def test_populate_target_zone_missing_returns_false(self):
        """target=True: missing zone should still return False, not raise."""
        register_auth(rsps_lib)
        register_conf(rsps_lib)
        register_views(rsps_lib)
        rsps_lib.add(
            rsps_lib.GET,
            f"{BASE_URL}/api/v2/zones",
            json={"data": [], "count": 0, "totalCount": 0},
        )

        provider = make_provider()
        zone = Zone("new.zone.example.com.", [])
        result = provider.populate(zone, target=True)
        assert result is False
