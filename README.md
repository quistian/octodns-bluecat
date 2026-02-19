## octodns-bluecat

An [octodns](https://github.com/octodns/octodns) provider for
[BlueCat Address Manager (BAM)](https://docs.bluecatnetworks.com/r/Address-Manager-API-Guide)
using the **REST API v2**.

### Supported providers

| Provider | Record Support | Notes |
|---|---|---|
| BlueCatProvider | A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TXT | See restrictions below |

### Requirements

#### Versions

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

```
# Start with the latest versions and don't just copy what's here
octodns==1.15.0
octodns-bluecat==0.0.1
```

#### BAM API v2

This provider requires BlueCat Address Manager with REST API v2 enabled.
API v2 is available in BAM 9.3 and later.

### Configuration

```yaml
providers:
  bluecat:
    class: octodns_bluecat.BlueCatProvider
    # BAM server base URL (no trailing slash). Required.
    base_url: https://bam.corp.example.com
    # BAM username. Use env/VAR to read from environment variable. Required.
    username: env/BLUECAT_USER
    # BAM password. Use env/VAR to read from environment variable. Required.
    password: env/BLUECAT_PASS
    # BAM Configuration name. Required.
    confname: env/BLUECAT_CONF
    # BAM DNS View name. Required.
    view: env/BLUECAT_VIEW
    # Optional. Default: 100. Number of resource records per page.
    #page_size: 100
    # Optional. Default: 30. HTTP request timeout in seconds.
    #timeout: 30
```

### Record type support

BlueCatProvider supports A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, and TXT records.

BlueCatProvider does not support dynamic records or geo routing.

BlueCatProvider does not manage PTR records — they are read-only and managed
by BAM's DHCP deployment process.

### CNAME and MX — ExternalHostRecord

BlueCat Address Manager stores CNAME targets and MX mail exchanges as
`ExternalHostRecord` objects in a dedicated zone within the view. When writing
CNAME or MX records, the provider automatically looks up or creates the required
`ExternalHostRecord` before linking it to the DNS record. No manual setup is
required.

### Wildcard zone sync

BlueCatProvider supports `list_zones()`, enabling wildcard zone configuration:

```yaml
zones:
  "*":
    sources:
      - bluecat
    targets:
      - dump
```

You can also target specific zones on the command line:

```bash
octodns-sync --config-file sync.yaml --doit zone1.example.com. zone2.example.com.
```

### Development

See the [CONTRIBUTING.md](CONTRIBUTING.md) guidelines for information on
contributing to this provider.

```bash
# Clone and install for development
git clone https://github.com/your-org/octodns-bluecat
cd octodns-bluecat
pip install -e ".[dev]"

# Run the test suite
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=octodns_bluecat --cov-report=term-missing
```

See the `/script` directory for helper scripts. The most useful is
`./script/test` which runs the full test suite.

### License

Copyright (c) 2026 Russell Sutherland, University of Toronto

Licensed under the [Apache License, Version 2.0](LICENSE).
