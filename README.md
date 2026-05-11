# FortiScan

A modular, all-in-one FortiGate vulnerability scanner for the command line.  
Integrates detection checks for multiple CVEs into a single tool with one virtual environment.

---

## Covered CVEs

| CVE ID | Description | Affected Versions |
|--------|-------------|-------------------|
| CVE-2018-13379 | SSL VPN directory traversal - credential dump | FortiOS 5.6.3-5.6.7, 6.0.0-6.0.4 |
| CVE-2022-40684 | HTTP management interface auth bypass | FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1; FortiProxy 7.0.0-7.0.6, 7.2.0 |
| CVE-2022-40684-LEAK | January 2025 credential leak database lookup | Devices previously exploited via CVE-2022-40684 |
| CVE-2023-27997 | SSL VPN heap buffer overflow - timing-based detection | FortiOS 6.0.x–7.2.x before June 2023 patches |
| CVE-2024-21762 | SSL VPN out-of-bounds write via Transfer-Encoding | FortiOS 6.0.x–7.4.2 |
| CVE-2024-55591 | Node.js websocket authentication bypass | FortiOS 7.0.0-7.0.16; FortiProxy 7.0.0-7.0.19, 7.2.0-7.2.12 |

---

## Requirements

- **Python 3.10 or newer** (tested on 3.12.3 and 3.13.11)
- No system-level dependencies — all packages install via pip
- 3 pip packages: `requests`, `urllib3`, `colorama`

## Setup

```bash
git clone https://github.com/EddieGerbs/FortiScan
cd FortiScan
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

### Run all checks against a single target
```bash
python fortiscan.py --target 10.0.0.1:443 --all
```

### Run specific CVE checks
```bash
python fortiscan.py --target 10.0.0.1:10443 --cve CVE-2024-21762 CVE-2023-27997
```

### Scan a list of targets from a file
```bash
python fortiscan.py --file targets.txt --all --threads 20
```

`targets.txt` format - one target per line:
```
10.0.0.1:443
192.168.1.254:8443
vpn.example.com
```

### Enable credential extraction (CVE-2018-13379)
```bash
python fortiscan.py --target 10.0.0.1:443 --cve CVE-2018-13379 --dump-creds
```

> Credential extraction is **disabled by default** and requires the explicit `--dump-creds` flag.

### Save results to a file
```bash
python fortiscan.py --target 10.0.0.1:443 --all --output results.json --format json
python fortiscan.py --target 10.0.0.1:443 --all --output results.csv --format csv
```

### List all available checks
```bash
python fortiscan.py --list
```

### Interactive mode
Run with no arguments to be prompted for target and check selection:
```bash
python fortiscan.py
```

---

## Full option reference

```
optional arguments:
  --version             Show version and exit
  --list                List all available CVE checks and exit
  --no-color            Disable coloured output

target specification:
  --target HOST:PORT    One or more targets (port defaults to 443)
  --file FILE           File with one target per line

check selection:
  --all                 Run all available checks
  --cve CVE_ID [...]    Run only specified check(s)

run options:
  --dump-creds          Enable credential extraction for CVE-2018-13379
  --threads N           Concurrent threads (default: 10)
  --timeout SECONDS     Per-request timeout (default: 10)

output:
  --output FILE         Save results to file
  --format              table | json | csv (default: table)
```

---

## Adding a new CVE check

1. Create `modules/cve_YYYY_XXXXX.py` with a class extending `BaseCheck`:

```python
from .base import BaseCheck, CheckResult

class CVE_YYYY_XXXXX(BaseCheck):
    CVE_ID = "CVE-YYYY-XXXXX"
    DESCRIPTION = "Short description"
    AFFECTED_VERSIONS = "Affected FortiOS versions"

    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        # your detection logic here
        return CheckResult(self.CVE_ID, f"{host}:{port}", "VULNERABLE", "details")
```

2. Add one line to the `REGISTRY` dict in `fortiscan.py`:

```python
from modules.cve_YYYY_XXXXX import CVE_YYYY_XXXXX

REGISTRY = {
    ...
    "CVE-YYYY-XXXXX": CVE_YYYY_XXXXX,
}
```

---

## Legal

This tool is intended for **authorised security testing only**.  
Always obtain written permission before scanning systems you do not own.  
The authors accept no liability for misuse.

---

## Credits

Detection logic adapted from research by:
- Bishop Fox (CVE-2023-27997 timing analysis)
- Orange Tsai / @x41x41x41 / @DavidStubley (CVE-2018-13379)
- Various public PoC researchers (CVE-2024-21762, CVE-2022-40684)
