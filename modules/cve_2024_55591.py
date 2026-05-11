"""
CVE-2024-55591
FortiOS / FortiProxy Node.js websocket module authentication bypass —
allows unauthenticated remote attacker to gain super-administrator privileges.
Affected: FortiOS 7.0.0-7.0.16; FortiProxy 7.0.0-7.0.19, 7.2.0-7.2.12.
Patched:  FortiOS 7.0.17+; FortiProxy 7.0.20+, 7.2.13+.

Detection strategy: extract the firmware version from publicly accessible
endpoints and compare against the known-vulnerable version ranges.
"""

import re

import requests
import urllib3

from .base import BaseCheck, CheckResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# (major, minor, patch_min, patch_max_inclusive)
_VULNERABLE_FORTI_OS = [(7, 0, 0, 16)]
_VULNERABLE_FORTI_PROXY = [(7, 0, 0, 19), (7, 2, 0, 12)]

_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


def _parse_version(text: str):
    m = _VERSION_RE.search(text)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def _in_range(ver: tuple, ranges: list) -> bool:
    major, minor, patch = ver
    for r_major, r_minor, r_patch_min, r_patch_max in ranges:
        if major == r_major and minor == r_minor and r_patch_min <= patch <= r_patch_max:
            return True
    return False


class CVE_2024_55591(BaseCheck):
    CVE_ID = "CVE-2024-55591"
    DESCRIPTION = "Node.js Websocket Authentication Bypass (Super-Admin)"
    AFFECTED_VERSIONS = (
        "FortiOS 7.0.0-7.0.16; "
        "FortiProxy 7.0.0-7.0.19, 7.2.0-7.2.12"
    )

    def _fetch_version(self, host: str, port: int) -> str | None:
        target = f"{host}:{port}"
        probes = [
            f"https://{target}/remote/info",
            f"https://{target}/login",
            f"https://{target}/",
        ]
        for url in probes:
            try:
                r = requests.get(url, verify=False, timeout=10, allow_redirects=True)
                # Look for explicit version tags
                for pattern in [
                    r"FortiOS[^0-9]*(\d+\.\d+\.\d+)",
                    r"FortiProxy[^0-9]*(\d+\.\d+\.\d+)",
                    r"salt='[0-9a-f]{8}'.*?version['\"\s=:]+(\d+\.\d+\.\d+)",
                    r"version['\"\s=:]+(\d+\.\d+\.\d+)",
                    r"v(\d+\.\d+\.\d+)",
                ]:
                    m = re.search(pattern, r.text, re.IGNORECASE)
                    if m:
                        return m.group(1)
            except Exception:
                continue
        return None

    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        target = f"{host}:{port}"
        version_str = self._fetch_version(host, port)

        if not version_str:
            return CheckResult(
                self.CVE_ID, target, "UNKNOWN",
                "Could not determine firmware version from accessible endpoints",
            )

        ver = _parse_version(version_str)
        if not ver:
            return CheckResult(
                self.CVE_ID, target, "UNKNOWN",
                f"Detected version string '{version_str}' but could not parse it",
            )

        data = {"detected_version": version_str}

        if _in_range(ver, _VULNERABLE_FORTI_OS):
            return CheckResult(
                self.CVE_ID, target, "VULNERABLE",
                f"FortiOS {version_str} falls in vulnerable range 7.0.0-7.0.16 "
                "(patch to 7.0.17+)",
                data,
            )
        if _in_range(ver, _VULNERABLE_FORTI_PROXY):
            return CheckResult(
                self.CVE_ID, target, "VULNERABLE",
                f"FortiProxy {version_str} falls in a vulnerable range "
                "(patch to 7.0.20+ or 7.2.13+)",
                data,
            )

        return CheckResult(
            self.CVE_ID, target, "PATCHED",
            f"Detected version {version_str} is not in the known-vulnerable ranges",
            data,
        )
