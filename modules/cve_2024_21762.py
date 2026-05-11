"""
CVE-2024-21762
FortiOS SSL VPN out-of-bounds write via malformed Transfer-Encoding chunked
request. Vulnerable targets stall/timeout on a crafted chunk; patched targets
return 403 Forbidden.
Affected: FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14,
          6.2.0-6.2.15, 6.0.x.
"""

import socket
import ssl

from .base import BaseCheck, CheckResult

_TIMEOUT = 10

_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

# Control: well-formed zero-chunk — FortiGate SSL VPN returns 403
_CONTROL_TEMPLATE = (
    "POST /remote/VULNCHECK HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "\r\n"
)

# Probe: oversized chunk value — vulnerable targets stall indefinitely
_PROBE_TEMPLATE = (
    "POST /remote/VULNCHECK HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0000000000000000FF\r\n"
    "\r\n"
)


def _send(host: str, port: int, raw_request: str):
    """Returns response bytes, 0 on timeout, or -1 on connection failure."""
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
    except OSError:
        return -1
    try:
        tls = _CTX.wrap_socket(sock)
        tls.send(raw_request.encode())
        try:
            return tls.read(4096)
        except socket.timeout:
            return 0
    except Exception:
        return -1
    finally:
        try:
            sock.close()
        except Exception:
            pass


class CVE_2024_21762(BaseCheck):
    CVE_ID = "CVE-2024-21762"
    DESCRIPTION = "SSL VPN Out-of-Bounds Write via Transfer-Encoding"
    AFFECTED_VERSIONS = (
        "FortiOS 6.0.x, 6.2.x, 6.4.0-6.4.14, "
        "7.0.0-7.0.13, 7.2.0-7.2.6, 7.4.0-7.4.2"
    )

    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        target = f"{host}:{port}"

        control = _send(host, port, _CONTROL_TEMPLATE.format(host=target))

        if control == -1:
            return CheckResult(self.CVE_ID, target, "ERROR", "Connection failed")
        if control == 0:
            return CheckResult(self.CVE_ID, target, "UNKNOWN",
                               "Control request timed out — cannot distinguish vulnerable/patched")
        if b"HTTP/1.1 403" not in control:
            return CheckResult(self.CVE_ID, target, "UNKNOWN",
                               "Control request did not return HTTP 403 — "
                               "target does not appear to be a FortiGate SSL VPN on this port")

        probe = _send(host, port, _PROBE_TEMPLATE.format(host=target))

        if probe == -1:
            return CheckResult(self.CVE_ID, target, "ERROR", "Probe connection failed")
        if probe == 0:
            return CheckResult(
                self.CVE_ID, target, "VULNERABLE",
                "Target stalled on malformed chunk (timeout indicates OOB write path)",
            )
        return CheckResult(
            self.CVE_ID, target, "PATCHED",
            "Target responded to malformed chunk without stalling",
        )
