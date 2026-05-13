"""
CVE-2025-64446
Fortinet FortiWeb authentication bypass via path traversal in the fwbcgi CGI
component. An unauthenticated GET request using a path traversal sequence
exposes the fwbcgi handler directly; vulnerable targets return HTTP 200 with
a specific JSON error payload.

Detection logic based on original research by watchTowr Labs and the
SensePost scanner at https://github.com/sensepost/CVE-2025-64446.

Affected: Fortinet FortiWeb (see Fortinet advisory for specific versions).

Note: This module assumes HTTPS. FortiWeb management interfaces running
on plain HTTP will return ERROR; target the HTTPS port in that case or
contact the tool maintainer to add HTTP support.
"""

import http.client
import json
import ssl

from .base import BaseCheck, CheckResult

_TARGET_PATH = "/api/v2.0/cmdb/system/admin/../../../../../cgi-bin/fwbcgi"
_TIMEOUT = 10

# Exact response body and headers returned by a patched FortiWeb on 403.
# Content-Length 199 is part of the patched fingerprint.
_PATCHED_CONTENT_LENGTH = "199"
_PATCHED_CONTENT_TYPE = "text/html; charset=iso-8859-1"
_PATCHED_BODY = (
    b'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
    b"<html><head>\n"
    b"<title>403 Forbidden</title>\n"
    b"</head><body>\n"
    b"<h1>Forbidden</h1>\n"
    b"<p>You don't have permission to access this resource.</p>\n"
    b"</body></html>\n"
)


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


_SSL_CTX = _build_ssl_context()


class CVE_2025_64446(BaseCheck):
    CVE_ID = "CVE-2025-64446"
    DESCRIPTION = "FortiWeb fwbcgi CGI Authentication Bypass"
    AFFECTED_VERSIONS = "Fortinet FortiWeb (see Fortinet advisory)"

    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        target = f"{host}:{port}"

        try:
            conn = http.client.HTTPSConnection(
                host, port, timeout=_TIMEOUT, context=_SSL_CTX
            )
            conn.request(
                "GET",
                _TARGET_PATH,
                headers={
                    "Host": target,
                    "User-Agent": "fwbcgi-scanner/1.0",
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()
            status = resp.status
            body = resp.read()
            headers = {k.lower(): v for k, v in resp.getheaders()}
        except Exception as e:
            return CheckResult(self.CVE_ID, target, "ERROR", str(e))
        finally:
            try:
                conn.close()
            except Exception:
                pass

        # ── Vulnerable: HTTP 200 with specific JSON payload ───────────────
        if status == 200:
            try:
                payload = json.loads(body.decode("utf-8", errors="ignore"))
            except (json.JSONDecodeError, ValueError):
                return CheckResult(
                    self.CVE_ID, target, "UNKNOWN",
                    "HTTP 200 but non-JSON body — indeterminate",
                )
            if isinstance(payload, dict):
                errcode = str(payload["errcode"]) if "errcode" in payload else None
                message = str(payload["message"]) if "message" in payload else None
                if errcode == "0" and message == "(null)":
                    return CheckResult(
                        self.CVE_ID, target, "VULNERABLE",
                        "fwbcgi endpoint exposed — HTTP 200 with errcode=0, message=(null)",
                        {"errcode": errcode, "message": message},
                    )
                return CheckResult(
                    self.CVE_ID, target, "UNKNOWN",
                    f"HTTP 200 with unexpected JSON (errcode={errcode}, message={message}) "
                    "— endpoint reachable but response does not match known-vulnerable pattern",
                    {"raw_payload": payload},
                )
            return CheckResult(
                self.CVE_ID, target, "UNKNOWN",
                "HTTP 200 with non-object JSON body — indeterminate",
            )

        # ── Patched: HTTP 403 ─────────────────────────────────────────────
        if status == 403:
            cl = headers.get("content-length")
            ct = headers.get("content-type", "").lower()
            if (
                cl == _PATCHED_CONTENT_LENGTH
                and ct == _PATCHED_CONTENT_TYPE
                and body == _PATCHED_BODY
            ):
                return CheckResult(
                    self.CVE_ID, target, "PATCHED",
                    "HTTP 403 with exact patched-FortiWeb response signature",
                )
            return CheckResult(
                self.CVE_ID, target, "UNKNOWN",
                f"HTTP 403 but signature does not match patched FortiWeb "
                f"(content-length={cl}, content-type={ct})",
            )

        return CheckResult(
            self.CVE_ID, target, "UNKNOWN",
            f"HTTP {status} — indeterminate response",
        )
