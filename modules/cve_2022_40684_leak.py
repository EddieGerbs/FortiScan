"""
CVE-2022-40684 — 2025 FortiGate Config Leak Database Lookup
Checks whether a target IP:Port appears in the dataset of ~15,000 FortiGate
devices whose configurations were leaked publicly in January 2025 following
exploitation of the CVE-2022-40684 authentication bypass.
"""

import os

from .base import BaseCheck, CheckResult

_DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "affected_ips.txt")


class CVE_2022_40684_Leak(BaseCheck):
    CVE_ID = "CVE-2022-40684-LEAK"
    DESCRIPTION = "2025 Config Leak Dataset — Affected IP Lookup"
    AFFECTED_VERSIONS = "Devices exploited via CVE-2022-40684 (data leaked Jan 2025)"

    _dataset: set = None

    @classmethod
    def _load(cls) -> None:
        if cls._dataset is not None:
            return
        cls._dataset = set()
        try:
            with open(_DATA_FILE) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("ip_address"):
                        cls._dataset.add(line)
        except FileNotFoundError:
            pass

    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        self._load()
        target = f"{host}:{port}"

        if target in self._dataset:
            return CheckResult(
                self.CVE_ID, target, "VULNERABLE",
                "Found in January 2025 FortiGate credential leak dataset",
            )

        # Secondary scan: check if the IP appears on any common port
        for common_port in (443, 4443, 8443, 10443):
            alt = f"{host}:{common_port}"
            if alt in self._dataset and common_port != port:
                return CheckResult(
                    self.CVE_ID, target, "VULNERABLE",
                    f"IP found in leak dataset on port {common_port} (queried port {port})",
                )

        if not self._dataset:
            return CheckResult(self.CVE_ID, target, "ERROR", "Leak dataset file not found")

        return CheckResult(
            self.CVE_ID, target, "NOT_FOUND",
            f"Not present in the 2025 leak dataset ({len(self._dataset):,} entries checked)",
        )
