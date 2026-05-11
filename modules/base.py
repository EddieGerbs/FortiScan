from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class CheckResult:
    cve: str
    target: str
    status: str  # VULNERABLE | PATCHED | UNKNOWN | ERROR | NOT_FOUND
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


class BaseCheck(ABC):
    CVE_ID: str = ""
    DESCRIPTION: str = ""
    AFFECTED_VERSIONS: str = ""

    def run(self, host: str, port: int, **kwargs) -> CheckResult:
        try:
            return self.check(host, port, **kwargs)
        except Exception as e:
            return CheckResult(
                cve=self.CVE_ID,
                target=f"{host}:{port}",
                status="ERROR",
                detail=str(e),
            )

    @abstractmethod
    def check(self, host: str, port: int, **kwargs) -> CheckResult:
        pass

    @classmethod
    def info(cls) -> dict:
        return {
            "cve": cls.CVE_ID,
            "description": cls.DESCRIPTION,
            "affected": cls.AFFECTED_VERSIONS,
        }
