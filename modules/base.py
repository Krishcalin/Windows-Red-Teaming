"""Abstract base class for all technique modules.

Every technique module inherits from BaseModule and implements:
- check(session)    — passive, read-only detection
- simulate(session) — active simulation (requires --simulate flag)
- cleanup(session)  — revert changes made during simulate
- get_mitigations() — recommended remediations

Required class attributes:
    TECHNIQUE_ID, TECHNIQUE_NAME, TACTIC, SEVERITY,
    SUPPORTED_OS, REQUIRES_ADMIN, SAFE_MODE
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

import structlog

from core.models import (
    Finding,
    ModuleResult,
    ModuleStatus,
    OSType,
    Severity,
)
from core.session import BaseSession

log = structlog.get_logger(component="module")


class BaseModule(ABC):
    """Abstract base class for MITRE ATT&CK technique modules.

    Subclasses must set all required class attributes and implement
    the check(), simulate(), cleanup(), and get_mitigations() methods.
    """

    # --- Required class attributes (must be overridden) ---
    TECHNIQUE_ID: ClassVar[str]          # e.g. "T1059.001"
    TECHNIQUE_NAME: ClassVar[str]        # e.g. "PowerShell"
    TACTIC: ClassVar[str]                # e.g. "Execution"
    SEVERITY: ClassVar[Severity]         # default severity for findings
    SUPPORTED_OS: ClassVar[list[OSType]] # which OS versions this supports
    REQUIRES_ADMIN: ClassVar[bool]       # needs elevated privileges?
    SAFE_MODE: ClassVar[bool] = True     # True = check-only is safe

    def __init__(self) -> None:
        self._log = log.bind(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
        )

    # --- Core interface ---

    @abstractmethod
    def check(self, session: BaseSession) -> ModuleResult:
        """Passive, read-only check for the technique.

        This method must NOT modify the target system in any way.
        It should inspect configuration, registry, services, etc.
        and report findings about whether the system is vulnerable
        to or protected against this technique.

        Args:
            session: Connected session to the target.

        Returns:
            ModuleResult with findings (if any).
        """

    @abstractmethod
    def simulate(self, session: BaseSession) -> ModuleResult:
        """Active simulation of the technique.

        This method may make temporary changes to demonstrate the
        technique. Any changes MUST be reverted by cleanup().
        Only runs when --simulate flag is explicitly provided.

        Args:
            session: Connected session to the target.

        Returns:
            ModuleResult with findings and evidence.
        """

    @abstractmethod
    def cleanup(self, session: BaseSession) -> None:
        """Revert any changes made during simulate().

        Called automatically after simulate() completes.
        Must be idempotent — safe to call even if simulate()
        was not run or failed partway through.

        Args:
            session: Connected session to the target.
        """

    @abstractmethod
    def get_mitigations(self) -> list[str]:
        """Return recommended mitigations for this technique.

        Returns:
            List of human-readable mitigation recommendations.
        """

    # --- Helpers ---

    def create_result(
        self,
        target_host: str = "",
        simulated: bool = False,
    ) -> ModuleResult:
        """Create a new ModuleResult pre-filled with this module's metadata."""
        return ModuleResult(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
            tactic=self.TACTIC,
            target_host=target_host,
            was_simulated=simulated,
        )

    def add_finding(
        self,
        result: ModuleResult,
        description: str,
        severity: Severity | None = None,
        evidence: str = "",
        recommendation: str = "",
        cwe: str = "",
    ) -> Finding:
        """Create a Finding and add it to the ModuleResult.

        Args:
            result: The ModuleResult to add the finding to.
            description: What was found.
            severity: Override default severity if needed.
            evidence: Raw evidence data.
            recommendation: Specific remediation advice.
            cwe: CWE identifier if applicable.

        Returns:
            The created Finding.
        """
        finding = Finding(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
            tactic=self.TACTIC,
            severity=severity or self.SEVERITY,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            mitigations=self.get_mitigations(),
            cwe=cwe,
        )
        result.add_finding(finding)
        self._log.info(
            "finding_added",
            severity=finding.severity.value,
            description=description[:120],
        )
        return finding

    def supports_os(self, os_type: OSType | None) -> bool:
        """Check if this module supports the given OS type.

        If os_type is None (unknown), returns True to allow the module
        to attempt execution.
        """
        if os_type is None:
            return True
        return os_type in self.SUPPORTED_OS

    def skip_result(self, reason: str, target_host: str = "") -> ModuleResult:
        """Create a SKIPPED result with the given reason."""
        result = self.create_result(target_host=target_host)
        result.status = ModuleStatus.SKIPPED
        result.error_message = reason
        result.complete()
        self._log.info("module_skipped", reason=reason)
        return result

    def error_result(
        self, error: str, target_host: str = ""
    ) -> ModuleResult:
        """Create an ERROR result with the given message."""
        result = self.create_result(target_host=target_host)
        result.status = ModuleStatus.ERROR
        result.error_message = error
        result.complete()
        self._log.error("module_error", error=error)
        return result

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"{self.TECHNIQUE_ID} {self.TECHNIQUE_NAME}>"
        )
