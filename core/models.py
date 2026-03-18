"""Data models for the Windows Red Teaming tool.

Defines the core data structures used across all modules:
- Target: connection details for a scan target
- Finding: individual security finding from a module
- ModuleResult: aggregated result from a single module execution
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity levels, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (lower = more severe)."""
        return _SEVERITY_RANK[self]

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_THRESHOLD: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class ModuleStatus(str, Enum):
    """Execution status of a module."""

    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"
    ERROR = "error"


class ConnectionMethod(str, Enum):
    """Supported connection methods to targets."""

    LOCAL = "local"
    WINRM = "winrm"
    SMB = "smb"
    WMI = "wmi"


class OSType(str, Enum):
    """Supported Windows OS types."""

    WIN10 = "Windows 10"
    WIN11 = "Windows 11"
    SERVER_2019 = "Server 2019"
    SERVER_2022 = "Server 2022"


@dataclass
class Target:
    """Represents a scan target machine.

    Attributes:
        host: IP address or hostname.
        connection: How to connect (local, winrm, smb, wmi).
        port: Connection port (default depends on method).
        domain: Active Directory domain (if applicable).
        username: Authentication username.
        password: Authentication password.
        use_kerberos: Use Kerberos authentication instead of NTLM.
        ssl: Use SSL/TLS for connection.
        os_type: Detected or specified OS type.
        metadata: Additional target metadata collected during scan.
    """

    host: str
    connection: ConnectionMethod = ConnectionMethod.LOCAL
    port: int | None = None
    domain: str = ""
    username: str = ""
    password: str = ""
    use_kerberos: bool = False
    ssl: bool = True
    os_type: OSType | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_local(self) -> bool:
        return (
            self.connection == ConnectionMethod.LOCAL
            or self.host in ("localhost", "127.0.0.1", "::1")
        )

    @property
    def effective_port(self) -> int:
        if self.port is not None:
            return self.port
        match self.connection:
            case ConnectionMethod.WINRM:
                return 5986 if self.ssl else 5985
            case ConnectionMethod.SMB:
                return 445
            case ConnectionMethod.WMI:
                return 135
            case _:
                return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "connection": self.connection.value,
            "port": self.effective_port,
            "domain": self.domain,
            "os_type": self.os_type.value if self.os_type else None,
        }


@dataclass
class Finding:
    """A single security finding produced by a technique module.

    Attributes:
        technique_id: MITRE ATT&CK technique ID (e.g. T1059.001).
        technique_name: Human-readable technique name.
        tactic: ATT&CK tactic name.
        severity: Finding severity level.
        description: Detailed description of what was found.
        evidence: Raw evidence (command output, registry values, etc.).
        recommendation: Suggested remediation.
        mitigations: List of mitigation references.
        cwe: CWE identifier if applicable.
        timestamp: When the finding was generated.
        finding_id: Unique identifier for this finding.
    """

    technique_id: str
    technique_name: str
    tactic: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    mitigations: list[str] = field(default_factory=list)
    cwe: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "mitigations": self.mitigations,
            "cwe": self.cwe,
            "timestamp": self.timestamp,
        }


@dataclass
class ModuleResult:
    """Aggregated result from executing a single technique module.

    Attributes:
        technique_id: MITRE ATT&CK technique ID.
        technique_name: Human-readable technique name.
        tactic: ATT&CK tactic name.
        status: Execution status (success, failure, skipped, error).
        findings: List of security findings.
        error_message: Error details if status is ERROR.
        start_time: When the module started execution.
        end_time: When the module finished execution.
        target_host: Target that was scanned.
        was_simulated: Whether active simulation was run.
    """

    technique_id: str
    technique_name: str
    tactic: str
    status: ModuleStatus = ModuleStatus.SUCCESS
    findings: list[Finding] = field(default_factory=list)
    error_message: str = ""
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    end_time: str = ""
    target_host: str = ""
    was_simulated: bool = False

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return min(f.severity for f in self.findings)

    @property
    def duration_seconds(self) -> float | None:
        if not self.end_time or not self.start_time:
            return None
        start = datetime.fromisoformat(self.start_time)
        end = datetime.fromisoformat(self.end_time)
        return (end - start).total_seconds()

    def complete(self, status: ModuleStatus | None = None) -> None:
        """Mark this result as complete, setting end_time and optional status."""
        self.end_time = datetime.now(timezone.utc).isoformat()
        if status is not None:
            self.status = status

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "target_host": self.target_host,
            "was_simulated": self.was_simulated,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class ScanResult:
    """Top-level result for an entire scan run.

    Attributes:
        scan_id: Unique identifier for this scan run.
        target: The target that was scanned.
        profile: Scan profile used (quick, full, stealth).
        simulate: Whether active simulation was enabled.
        module_results: Results from each module that ran.
        start_time: Scan start time.
        end_time: Scan end time.
    """

    target: Target
    profile: str = "full"
    simulate: bool = False
    module_results: list[ModuleResult] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    end_time: str = ""

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for mr in self.module_results:
            findings.extend(mr.findings)
        return findings

    @property
    def total_findings(self) -> int:
        return sum(len(mr.findings) for mr in self.module_results)

    @property
    def findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.all_findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def techniques_tested(self) -> int:
        return len(self.module_results)

    @property
    def techniques_with_findings(self) -> int:
        return sum(1 for mr in self.module_results if mr.has_findings)

    def complete(self) -> None:
        self.end_time = datetime.now(timezone.utc).isoformat()

    def add_module_result(self, result: ModuleResult) -> None:
        self.module_results.append(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target.to_dict(),
            "profile": self.profile,
            "simulate": self.simulate,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "techniques_tested": self.techniques_tested,
            "techniques_with_findings": self.techniques_with_findings,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "module_results": [mr.to_dict() for mr in self.module_results],
        }
