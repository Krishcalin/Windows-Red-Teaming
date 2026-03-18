"""Unit tests for core.models data structures."""

from __future__ import annotations

from core.models import (
    ConnectionMethod,
    Finding,
    ModuleResult,
    ScanResult,
    Severity,
    Target,
)


# ── Severity ────────────────────────────────────────────────────────

def test_severity_ordering():
    """CRITICAL < HIGH < MEDIUM < LOW < INFO by rank."""
    ordered = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            assert ordered[i].rank < ordered[j].rank
            assert ordered[i] < ordered[j]


# ── Target ──────────────────────────────────────────────────────────

def test_target_is_local():
    """A target with host='localhost' reports is_local=True."""
    t = Target(host="localhost", connection=ConnectionMethod.WINRM)
    assert t.is_local is True


def test_target_effective_port():
    """WinRM with ssl=True defaults to port 5986."""
    t = Target(host="10.0.0.1", connection=ConnectionMethod.WINRM, ssl=True)
    assert t.effective_port == 5986


# ── Finding ─────────────────────────────────────────────────────────

def test_finding_to_dict(sample_finding: Finding):
    """to_dict() includes every expected key."""
    d = sample_finding.to_dict()
    expected_keys = {
        "finding_id",
        "technique_id",
        "technique_name",
        "tactic",
        "severity",
        "description",
        "evidence",
        "recommendation",
        "mitigations",
        "cwe",
        "timestamp",
    }
    assert expected_keys == set(d.keys())
    assert d["technique_id"] == "T1082"
    assert d["severity"] == "MEDIUM"


# ── ModuleResult ────────────────────────────────────────────────────

def test_module_result_add_finding(
    sample_module_result: ModuleResult,
    sample_finding: Finding,
):
    """add_finding() appends to the findings list."""
    assert len(sample_module_result.findings) == 0
    sample_module_result.add_finding(sample_finding)
    assert len(sample_module_result.findings) == 1
    assert sample_module_result.findings[0] is sample_finding


def test_module_result_max_severity(sample_module_result: ModuleResult):
    """max_severity returns the most severe finding (lowest rank)."""
    assert sample_module_result.max_severity is None

    sample_module_result.add_finding(
        Finding(
            technique_id="T1082",
            technique_name="System Info",
            tactic="Discovery",
            severity=Severity.LOW,
            description="low",
        )
    )
    assert sample_module_result.max_severity == Severity.LOW

    sample_module_result.add_finding(
        Finding(
            technique_id="T1082",
            technique_name="System Info",
            tactic="Discovery",
            severity=Severity.HIGH,
            description="high",
        )
    )
    assert sample_module_result.max_severity == Severity.HIGH


# ── ScanResult ──────────────────────────────────────────────────────

def test_scan_result_aggregate():
    """ScanResult aggregates findings across module results."""
    target = Target(host="localhost")
    scan = ScanResult(target=target)

    mr1 = ModuleResult(
        technique_id="T1082",
        technique_name="System Info",
        tactic="Discovery",
    )
    mr1.add_finding(
        Finding(
            technique_id="T1082",
            technique_name="System Info",
            tactic="Discovery",
            severity=Severity.MEDIUM,
            description="f1",
        )
    )

    mr2 = ModuleResult(
        technique_id="T1059",
        technique_name="Command Execution",
        tactic="Execution",
    )
    mr2.add_finding(
        Finding(
            technique_id="T1059",
            technique_name="Command Execution",
            tactic="Execution",
            severity=Severity.CRITICAL,
            description="f2",
        )
    )
    mr2.add_finding(
        Finding(
            technique_id="T1059",
            technique_name="Command Execution",
            tactic="Execution",
            severity=Severity.MEDIUM,
            description="f3",
        )
    )

    scan.add_module_result(mr1)
    scan.add_module_result(mr2)

    assert scan.techniques_tested == 2
    assert scan.techniques_with_findings == 2
    assert scan.total_findings == 3
    assert scan.findings_by_severity["CRITICAL"] == 1
    assert scan.findings_by_severity["MEDIUM"] == 2
