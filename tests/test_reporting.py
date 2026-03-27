"""Tests for Phase 6 — Reporting, ATT&CK Navigator, and Compliance Mapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.compliance_mapper import (
    ComplianceMapper,
    TECHNIQUE_TO_CIS,
    TECHNIQUE_TO_NIST,
)
from core.mitre_mapper import MitreMapper
from core.models import (
    ConnectionMethod,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanResult,
    Severity,
    Target,
)
from core.reporter import Reporter


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def scan_result() -> ScanResult:
    """Build a representative ScanResult with findings across several techniques."""
    target = Target(host="10.0.0.5", connection=ConnectionMethod.LOCAL)
    sr = ScanResult(
        target=target,
        profile="full",
        simulate=False,
        scan_id="test_scan_001",
    )

    # Module 1 — Critical finding
    mr1 = ModuleResult(
        technique_id="T1003.001",
        technique_name="LSASS Memory",
        tactic="Credential Access",
        target_host="10.0.0.5",
    )
    mr1.add_finding(Finding(
        technique_id="T1003.001",
        technique_name="LSASS Memory",
        tactic="Credential Access",
        severity=Severity.CRITICAL,
        description="Credential Guard not enabled",
        evidence="SecurityServicesRunning = 0",
        recommendation="Enable Credential Guard",
    ))
    mr1.complete(ModuleStatus.SUCCESS)

    # Module 2 — Medium finding
    mr2 = ModuleResult(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        target_host="10.0.0.5",
    )
    mr2.add_finding(Finding(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        severity=Severity.MEDIUM,
        description="Secure Boot is disabled",
        evidence="SecureBoot = False",
        recommendation="Enable Secure Boot in BIOS",
    ))
    mr2.complete(ModuleStatus.SUCCESS)

    # Module 3 — High finding (lateral movement)
    mr3 = ModuleResult(
        technique_id="T1021.001",
        technique_name="Remote Desktop Protocol",
        tactic="Lateral Movement",
        target_host="10.0.0.5",
    )
    mr3.add_finding(Finding(
        technique_id="T1021.001",
        technique_name="Remote Desktop Protocol",
        tactic="Lateral Movement",
        severity=Severity.HIGH,
        description="RDP enabled without NLA",
        evidence="fDenyTSConnections=0x0",
        recommendation="Enable NLA",
    ))
    mr3.complete(ModuleStatus.SUCCESS)

    # Module 4 — No findings (clean)
    mr4 = ModuleResult(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        target_host="10.0.0.5",
    )
    mr4.complete(ModuleStatus.SUCCESS)

    sr.add_module_result(mr1)
    sr.add_module_result(mr2)
    sr.add_module_result(mr3)
    sr.add_module_result(mr4)
    sr.complete()
    return sr


@pytest.fixture
def tmp_output(tmp_path) -> Path:
    return tmp_path / "reports"


# ═══════════════════════════════════════════════════════════════════
# Reporter Tests
# ═══════════════════════════════════════════════════════════════════


class TestReporter:
    def test_generate_json(self, scan_result, tmp_output):
        reporter = Reporter(output_dir=tmp_output)
        path = reporter.generate_json(scan_result, "test.json")

        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["scan_id"] == "test_scan_001"
        assert data["total_findings"] == 3
        assert data["techniques_tested"] == 4
        assert len(data["module_results"]) == 4

    def test_generate_csv(self, scan_result, tmp_output):
        reporter = Reporter(output_dir=tmp_output)
        path = reporter.generate_csv(scan_result, "test.csv")

        assert path.exists()
        content = path.read_text(encoding="utf-8")
        lines = [l for l in content.strip().split("\n") if l.strip()]
        assert len(lines) == 4  # header + 3 findings

    def test_generate_html(self, scan_result, tmp_output):
        reporter = Reporter(
            template_dir="templates",
            output_dir=tmp_output,
        )
        path = reporter.generate_html(scan_result, "test.html")

        assert path.exists()
        html = path.read_text(encoding="utf-8")
        assert "Red Team Scan Report" in html
        assert "T1003.001" in html
        assert "Credential Guard" in html
        assert "10.0.0.5" in html

    def test_print_summary(self, scan_result):
        reporter = Reporter()
        summary = reporter.print_summary(scan_result)

        assert "SCAN RESULTS SUMMARY" in summary
        assert "10.0.0.5" in summary
        assert "CRITICAL" in summary
        assert "3" in summary  # total findings

    def test_severity_counts_in_summary(self, scan_result):
        reporter = Reporter()
        summary = reporter.print_summary(scan_result)

        # Should show counts for each severity
        assert "CRITICAL" in summary
        assert "HIGH" in summary
        assert "MEDIUM" in summary


# ═══════════════════════════════════════════════════════════════════
# MitreMapper Tests
# ═══════════════════════════════════════════════════════════════════


class TestMitreMapper:
    def test_generate_layer(self, scan_result, tmp_output):
        mapper = MitreMapper(output_dir=tmp_output)
        path = mapper.generate_layer(scan_result, "test_layer.json")

        assert path.exists()
        layer = json.loads(path.read_text(encoding="utf-8"))

        assert layer["domain"] == "enterprise-attack"
        assert "10.0.0.5" in layer["name"]
        assert len(layer["techniques"]) == 4

    def test_technique_colors(self, scan_result, tmp_output):
        mapper = MitreMapper(output_dir=tmp_output)
        path = mapper.generate_layer(scan_result, "test_colors.json")
        layer = json.loads(path.read_text(encoding="utf-8"))

        techniques = {t["techniqueID"]: t for t in layer["techniques"]}

        # T1003.001 should have critical color (red)
        assert techniques["T1003.001"]["color"] == "#ff0000"
        # T1046 has no findings — should be clean (green)
        assert techniques["T1046"]["color"] == "#00cc00"

    def test_severity_scores(self, scan_result, tmp_output):
        mapper = MitreMapper(output_dir=tmp_output)
        path = mapper.generate_layer(scan_result, "test_scores.json")
        layer = json.loads(path.read_text(encoding="utf-8"))

        techniques = {t["techniqueID"]: t for t in layer["techniques"]}

        assert techniques["T1003.001"]["score"] == 4  # CRITICAL
        assert techniques["T1021.001"]["score"] == 3  # HIGH
        assert techniques["T1082"]["score"] == 2       # MEDIUM
        assert techniques["T1046"]["score"] == 0       # no findings

    def test_tactic_normalization(self):
        mapper = MitreMapper()
        assert mapper._normalize_tactic("Lateral Movement") == "lateral-movement"
        assert mapper._normalize_tactic("Command and Control") == "command-and-control"
        assert mapper._normalize_tactic("Defense Evasion") == "defense-evasion"
        assert mapper._normalize_tactic("Discovery") == "discovery"

    def test_legend_items(self, scan_result, tmp_output):
        mapper = MitreMapper(output_dir=tmp_output)
        path = mapper.generate_layer(scan_result, "test_legend.json")
        layer = json.loads(path.read_text(encoding="utf-8"))

        labels = [item["label"] for item in layer["legendItems"]]
        assert "Critical finding" in labels
        assert "No findings" in labels
        assert "Not tested" in labels

    def test_subtechnique_handling(self, scan_result, tmp_output):
        mapper = MitreMapper(output_dir=tmp_output)
        path = mapper.generate_layer(scan_result, "test_sub.json")
        layer = json.loads(path.read_text(encoding="utf-8"))

        techniques = {t["techniqueID"]: t for t in layer["techniques"]}

        # T1003.001 is a sub-technique — should show subtechniques
        assert techniques["T1003.001"]["showSubtechniques"] is True
        # T1082 is a parent technique — should not
        assert techniques["T1082"]["showSubtechniques"] is False


# ═══════════════════════════════════════════════════════════════════
# ComplianceMapper Tests
# ═══════════════════════════════════════════════════════════════════


class TestComplianceMapper:
    def test_get_cis_controls(self):
        mapper = ComplianceMapper()

        # Known technique
        cis = mapper.get_cis_controls("T1003.001")
        assert len(cis) >= 2
        assert "6.1" in cis

        # Unknown technique
        assert mapper.get_cis_controls("T9999") == []

    def test_get_nist_controls(self):
        mapper = ComplianceMapper()

        nist = mapper.get_nist_controls("T1021.001")
        assert len(nist) >= 2
        assert "AC-17" in nist

        assert mapper.get_nist_controls("T9999") == []

    def test_all_42_techniques_mapped(self):
        """Verify every technique in the tool has CIS and NIST mappings."""
        from core.engine import ScanEngine
        engine = ScanEngine()
        technique_ids = {m["technique_id"] for m in engine.discovered_modules}

        mapper = ComplianceMapper()
        unmapped_cis = [t for t in technique_ids if not mapper.get_cis_controls(t)]
        unmapped_nist = [t for t in technique_ids if not mapper.get_nist_controls(t)]

        assert unmapped_cis == [], f"CIS unmapped: {unmapped_cis}"
        assert unmapped_nist == [], f"NIST unmapped: {unmapped_nist}"

    def test_map_findings(self, scan_result):
        mapper = ComplianceMapper()
        report = mapper.map_findings(scan_result)

        assert report["scan_id"] == "test_scan_001"
        assert report["summary"]["total_findings"] == 3
        assert report["summary"]["unique_cis_controls_implicated"] > 0
        assert report["summary"]["unique_nist_controls_implicated"] > 0

        # Each finding should have CIS and NIST controls
        for finding in report["findings"]:
            assert len(finding["cis_controls"]) > 0
            assert len(finding["nist_controls"]) > 0

    def test_generate_compliance_report(self, scan_result, tmp_output):
        mapper = ComplianceMapper()
        path = mapper.generate_compliance_report(
            scan_result,
            str(tmp_output / "compliance_test.json"),
        )

        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "summary" in data
        assert "findings" in data
        assert len(data["findings"]) == 3

    def test_cis_nist_coverage_complete(self):
        """All technique IDs in CIS map should also be in NIST map and vice versa."""
        cis_keys = set(TECHNIQUE_TO_CIS.keys())
        nist_keys = set(TECHNIQUE_TO_NIST.keys())

        assert cis_keys == nist_keys, (
            f"CIS-only: {cis_keys - nist_keys}, NIST-only: {nist_keys - cis_keys}"
        )

    def test_ransomware_has_backup_controls(self):
        """T1486 (ransomware) should map to backup-related controls."""
        mapper = ComplianceMapper()
        cis = mapper.get_cis_controls("T1486")
        nist = mapper.get_nist_controls("T1486")

        assert "11.1" in cis  # Data Recovery Process
        assert "CP-9" in nist  # System Backup
