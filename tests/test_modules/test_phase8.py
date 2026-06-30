"""Tests for Phase 8 — new ATT&CK technique modules.

Covers T1003.004 (LSA Secrets), T1112 (Modify Registry),
T1543.003 (Windows Service), and T1490 (Inhibit System Recovery).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.models import (
    ConnectionMethod,
    ModuleStatus,
    OSType,
    Severity,
    Target,
)
from core.session import BaseSession, CommandResult


@pytest.fixture
def mock_session():
    session = MagicMock(spec=BaseSession)
    session.target = Target(
        host="10.0.0.5",
        connection=ConnectionMethod.WINRM,
        os_type=OSType.SERVER_2022,
    )
    session.os_type = OSType.SERVER_2022
    return session


def _cmd(stdout="", stderr="", success=True):
    return CommandResult(
        stdout=stdout, stderr=stderr,
        return_code=0 if success else 1, success=success,
    )


# ── T1003.004 LSA Secrets ───────────────────────────────────────

class TestT1003004LsaSecrets:
    def test_weak_configuration(self, mock_session):
        from modules.credential_access.T1003_004_lsa_secrets import LsaSecretsCheck

        mock_session.run_powershell.side_effect = [
            _cmd(""),                                                  # RunAsPPL not set
            _cmd("1"),                                                 # WDigest enabled
            _cmd('{"AutoAdminLogon":"1","HasDefaultPassword":true}'),  # autologon secret
            _cmd("Other Object Access Events  No Auditing"),           # auditing off
        ]

        mod = LsaSecretsCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS
        descs = " ".join(f.description for f in result.findings)
        assert "LSA Protection" in descs
        assert "WDigest" in descs
        assert "Auto-logon" in descs
        assert "auditing" in descs.lower()
        # WDigest cleartext caching is the critical finding here
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    def test_hardened_configuration(self, mock_session):
        from modules.credential_access.T1003_004_lsa_secrets import LsaSecretsCheck

        mock_session.run_powershell.side_effect = [
            _cmd("1"),                                  # RunAsPPL enabled
            _cmd("0"),                                  # WDigest disabled
            _cmd('{"AutoAdminLogon":"0","HasDefaultPassword":false}'),
            _cmd("Other Object Access Events  Success and Failure"),
        ]

        mod = LsaSecretsCheck()
        result = mod.check(mock_session)

        # No HIGH/CRITICAL findings when hardened
        assert all(
            f.severity in (Severity.INFO, Severity.LOW)
            for f in result.findings
        )

    def test_metadata(self):
        from modules.credential_access.T1003_004_lsa_secrets import LsaSecretsCheck

        mod = LsaSecretsCheck()
        assert mod.TECHNIQUE_ID == "T1003.004"
        assert mod.TACTIC == "Credential Access"
        assert mod.REQUIRES_ADMIN is True
        assert len(mod.get_mitigations()) > 0


# ── T1112 Modify Registry ───────────────────────────────────────

class TestT1112ModifyRegistry:
    def test_evasion_artifacts_detected(self, mock_session):
        from modules.defense_evasion.T1112_modify_registry import ModifyRegistryCheck

        mock_session.run_powershell.side_effect = [
            _cmd("Registry   No Auditing"),                              # auditing off
            _cmd("1"),                                                   # HKCU DisableRegistryTools
            _cmd(""),                                                    # HKLM DisableRegistryTools
            _cmd('{"Image":"taskmgr.exe","Debugger":"C:\\\\evil.exe"}'),  # IFEO debugger
            _cmd("1"),                                                   # Defender disabled
        ]

        mod = ModifyRegistryCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS
        descs = " ".join(f.description for f in result.findings)
        assert "auditing is disabled" in descs.lower()
        assert "Image File Execution Options" in descs
        assert "Defender" in descs
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    def test_clean_system(self, mock_session):
        from modules.defense_evasion.T1112_modify_registry import ModifyRegistryCheck

        mock_session.run_powershell.side_effect = [
            _cmd("Registry   Success and Failure"),  # auditing on
            _cmd(""),                                 # HKCU clean
            _cmd(""),                                 # HKLM clean
            _cmd("[]"),                               # no IFEO debuggers
            _cmd(""),                                 # Defender not disabled
        ]

        mod = ModifyRegistryCheck()
        result = mod.check(mock_session)

        assert not any(
            f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in result.findings
        )

    def test_metadata(self):
        from modules.defense_evasion.T1112_modify_registry import ModifyRegistryCheck

        mod = ModifyRegistryCheck()
        assert mod.TECHNIQUE_ID == "T1112"
        assert mod.TACTIC == "Defense Evasion"


# ── T1543.003 Windows Service ───────────────────────────────────

class TestT1543003WindowsService:
    def test_weak_services(self, mock_session):
        from modules.persistence.T1543_003_windows_service import WindowsServiceCheck

        mock_session.run_powershell.side_effect = [
            _cmd('{"Name":"Vuln","PathName":"C:\\\\Program Files\\\\App\\\\svc.exe"}'),  # unquoted
            _cmd('[{"Name":"Bad","PathName":"C:\\\\Users\\\\bob\\\\svc.exe"}]'),         # user-writable
        ]

        mod = WindowsServiceCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS
        descs = " ".join(f.description for f in result.findings)
        assert "Unquoted service path" in descs
        assert "user-writable" in descs.lower()
        assert sum(1 for f in result.findings if f.severity == Severity.HIGH) >= 2

    def test_clean_services(self, mock_session):
        from modules.persistence.T1543_003_windows_service import WindowsServiceCheck

        mock_session.run_powershell.side_effect = [
            _cmd("[]"),                                                         # no unquoted
            _cmd('[{"Name":"Ok","PathName":"C:\\\\Windows\\\\System32\\\\svc.exe"}]'),
        ]

        mod = WindowsServiceCheck()
        result = mod.check(mock_session)

        assert all(f.severity == Severity.INFO for f in result.findings)

    def test_metadata(self):
        from modules.persistence.T1543_003_windows_service import WindowsServiceCheck

        mod = WindowsServiceCheck()
        assert mod.TECHNIQUE_ID == "T1543.003"
        assert mod.TACTIC == "Persistence"


# ── T1490 Inhibit System Recovery ───────────────────────────────

class TestT1490InhibitRecovery:
    def test_recovery_inhibited(self, mock_session):
        from modules.impact.T1490_inhibit_recovery import InhibitRecoveryCheck

        mock_session.run_powershell.side_effect = [
            _cmd("0"),                                              # no shadow copies
            _cmd('{"Status":"Stopped","StartType":"Disabled"}'),   # VSS disabled
            _cmd("Windows RE status:         Disabled"),           # WinRE off
            _cmd("bootstatuspolicy        ignoreallfailures"),     # boot recovery tampered
        ]

        mod = InhibitRecoveryCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS
        descs = " ".join(f.description for f in result.findings)
        assert "No Volume Shadow Copies" in descs
        assert "VSS" in descs
        assert "WinRE" in descs or "Windows Recovery" in descs
        assert "ignoreallfailures" in descs
        assert sum(1 for f in result.findings if f.severity == Severity.HIGH) >= 2

    def test_recovery_healthy(self, mock_session):
        from modules.impact.T1490_inhibit_recovery import InhibitRecoveryCheck

        mock_session.run_powershell.side_effect = [
            _cmd("3"),                                            # shadow copies present
            _cmd('{"Status":"Running","StartType":"Manual"}'),   # VSS normal
            _cmd("Windows RE status:         Enabled"),          # WinRE on
            _cmd("recoveryenabled           Yes"),               # boot recovery fine
        ]

        mod = InhibitRecoveryCheck()
        result = mod.check(mock_session)

        assert not any(
            f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in result.findings
        )

    def test_metadata(self):
        from modules.impact.T1490_inhibit_recovery import InhibitRecoveryCheck

        mod = InhibitRecoveryCheck()
        assert mod.TECHNIQUE_ID == "T1490"
        assert mod.TACTIC == "Impact"
        assert mod.REQUIRES_ADMIN is True
