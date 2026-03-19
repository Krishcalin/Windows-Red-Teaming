"""Tests for Phase 3 — Credential Access modules."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from core.models import ModuleStatus, OSType, Severity, Target, ConnectionMethod
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
    return CommandResult(stdout=stdout, stderr=stderr,
                         return_code=0 if success else 1, success=success)


# ── T1003.001 LSASS Memory ──────────────────────────────────────

class TestT1003001LsassMemory:
    def test_no_ppl_no_wdigest(self, mock_session):
        from modules.credential_access.T1003_001_lsass_memory import LsassMemoryCheck

        mock_session.read_registry.side_effect = [
            None,    # RunAsPPL not set
            "1",     # WDigest UseLogonCredential enabled
            None,    # LSASS AuditLevel not set
        ]
        mock_session.run_powershell.side_effect = [
            _cmd("0"),       # Credential Guard — not running
            _cmd("False"),   # ASR rule not found
        ]

        mod = LsassMemoryCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS
        descs = [f.description for f in result.findings]
        assert any("RunAsPPL" in d for d in descs)
        assert any("WDigest" in d for d in descs)
        assert any("Credential Guard" in d for d in descs)

    def test_metadata(self):
        from modules.credential_access.T1003_001_lsass_memory import LsassMemoryCheck

        mod = LsassMemoryCheck()
        assert mod.TECHNIQUE_ID == "T1003.001"
        assert mod.REQUIRES_ADMIN is True
        assert mod.SEVERITY == Severity.CRITICAL


# ── T1003.002 SAM Database ──────────────────────────────────────

class TestT1003002SamDatabase:
    def test_backup_files_found(self, mock_session):
        from modules.credential_access.T1003_002_sam_database import SamDatabaseCheck

        def file_exists(path):
            return "Repair" in path

        mock_session.file_exists.side_effect = file_exists
        mock_session.run_powershell.side_effect = [
            _cmd("3"),       # 3 shadow copies
            _cmd(""),        # SAM ACL — clean
            _cmd("22631"),   # Build number
        ]

        mod = SamDatabaseCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("backup" in d.lower() for d in descs)
        assert any("Shadow" in d for d in descs)

    def test_metadata(self):
        from modules.credential_access.T1003_002_sam_database import SamDatabaseCheck

        mod = SamDatabaseCheck()
        assert mod.TECHNIQUE_ID == "T1003.002"


# ── T1003.003 NTDS.dit ──────────────────────────────────────────

class TestT1003003NtdsDit:
    def test_skip_non_dc(self, mock_session):
        from modules.credential_access.T1003_003_ntds_dit import NtdsDitCheck

        mock_session.run_powershell.return_value = _cmd("2")  # Workstation role

        mod = NtdsDitCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SKIPPED

    def test_dc_with_vss(self, mock_session):
        from modules.credential_access.T1003_003_ntds_dit import NtdsDitCheck

        mock_session.run_powershell.side_effect = [
            _cmd("5"),       # Primary DC role
            _cmd(""),        # NTDS ACL clean
            _cmd(""),        # No backup copies
            _cmd("2"),       # 2 shadow copies
            _cmd(""),        # DCSync perms clean
            _cmd("No Auditing"),  # DS audit not enabled
        ]
        mock_session.file_exists.return_value = True

        mod = NtdsDitCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Shadow" in d for d in descs)
        assert any("auditing" in d.lower() for d in descs)

    def test_metadata(self):
        from modules.credential_access.T1003_003_ntds_dit import NtdsDitCheck

        mod = NtdsDitCheck()
        assert mod.TECHNIQUE_ID == "T1003.003"
        assert OSType.WIN10 not in mod.SUPPORTED_OS


# ── T1558.003 Kerberoasting ─────────────────────────────────────

class TestT1558003Kerberoasting:
    def test_skip_non_domain(self, mock_session):
        from modules.credential_access.T1558_003_kerberoasting import KerberoastingCheck

        mock_session.run_powershell.return_value = _cmd("False")

        mod = KerberoastingCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SKIPPED

    def test_spn_accounts_found(self, mock_session):
        from modules.credential_access.T1558_003_kerberoasting import KerberoastingCheck

        spn_data = json.dumps([
            {"Name": "svc_sql", "SPN": "MSSQLSvc/db01:1433", "Groups": "", "PwdLastSet": ""},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd("True"),        # Domain-joined
            _cmd(spn_data),      # SPN accounts
            _cmd("No Auditing"), # Kerberos audit
            _cmd("0"),           # No gMSAs
        ]
        mock_session.read_registry.return_value = None  # No encryption type set

        mod = KerberoastingCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Kerberoastable" in d for d in descs)

    def test_metadata(self):
        from modules.credential_access.T1558_003_kerberoasting import KerberoastingCheck

        mod = KerberoastingCheck()
        assert mod.TECHNIQUE_ID == "T1558.003"


# ── T1552.001 Credentials in Files ──────────────────────────────

class TestT1552001CredentialsInFiles:
    def test_unattend_found(self, mock_session):
        from modules.credential_access.T1552_001_credentials_in_files import CredentialsInFilesCheck

        def ps_side_effect(script, **kwargs):
            if "unattend.xml" in script and "Panther\\" in script and "Unattend\\" not in script and "Get-Item" in script:
                return _cmd("C:\\Windows\\Panther\\unattend.xml")
            if "Select-String" in script and "password" in script:
                return _cmd("<Password>P@ssw0rd</Password>")
            if "SYSVOL" in script:
                return _cmd("")
            if "ConsoleHost_history" in script:
                return _cmd("")
            if "cmdkey" in script:
                return _cmd("")
            if "wlan" in script:
                return _cmd("")
            return _cmd("")

        mock_session.run_powershell.side_effect = ps_side_effect
        mock_session.run_cmd.side_effect = [_cmd("")]

        mod = CredentialsInFilesCheck()
        result = mod.check(mock_session)

        assert result.has_findings

    def test_metadata(self):
        from modules.credential_access.T1552_001_credentials_in_files import CredentialsInFilesCheck

        mod = CredentialsInFilesCheck()
        assert mod.TECHNIQUE_ID == "T1552.001"


# ── T1110 Brute Force ───────────────────────────────────────────

class TestT1110BruteForce:
    def test_no_lockout(self, mock_session):
        from modules.credential_access.T1110_brute_force import BruteForceCheck

        net_accounts_output = (
            "Lockout threshold:                  Never\n"
            "Lockout duration (minutes):          30\n"
            "Minimum password length:             7\n"
            "Minimum password age (days):         0\n"
            "Password history length:             5\n"
        )
        mock_session.run_cmd.return_value = _cmd(net_accounts_output)
        mock_session.run_powershell.side_effect = [
            _cmd("PasswordComplexity = 0"),    # Complexity export
            _cmd("No Auditing"),               # Logon audit
            _cmd("Stopped"),                   # Smart card service
        ]
        mock_session.read_registry.side_effect = [
            None,    # LmCompatibilityLevel
        ]

        mod = BruteForceCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("lockout threshold" in d.lower() for d in descs)
        assert any("complexity" in d.lower() for d in descs)
        sevs = [f.severity for f in result.findings]
        assert Severity.CRITICAL in sevs

    def test_metadata(self):
        from modules.credential_access.T1110_brute_force import BruteForceCheck

        mod = BruteForceCheck()
        assert mod.TECHNIQUE_ID == "T1110"
