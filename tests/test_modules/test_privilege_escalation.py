"""Tests for Phase 3 — Privilege Escalation modules."""

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
        connection=ConnectionMethod.LOCAL,
        os_type=OSType.WIN11,
    )
    session.os_type = OSType.WIN11
    return session


def _cmd(stdout="", stderr="", success=True):
    return CommandResult(stdout=stdout, stderr=stderr,
                         return_code=0 if success else 1, success=success)


# ── T1548.002 UAC Bypass ────────────────────────────────────────

class TestT1548002UacBypass:
    def test_uac_disabled(self, mock_session):
        from modules.privilege_escalation.T1548_002_uac_bypass import UacBypassCheck

        mock_session.read_registry.side_effect = [
            "0",     # EnableLUA = 0 (UAC disabled)
            "0",     # ConsentPromptBehaviorAdmin
            "0",     # ConsentPromptBehaviorUser
            None,    # FilterAdministratorToken
            "0",     # PromptOnSecureDesktop
            "0",     # EnableInstallerDetection
            "1",     # EnableVirtualization
        ]
        mock_session.run_powershell.return_value = _cmd("")

        mod = UacBypassCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("UAC" in d and "disabled" in d for d in descs)
        sevs = [f.severity for f in result.findings]
        assert Severity.CRITICAL in sevs

    def test_weak_consent_prompt(self, mock_session):
        from modules.privilege_escalation.T1548_002_uac_bypass import UacBypassCheck

        mock_session.read_registry.side_effect = [
            "1",     # EnableLUA = 1 (UAC on)
            "5",     # ConsentPromptBehaviorAdmin = 5 (consent for non-Win binaries)
            "1",     # ConsentPromptBehaviorUser
            "1",     # FilterAdministratorToken
            "1",     # PromptOnSecureDesktop
            "1",     # EnableInstallerDetection
            "1",     # EnableVirtualization
        ]
        mock_session.run_powershell.return_value = _cmd("")

        mod = UacBypassCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("consent only" in d for d in descs)

    def test_metadata(self):
        from modules.privilege_escalation.T1548_002_uac_bypass import UacBypassCheck

        mod = UacBypassCheck()
        assert mod.TECHNIQUE_ID == "T1548.002"
        assert mod.TACTIC == "Privilege Escalation"


# ── T1134 Access Token Manipulation ─────────────────────────────

class TestT1134AccessToken:
    def test_dangerous_privileges(self, mock_session):
        from modules.privilege_escalation.T1134_access_token import AccessTokenManipulation

        mock_session.run_cmd.return_value = _cmd(
            "PRIVILEGES INFORMATION\n"
            "SeDebugPrivilege              Enabled\n"
            "SeImpersonatePrivilege        Disabled\n"
        )
        mock_session.run_powershell.side_effect = [
            _cmd(""),                           # secedit export (empty)
            _cmd("Mandatory Label\\High Mandatory Level"),  # integrity
            _cmd("No Auditing"),                # privilege audit
        ]

        mod = AccessTokenManipulation()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("SeDebugPrivilege" in d for d in descs)
        assert any("SeImpersonatePrivilege" in d for d in descs)

    def test_metadata(self):
        from modules.privilege_escalation.T1134_access_token import AccessTokenManipulation

        mod = AccessTokenManipulation()
        assert mod.TECHNIQUE_ID == "T1134"


# ── T1574.001 DLL Search Order Hijacking ────────────────────────

class TestT1574001DllSearchOrder:
    def test_safe_dll_disabled(self, mock_session):
        from modules.privilege_escalation.T1574_001_dll_search_order import DllSearchOrderHijacking

        mock_session.read_registry.side_effect = [
            "0",     # SafeDllSearchMode disabled
            None,    # CWDIllegalInDllSearch not set
        ]
        mock_session.run_powershell.side_effect = [
            _cmd(""),     # PATH writable check — clean
            _cmd("35"),   # KnownDLLs count
            _cmd(""),     # Service binary perms — clean
        ]

        mod = DllSearchOrderHijacking()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("SafeDllSearchMode" in d for d in descs)
        assert any("CWDIllegalInDllSearch" in d for d in descs)

    def test_metadata(self):
        from modules.privilege_escalation.T1574_001_dll_search_order import DllSearchOrderHijacking

        mod = DllSearchOrderHijacking()
        assert mod.TECHNIQUE_ID == "T1574.001"


# ── T1574.002 DLL Side-Loading ──────────────────────────────────

class TestT1574002DllSideLoading:
    def test_unquoted_service_path(self, mock_session):
        from modules.privilege_escalation.T1574_002_dll_side_loading import DllSideLoading

        svc_json = json.dumps([{
            "Name": "VulnSvc",
            "PathName": "C:\\Program Files\\Vuln App\\service.exe",
            "StartMode": "Auto",
            "State": "Running",
        }])
        mock_session.run_powershell.side_effect = [
            _cmd(""),          # Writable program dirs — clean
            _cmd(svc_json),    # Unquoted service path
            _cmd("0"),         # Code integrity status
            _cmd(""),          # .local files — clean
        ]
        mock_session.read_registry.side_effect = [
            "",      # AppInit_DLLs (empty)
            "0",     # LoadAppInit_DLLs disabled
        ]

        mod = DllSideLoading()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Unquoted" in d for d in descs)

    def test_appinit_enabled(self, mock_session):
        from modules.privilege_escalation.T1574_002_dll_side_loading import DllSideLoading

        mock_session.run_powershell.side_effect = [
            _cmd(""),     # Writable dirs — clean
            _cmd(""),     # Unquoted — clean
            _cmd("0"),    # Code integrity
            _cmd(""),     # .local — clean
        ]
        mock_session.read_registry.side_effect = [
            "C:\\evil.dll",  # AppInit_DLLs has entry
            "1",             # LoadAppInit_DLLs enabled
        ]

        mod = DllSideLoading()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("AppInit_DLLs" in d and "enabled" in d for d in descs)

    def test_metadata(self):
        from modules.privilege_escalation.T1574_002_dll_side_loading import DllSideLoading

        mod = DllSideLoading()
        assert mod.TECHNIQUE_ID == "T1574.002"


# ── Engine Integration ───────────────────────────────────────────

class TestPhase3ModuleDiscovery:
    def test_engine_discovers_phase3_modules(self):
        from core.engine import ScanEngine

        engine = ScanEngine()
        ids = {m["technique_id"] for m in engine.discovered_modules}

        expected = {
            "T1003.001", "T1003.002", "T1003.003", "T1558.003",
            "T1552.001", "T1110", "T1548.002", "T1134",
            "T1574.001", "T1574.002",
        }
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_total_modules_phase1_2_3(self):
        from core.engine import ScanEngine

        engine = ScanEngine()
        assert len(engine.discovered_modules) >= 19  # 9 Phase 2 + 10 Phase 3
