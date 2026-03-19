"""Tests for Phase 4 — Execution, Persistence & Defense Evasion modules."""

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
        host="10.0.0.5", connection=ConnectionMethod.LOCAL, os_type=OSType.WIN11,
    )
    session.os_type = OSType.WIN11
    return session


def _cmd(stdout="", stderr="", success=True):
    return CommandResult(stdout=stdout, stderr=stderr,
                         return_code=0 if success else 1, success=success)


# ── T1059.001 PowerShell ────────────────────────────────────────

class TestT1059001PowerShell:
    def test_weak_execution_policy(self, mock_session):
        from modules.execution.T1059_001_powershell import PowerShellPolicyCheck

        mock_session.run_powershell.side_effect = [
            _cmd("Scope ExecutionPolicy\n----- ---------------\nMachinePolicy Bypass"),
            _cmd("FullLanguage"),       # CLM
            _cmd("Enabled"),            # PS v2
        ]
        mock_session.read_registry.side_effect = [
            "Bypass",    # Machine execution policy
            None,        # SBL not set
            None,        # SBL invocation
            None,        # Transcription
            None,        # Module logging
            None,        # AMSI
        ]

        mod = PowerShellPolicyCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Bypass" in d for d in descs)
        assert any("Script Block Logging" in d for d in descs)
        assert any("v2" in d for d in descs)

    def test_metadata(self):
        from modules.execution.T1059_001_powershell import PowerShellPolicyCheck
        mod = PowerShellPolicyCheck()
        assert mod.TECHNIQUE_ID == "T1059.001"
        assert mod.TACTIC == "Execution"


# ── T1059.003 Command Shell ─────────────────────────────────────

class TestT1059003CommandShell:
    def test_no_cmd_audit(self, mock_session):
        from modules.execution.T1059_003_command_shell import CommandShellCheck

        mock_session.read_registry.side_effect = [
            None,    # DisableCMD
            None,    # ProcessCreationIncludeCmdLine
            None,    # WSH Enabled
        ]
        mock_session.run_powershell.side_effect = [
            _cmd("No Auditing"),    # Process creation audit
            _cmd("Stopped"),        # AppLocker service
        ]

        mod = CommandShellCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Process creation auditing" in d for d in descs)
        assert any("AppLocker" in d for d in descs)

    def test_metadata(self):
        from modules.execution.T1059_003_command_shell import CommandShellCheck
        mod = CommandShellCheck()
        assert mod.TECHNIQUE_ID == "T1059.003"


# ── T1047 WMI ───────────────────────────────────────────────────

class TestT1047Wmi:
    def test_wmi_subscriptions_found(self, mock_session):
        from modules.execution.T1047_wmi import WmiAccessCheck

        sub_json = json.dumps([{"__CLASS": "CommandLineEventConsumer", "Name": "evil"}])
        mock_session.run_powershell.side_effect = [
            _cmd("Running"),     # WMI service
            _cmd(""),            # Firewall rules (none)
            _cmd(sub_json),      # Event subscriptions found
            _cmd(""),            # Bindings
            _cmd(json.dumps({"Enabled": True, "MaxSize": 1048576, "Records": 10})),  # WMI log
            _cmd("No Auditing"), # Namespace audit
        ]

        mod = WmiAccessCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("subscription" in d.lower() for d in descs)

    def test_metadata(self):
        from modules.execution.T1047_wmi import WmiAccessCheck
        mod = WmiAccessCheck()
        assert mod.TECHNIQUE_ID == "T1047"


# ── T1053.005 Scheduled Task ────────────────────────────────────

class TestT1053005ScheduledTask:
    def test_suspicious_task(self, mock_session):
        from modules.persistence.T1053_005_scheduled_task import ScheduledTaskCheck

        tasks = json.dumps([{
            "TaskName": "Updater",
            "TaskPath": "\\",
            "Author": "unknown",
            "Action": "powershell.exe -enc base64stuff",
            "RunAs": "SYSTEM",
        }])
        mock_session.run_powershell.side_effect = [
            _cmd(tasks),           # Task list
            _cmd(""),              # Folder permissions (clean)
            _cmd("No Auditing"),   # Task creation audit
        ]
        mock_session.run_cmd.return_value = _cmd("Access is denied.", success=False)

        mod = ScheduledTaskCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Suspicious SYSTEM" in d for d in descs)

    def test_metadata(self):
        from modules.persistence.T1053_005_scheduled_task import ScheduledTaskCheck
        mod = ScheduledTaskCheck()
        assert mod.TECHNIQUE_ID == "T1053.005"
        assert mod.TACTIC == "Persistence"


# ── T1547.001 Registry Run Keys ─────────────────────────────────

class TestT1547001RegistryRunKeys:
    def test_winlogon_tampered(self, mock_session):
        from modules.persistence.T1547_001_registry_run_keys import RegistryRunKeysCheck

        def reg_side_effect(hive, key, value):
            if "Winlogon" in key and value == "Shell":
                return "explorer.exe, C:\\evil.exe"
            if "Winlogon" in key and value == "Userinit":
                return r"C:\Windows\system32\userinit.exe,"
            return None

        mock_session.read_registry.side_effect = reg_side_effect
        mock_session.run_powershell.side_effect = [
            _cmd(""),    # HKLM Run entries
            _cmd(""),    # HKLM RunOnce
            _cmd(""),    # HKLM Run WOW64
            _cmd(""),    # HKCU Run
            _cmd(""),    # HKCU RunOnce
            _cmd(""),    # Run key ACL
            _cmd(""),    # Startup folder
            _cmd("No Auditing"),  # Registry audit
        ]

        mod = RegistryRunKeysCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Winlogon Shell" in d for d in descs)
        sevs = [f.severity for f in result.findings]
        assert Severity.CRITICAL in sevs

    def test_metadata(self):
        from modules.persistence.T1547_001_registry_run_keys import RegistryRunKeysCheck
        mod = RegistryRunKeysCheck()
        assert mod.TECHNIQUE_ID == "T1547.001"


# ── T1546.001 File Association ───────────────────────────────────

class TestT1546001FileAssociation:
    def test_tampered_association(self, mock_session):
        from modules.persistence.T1546_001_file_association import FileAssociationCheck

        def cmd_side_effect(cmd, **kwargs):
            if "assoc .bat" in cmd:
                return _cmd(".bat=evilhandler")
            return _cmd("")

        mock_session.run_cmd.side_effect = cmd_side_effect
        mock_session.run_powershell.side_effect = [
            _cmd(""),    # ProgID handlers
            _cmd(""),    # ProgID handlers
            _cmd(""),    # ProgID handlers
            _cmd(""),    # ProgID handlers
            _cmd(""),    # User choice overrides
        ]

        mod = FileAssociationCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any(".bat" in d and "changed" in d for d in descs)

    def test_metadata(self):
        from modules.persistence.T1546_001_file_association import FileAssociationCheck
        mod = FileAssociationCheck()
        assert mod.TECHNIQUE_ID == "T1546.001"


# ── T1562.001 Disable Security Tools ────────────────────────────

class TestT1562001DisableTools:
    def test_defender_disabled(self, mock_session):
        from modules.defense_evasion.T1562_001_disable_security_tools import DisableSecurityToolsCheck

        mock_session.run_powershell.side_effect = [
            _cmd("Stopped"),     # WinDefend service
            _cmd("False"),       # Tamper protection
            _cmd(json.dumps({"Paths": ["C:\\"], "Extensions": [".exe"], "Processes": []})),
            _cmd(json.dumps({"RealTimeEnabled": False, "BehaviorMonitor": True,
                             "IoavProtection": True, "NISEnabled": True, "AntispywareEnabled": True})),
            _cmd(""),            # Firewall — all enabled
            _cmd("0"),           # ASR count
        ]
        mock_session.read_registry.return_value = "1"  # DisableAntiSpyware

        mod = DisableSecurityToolsCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("WinDefend" in d for d in descs)
        assert any("DisableAntiSpyware" in d for d in descs)
        assert any("Real-time" in d for d in descs)

    def test_metadata(self):
        from modules.defense_evasion.T1562_001_disable_security_tools import DisableSecurityToolsCheck
        mod = DisableSecurityToolsCheck()
        assert mod.TECHNIQUE_ID == "T1562.001"
        assert mod.SEVERITY == Severity.CRITICAL


# ── T1562.002 Disable Event Logging ─────────────────────────────

class TestT1562002DisableLogging:
    def test_security_log_disabled(self, mock_session):
        from modules.defense_evasion.T1562_002_disable_event_logging import DisableEventLoggingCheck

        mock_session.run_powershell.side_effect = [
            _cmd("Running"),     # EventLog service
            # Log sizes — Security log disabled
            _cmd(json.dumps({"Enabled": False, "MaxSize": 20971520, "LogMode": "Circular"})),
            _cmd(json.dumps({"Enabled": True, "MaxSize": 20971520, "LogMode": "Circular"})),
            _cmd(json.dumps({"Enabled": True, "MaxSize": 20971520, "LogMode": "Circular"})),
            _cmd("missing"),     # Sysmon
            _cmd("missing"),     # PS Operational
            _cmd("missing"),     # Windows PS
            # Audit policy
            _cmd("  Logon    No Auditing\n  Account Logon   No Auditing\n"),
            # Sysmon check
            _cmd(""),
            # Forwarding checks
            _cmd(""),            # WEF
            _cmd(""),            # Winlogbeat
            _cmd(""),            # NXLog
        ]

        mod = DisableEventLoggingCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("disabled" in d.lower() and "Security" in d for d in descs)

    def test_metadata(self):
        from modules.defense_evasion.T1562_002_disable_event_logging import DisableEventLoggingCheck
        mod = DisableEventLoggingCheck()
        assert mod.TECHNIQUE_ID == "T1562.002"


# ── T1036 Masquerading ──────────────────────────────────────────

class TestT1036Masquerading:
    def test_masquerading_detected(self, mock_session):
        from modules.defense_evasion.T1036_masquerading import MasqueradingCheck

        def ps_side_effect(script, **kwargs):
            if "svchost" in script and "Get-Process" in script:
                return _cmd(json.dumps([
                    {"Name": "svchost", "Id": 1234, "Path": "C:\\Users\\evil\\svchost.exe"},
                ]))
            if "TEMP" in script:
                return _cmd("")
            return _cmd("")

        mock_session.run_powershell.side_effect = ps_side_effect
        mock_session.read_registry.return_value = "1"  # HideFileExt

        mod = MasqueradingCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("masquerading" in d.lower() and "svchost" in d for d in descs)

    def test_metadata(self):
        from modules.defense_evasion.T1036_masquerading import MasqueradingCheck
        mod = MasqueradingCheck()
        assert mod.TECHNIQUE_ID == "T1036"


# ── T1070.001 Clear Event Logs ──────────────────────────────────

class TestT1070001ClearLogs:
    def test_recent_clear_detected(self, mock_session):
        from modules.defense_evasion.T1070_001_clear_event_logs import ClearEventLogsCheck

        clear_json = json.dumps([{"TimeCreated": "2026-03-19", "Message": "Log cleared by admin"}])
        mock_session.run_powershell.side_effect = [
            _cmd("No Auditing"),     # Audit policy change
            _cmd(clear_json),        # Security log clears (1102)
            _cmd(""),                # System log clears (104)
            _cmd(""),                # Log file permissions
            _cmd("none"),            # Forwarding
            _cmd("True"),            # wevtutil exists
        ]

        mod = ClearEventLogsCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("recently cleared" in d.lower() for d in descs)
        assert any("forwarding" in d.lower() for d in descs)

    def test_metadata(self):
        from modules.defense_evasion.T1070_001_clear_event_logs import ClearEventLogsCheck
        mod = ClearEventLogsCheck()
        assert mod.TECHNIQUE_ID == "T1070.001"


# ── Engine Integration ───────────────────────────────────────────

class TestPhase4ModuleDiscovery:
    def test_engine_discovers_phase4_modules(self):
        from core.engine import ScanEngine

        engine = ScanEngine()
        ids = {m["technique_id"] for m in engine.discovered_modules}

        expected = {
            "T1059.001", "T1059.003", "T1047",
            "T1053.005", "T1547.001", "T1546.001",
            "T1562.001", "T1562.002", "T1036", "T1070.001",
        }
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_total_modules_phases_1_through_4(self):
        from core.engine import ScanEngine

        engine = ScanEngine()
        assert len(engine.discovered_modules) >= 29  # 9 + 10 + 10
