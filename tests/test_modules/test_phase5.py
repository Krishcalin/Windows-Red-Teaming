"""Tests for Phase 5 — Lateral Movement, C2, Collection, Exfiltration & Impact modules."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from core.models import ConnectionMethod, ModuleStatus, OSType, Severity, Target
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


# ═══════════════════════════════════════════════════════════════════
# Lateral Movement
# ═══════════════════════════════════════════════════════════════════

# ── T1021.001 RDP ──────────────────────────────────────────────────

class TestT1021001RDP:
    def test_rdp_enabled_no_nla(self, mock_session):
        from modules.lateral_movement.T1021_001_rdp_config import RDPConfigAudit

        mock_session.run_cmd.side_effect = [
            _cmd("fDenyTSConnections    REG_DWORD    0x0"),   # RDP enabled
            _cmd("UserAuthentication    REG_DWORD    0x0"),    # NLA disabled
            _cmd("PortNumber    REG_DWORD    0xd3d"),          # standard port
        ]
        mock_session.run_powershell.return_value = _cmd("")    # firewall

        mod = RDPConfigAudit()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("NLA" in d for d in descs)
        assert any("RDP is enabled" in d for d in descs)

    def test_non_standard_port(self, mock_session):
        from modules.lateral_movement.T1021_001_rdp_config import RDPConfigAudit

        mock_session.run_cmd.side_effect = [
            _cmd("fDenyTSConnections    REG_DWORD    0x1"),   # RDP disabled
            _cmd("UserAuthentication    REG_DWORD    0x1"),    # NLA enabled
            _cmd("PortNumber    REG_DWORD    0x1f90"),         # port 8080
        ]
        mock_session.run_powershell.return_value = _cmd("")

        mod = RDPConfigAudit()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("non-standard port" in d for d in descs)

    def test_metadata(self):
        from modules.lateral_movement.T1021_001_rdp_config import RDPConfigAudit
        mod = RDPConfigAudit()
        assert mod.TECHNIQUE_ID == "T1021.001"
        assert mod.TACTIC == "Lateral Movement"
        assert mod.SEVERITY == Severity.HIGH


# ── T1021.002 SMB Shares ──────────────────────────────────────────

class TestT1021002SMB:
    def test_smbv1_enabled(self, mock_session):
        from modules.lateral_movement.T1021_002_smb_shares import SMBSharesAudit

        mock_session.run_powershell.side_effect = [
            _cmd(json.dumps([{"Name": "C$", "Path": "C:\\", "Description": "Default share"}])),
            _cmd(json.dumps({"EnableSMB1Protocol": True})),
            _cmd(json.dumps({"RequireSecuritySignature": False, "EnableSecuritySignature": False})),
        ]
        mock_session.run_cmd.return_value = _cmd(
            "Share name   Resource\n"
            "C$           C:\\\n"
            "ADMIN$       C:\\Windows\n"
            "IPC$         \n"
        )

        mod = SMBSharesAudit()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("SMBv1" in d for d in descs)
        assert any("signing" in d.lower() for d in descs)

    def test_metadata(self):
        from modules.lateral_movement.T1021_002_smb_shares import SMBSharesAudit
        mod = SMBSharesAudit()
        assert mod.TECHNIQUE_ID == "T1021.002"
        assert mod.TACTIC == "Lateral Movement"


# ── T1021.006 WinRM ──────────────────────────────────────────────

class TestT1021006WinRM:
    def test_winrm_insecure(self, mock_session):
        from modules.lateral_movement.T1021_006_winrm_config import WinRMConfigAudit

        mock_session.run_powershell.side_effect = [
            _cmd(json.dumps({"Status": "Running", "StartType": 2})),  # running
            _cmd("*"),                                          # TrustedHosts = *
            _cmd("true"),                                       # AllowUnencrypted
        ]
        mock_session.run_cmd.return_value = _cmd(
            "Listener\n"
            "    Address = *\n"
            "    Transport = HTTP\n"
            "    Port = 5985\n"
        )

        mod = WinRMConfigAudit()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("TrustedHosts" in d or "trusted" in d.lower() for d in descs)

    def test_metadata(self):
        from modules.lateral_movement.T1021_006_winrm_config import WinRMConfigAudit
        mod = WinRMConfigAudit()
        assert mod.TECHNIQUE_ID == "T1021.006"


# ── T1550.002 Pass the Hash ──────────────────────────────────────

class TestT1550002PtH:
    def test_credential_guard_off(self, mock_session):
        from modules.lateral_movement.T1550_002_pass_the_hash import PassTheHashCheck

        mock_session.run_powershell.return_value = _cmd("")    # empty = CG not running
        mock_session.run_cmd.side_effect = [
            _cmd("DisableRestrictedAdmin    REG_DWORD    0x0"),  # restricted admin on
            _cmd("UseLogonCredential    REG_DWORD    0x1"),       # WDigest on
            _cmd("NoLMHash    REG_DWORD    0x0"),                 # LM hashes stored
            _cmd("LmCompatibilityLevel    REG_DWORD    0x1"),     # weak NTLM
        ]

        mod = PassTheHashCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Credential Guard" in d for d in descs)
        assert any("WDigest" in d for d in descs)
        assert any("LM hash" in d for d in descs)
        assert any("LmCompatibilityLevel" in d for d in descs)

    def test_secure_system(self, mock_session):
        from modules.lateral_movement.T1550_002_pass_the_hash import PassTheHashCheck

        mock_session.run_powershell.return_value = _cmd("1")   # CG running
        mock_session.run_cmd.side_effect = [
            _cmd("", stderr="not find", success=False),          # no restricted admin
            _cmd("UseLogonCredential    REG_DWORD    0x0"),       # WDigest off
            _cmd("NoLMHash    REG_DWORD    0x1"),                 # LM hashes disabled
            _cmd("LmCompatibilityLevel    REG_DWORD    0x5"),     # NTLMv2 only
        ]

        mod = PassTheHashCheck()
        result = mod.check(mock_session)

        # Secure system should have no critical/high findings
        severe = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(severe) == 0

    def test_metadata(self):
        from modules.lateral_movement.T1550_002_pass_the_hash import PassTheHashCheck
        mod = PassTheHashCheck()
        assert mod.TECHNIQUE_ID == "T1550.002"
        assert mod.SEVERITY == Severity.CRITICAL


# ═══════════════════════════════════════════════════════════════════
# Command and Control
# ═══════════════════════════════════════════════════════════════════

class TestT1071001WebProtocol:
    def test_suspicious_tasks_found(self, mock_session):
        from modules.command_and_control.T1071_001_web_protocols import WebProtocolC2Check

        mock_session.run_cmd.side_effect = [
            _cmd("ProxyEnable    REG_DWORD    0x0"),              # no proxy
            _cmd("", stderr="not find", success=False),           # no proxy server
        ]
        tasks = json.dumps([
            {"TaskName": "SuspiciousUpdate", "State": "Ready"},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(""),       # firewall rules
            _cmd(tasks),    # suspicious tasks
            _cmd(""),       # cert validation
        ]

        mod = WebProtocolC2Check()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("proxy" in d.lower() or "task" in d.lower() for d in descs)

    def test_metadata(self):
        from modules.command_and_control.T1071_001_web_protocols import WebProtocolC2Check
        mod = WebProtocolC2Check()
        assert mod.TECHNIQUE_ID == "T1071.001"
        assert mod.TACTIC == "Command and Control"


# ═══════════════════════════════════════════════════════════════════
# Exfiltration
# ═══════════════════════════════════════════════════════════════════

class TestT1048AltProtocol:
    def test_dns_exfil_vectors(self, mock_session):
        from modules.exfiltration.T1048_exfiltration_alt_protocol import ExfiltrationAltProtocolCheck

        dns_json = json.dumps([
            {"InterfaceAlias": "Ethernet", "ServerAddresses": ["8.8.8.8", "8.8.4.4"]},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(dns_json),     # DNS config
            _cmd(""),           # non-standard ports
            _cmd("True"),       # ICMP reachable
        ]
        mock_session.run_cmd.return_value = _cmd("", stderr="not find", success=False)  # USB

        mod = ExfiltrationAltProtocolCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS

    def test_metadata(self):
        from modules.exfiltration.T1048_exfiltration_alt_protocol import ExfiltrationAltProtocolCheck
        mod = ExfiltrationAltProtocolCheck()
        assert mod.TECHNIQUE_ID == "T1048"
        assert mod.TACTIC == "Exfiltration"


class TestT1041C2Exfil:
    def test_no_dlp(self, mock_session):
        from modules.exfiltration.T1041_c2_channel_exfil import C2ChannelExfilCheck

        tools_json = json.dumps([
            {"Name": "curl", "Source": "C:\\Windows\\System32\\curl.exe"},
            {"Name": "certutil", "Source": "C:\\Windows\\System32\\certutil.exe"},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(""),               # no DLP processes
            _cmd(tools_json),       # transfer tools
            _cmd(json.dumps([       # firewall logging off
                {"Name": "Domain", "LogAllowed": "False", "LogBlocked": "False"},
            ])),
        ]
        mock_session.run_cmd.return_value = _cmd("", stderr="not find", success=False)

        mod = C2ChannelExfilCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("DLP" in d or "transfer tool" in d.lower() or "logging" in d.lower() for d in descs)

    def test_metadata(self):
        from modules.exfiltration.T1041_c2_channel_exfil import C2ChannelExfilCheck
        mod = C2ChannelExfilCheck()
        assert mod.TECHNIQUE_ID == "T1041"


# ═══════════════════════════════════════════════════════════════════
# Collection
# ═══════════════════════════════════════════════════════════════════

class TestT1113ScreenCapture:
    def test_capture_tools_available(self, mock_session):
        from modules.collection.T1113_screen_capture import ScreenCaptureCheck

        mock_session.run_powershell.side_effect = [
            _cmd(json.dumps([{"Name": "SnippingTool.exe"}])),  # snipping tool
            _cmd("1"),                                          # screenshot index
            _cmd("accessible"),                                 # GDI+
            _cmd(""),                                           # no third-party
        ]

        mod = ScreenCaptureCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS

    def test_metadata(self):
        from modules.collection.T1113_screen_capture import ScreenCaptureCheck
        mod = ScreenCaptureCheck()
        assert mod.TECHNIQUE_ID == "T1113"
        assert mod.TACTIC == "Collection"


class TestT1560ArchiveData:
    def test_archive_tools_found(self, mock_session):
        from modules.collection.T1560_archive_data import ArchiveDataCheck

        tools_json = json.dumps([
            {"Name": "Compress-Archive", "Source": ""},
            {"Name": "tar", "Source": "C:\\Windows\\System32\\tar.exe"},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(tools_json),    # archive tools
            _cmd(""),            # temp ACL
        ]
        mock_session.run_cmd.side_effect = [
            _cmd("C:\\Windows\\System32\\makecab.exe"),  # makecab
            _cmd("", stderr="not find", success=False),  # no 7-Zip
            _cmd("", stderr="not find", success=False),  # no WinRAR
        ]

        mod = ArchiveDataCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS

    def test_metadata(self):
        from modules.collection.T1560_archive_data import ArchiveDataCheck
        mod = ArchiveDataCheck()
        assert mod.TECHNIQUE_ID == "T1560"


class TestT1074DataStaged:
    def test_staging_dirs_writable(self, mock_session):
        from modules.collection.T1074_data_staged import DataStagedCheck

        acl_json = json.dumps([
            {"Path": "C:\\Users\\user\\AppData\\Local\\Temp", "Owner": "user"},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(acl_json),     # staging dir ACLs
            _cmd("5"),          # recycle bin items
            _cmd(json.dumps({"Count": 3})),  # large files
            _cmd("True\nTrue"),  # public folders exist
        ]

        mod = DataStagedCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS

    def test_metadata(self):
        from modules.collection.T1074_data_staged import DataStagedCheck
        mod = DataStagedCheck()
        assert mod.TECHNIQUE_ID == "T1074"


# ═══════════════════════════════════════════════════════════════════
# Impact
# ═══════════════════════════════════════════════════════════════════

class TestT1489ServiceStop:
    def test_critical_services_unprotected(self, mock_session):
        from modules.impact.T1489_service_stop import ServiceStopCheck

        svc_json = json.dumps([
            {"Name": "WinDefend", "Status": 4, "StartType": 2},
            {"Name": "EventLog", "Status": 4, "StartType": 2},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(svc_json),             # services
            _cmd("D:(A;;RPWPCR;;;BU)"),  # weak SDDL
            _cmd(json.dumps([
                {"Name": "WinDefend", "StartMode": "Auto"},
            ])),                         # recovery
        ]
        mock_session.run_cmd.return_value = _cmd("", stderr="not find", success=False)  # no PPL

        mod = ServiceStopCheck()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS

    def test_metadata(self):
        from modules.impact.T1489_service_stop import ServiceStopCheck
        mod = ServiceStopCheck()
        assert mod.TECHNIQUE_ID == "T1489"
        assert mod.TACTIC == "Impact"


class TestT1486DataEncrypted:
    def test_no_ransomware_protection(self, mock_session):
        from modules.impact.T1486_data_encrypted import DataEncryptedForImpactCheck

        mock_session.run_powershell.side_effect = [
            _cmd(json.dumps({"Status": 1, "StartType": 3})),   # VSS stopped/manual
            _cmd(json.dumps({"Count": 0})),                     # no shadow copies
            _cmd(json.dumps({"EnableControlledFolderAccess": 0})),  # CFA off
        ]
        mock_session.run_cmd.side_effect = [
            _cmd("", stderr="not find", success=False),  # no backup config
            _cmd("C:\\Windows\\System32\\vssadmin.exe"),  # vssadmin exists
        ]

        mod = DataEncryptedForImpactCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("shadow" in d.lower() or "controlled folder" in d.lower() or "vss" in d.lower()
                    for d in descs)

    def test_metadata(self):
        from modules.impact.T1486_data_encrypted import DataEncryptedForImpactCheck
        mod = DataEncryptedForImpactCheck()
        assert mod.TECHNIQUE_ID == "T1486"
        assert mod.SEVERITY == Severity.CRITICAL


class TestT1529Shutdown:
    def test_shutdown_without_logon(self, mock_session):
        from modules.impact.T1529_system_shutdown import SystemShutdownCheck

        mock_session.run_powershell.return_value = _cmd("SeShutdownPrivilege    Enabled")
        mock_session.run_cmd.side_effect = [
            _cmd("ShutdownWithoutLogon    REG_DWORD    0x1"),   # shutdown without logon
            _cmd("", stderr="not find", success=False),          # no shutdown tracking
        ]

        mod = SystemShutdownCheck()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("shutdown" in d.lower() for d in descs)

    def test_metadata(self):
        from modules.impact.T1529_system_shutdown import SystemShutdownCheck
        mod = SystemShutdownCheck()
        assert mod.TECHNIQUE_ID == "T1529"
        assert mod.TACTIC == "Impact"


# ═══════════════════════════════════════════════════════════════════
# Engine Integration — Phase 5 module discovery
# ═══════════════════════════════════════════════════════════════════

class TestPhase5ModuleDiscovery:
    def test_engine_discovers_phase5_modules(self):
        from core.engine import ScanEngine

        engine = ScanEngine()
        ids = {m["technique_id"] for m in engine.discovered_modules}

        expected = {
            "T1021.001", "T1021.002", "T1021.006", "T1550.002",
            "T1071.001",
            "T1048", "T1041",
            "T1113", "T1560", "T1074",
            "T1489", "T1486", "T1529",
        }
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_total_modules_phases_1_through_5(self):
        from core.engine import ScanEngine

        engine = ScanEngine()
        # Phase 1-4: 29 modules + Phase 5: 13 modules = 42 total
        assert len(engine.discovered_modules) >= 42
