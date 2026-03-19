"""Tests for Phase 2 — Discovery & Reconnaissance modules.

Uses mocked sessions so tests run on any platform without
requiring a live Windows target.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.models import ModuleStatus, OSType, Severity, Target, ConnectionMethod
from core.session import BaseSession, CommandResult


# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture
def mock_session():
    """Create a mock session with a local target."""
    session = MagicMock(spec=BaseSession)
    session.target = Target(
        host="localhost",
        connection=ConnectionMethod.LOCAL,
        os_type=OSType.WIN11,
    )
    session.os_type = OSType.WIN11
    return session


def _cmd(stdout: str = "", stderr: str = "", success: bool = True) -> CommandResult:
    """Helper to build a CommandResult."""
    return CommandResult(
        stdout=stdout,
        stderr=stderr,
        return_code=0 if success else 1,
        success=success,
    )


# ── T1082 System Information Discovery ───────────────────────────

class TestT1082SystemInfo:
    def test_check_credential_guard_not_running(self, mock_session):
        from modules.discovery.T1082_system_info import SystemInfoDiscovery

        mock_session.run_powershell.side_effect = [
            _cmd("Caption: Windows 11\n"),       # OS info
            _cmd("0"),                            # Credential Guard — not running
            _cmd("True"),                         # Secure Boot
            _cmd("2"),                            # VBS running
            _cmd("On"),                           # BitLocker
            _cmd("5"),                            # Uptime days
            _cmd("22631"),                        # Build number
        ]

        mod = SystemInfoDiscovery()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS
        assert result.has_findings
        descs = [f.description for f in result.findings]
        assert any("Credential Guard" in d for d in descs)

    def test_check_secure_boot_disabled(self, mock_session):
        from modules.discovery.T1082_system_info import SystemInfoDiscovery

        mock_session.run_powershell.side_effect = [
            _cmd("OS info"),                      # OS info
            _cmd("1"),                            # CG running
            _cmd("False"),                        # Secure Boot disabled
            _cmd("2"),                            # VBS running
            _cmd("On"),                           # BitLocker
            _cmd("10"),                           # Uptime
            _cmd("22631"),                        # Build
        ]

        mod = SystemInfoDiscovery()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Secure Boot is disabled" in d for d in descs)

    def test_check_old_build(self, mock_session):
        from modules.discovery.T1082_system_info import SystemInfoDiscovery

        mock_session.run_powershell.side_effect = [
            _cmd("OS info"),
            _cmd("1"),         # CG OK
            _cmd("True"),      # SB OK
            _cmd("2"),         # VBS OK
            _cmd("On"),        # BL OK
            _cmd("10"),        # uptime OK
            _cmd("18362"),     # OLD build
        ]

        mod = SystemInfoDiscovery()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("end-of-life" in d for d in descs)

    def test_module_metadata(self):
        from modules.discovery.T1082_system_info import SystemInfoDiscovery

        mod = SystemInfoDiscovery()
        assert mod.TECHNIQUE_ID == "T1082"
        assert mod.TACTIC == "Discovery"
        assert mod.SAFE_MODE is True
        assert len(mod.get_mitigations()) > 0


# ── T1087 Account Discovery ─────────────────────────────────────

class TestT1087AccountDiscovery:
    def test_builtin_admin_enabled(self, mock_session):
        from modules.discovery.T1087_account_discovery import AccountDiscovery

        users_json = json.dumps([
            {"Name": "Administrator", "Enabled": True, "PasswordRequired": True,
             "PasswordLastSet": None, "LastLogon": None},
            {"Name": "jsmith", "Enabled": True, "PasswordRequired": True,
             "PasswordLastSet": None, "LastLogon": None},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(users_json),                    # Local users
            _cmd(""),                            # Stale accounts
            _cmd("False"),                       # Not domain-joined
        ]
        mock_session.run_cmd.side_effect = [
            _cmd("Lockout threshold: Never\n"),  # Lockout policy
            _cmd("Minimum password length: 0\nMaximum password age: Unlimited\n"),
        ]

        mod = AccountDiscovery()
        result = mod.check(mock_session)

        assert result.status == ModuleStatus.SUCCESS
        descs = [f.description for f in result.findings]
        assert any("Built-in Administrator" in d for d in descs)

    def test_no_password_required(self, mock_session):
        from modules.discovery.T1087_account_discovery import AccountDiscovery

        users_json = json.dumps([
            {"Name": "weakuser", "Enabled": True, "PasswordRequired": False,
             "PasswordLastSet": None, "LastLogon": None},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(users_json),
            _cmd(""),
            _cmd("False"),
        ]
        mock_session.run_cmd.side_effect = [
            _cmd("Lockout threshold: 5\n"),
            _cmd("Minimum password length: 14\n"),
        ]

        mod = AccountDiscovery()
        result = mod.check(mock_session)

        severities = [f.severity for f in result.findings]
        assert Severity.CRITICAL in severities

    def test_module_metadata(self):
        from modules.discovery.T1087_account_discovery import AccountDiscovery

        mod = AccountDiscovery()
        assert mod.TECHNIQUE_ID == "T1087"
        assert mod.TACTIC == "Discovery"


# ── T1069 Permission Groups Discovery ───────────────────────────

class TestT1069PermissionGroups:
    def test_excessive_admin_members(self, mock_session):
        from modules.discovery.T1069_permission_groups import PermissionGroupsDiscovery

        admin_members = json.dumps([
            {"Name": "BUILTIN\\Administrator", "ObjectClass": "User", "PrincipalSource": "Local"},
            {"Name": "DOMAIN\\jsmith", "ObjectClass": "User", "PrincipalSource": "ActiveDirectory"},
            {"Name": "DOMAIN\\user2", "ObjectClass": "User", "PrincipalSource": "ActiveDirectory"},
            {"Name": "DOMAIN\\user3", "ObjectClass": "User", "PrincipalSource": "ActiveDirectory"},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(admin_members),    # Administrators
            _cmd(""),               # Remote Desktop Users
            _cmd(""),               # Remote Management Users
            _cmd(""),               # Backup Operators
            _cmd(""),               # Hyper-V Administrators
            _cmd(""),               # Network Configuration Operators
            _cmd("False"),          # Not domain-joined
        ]

        mod = PermissionGroupsDiscovery()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("excessive" in d.lower() for d in descs)

    def test_module_metadata(self):
        from modules.discovery.T1069_permission_groups import PermissionGroupsDiscovery

        mod = PermissionGroupsDiscovery()
        assert mod.TECHNIQUE_ID == "T1069"


# ── T1046 Network Service Discovery ─────────────────────────────

class TestT1046NetworkService:
    def test_smb1_enabled(self, mock_session):
        from modules.discovery.T1046_network_service import NetworkServiceDiscovery

        mock_session.run_powershell.side_effect = [
            _cmd("[]"),                           # No listeners
            _cmd(json.dumps([                     # Firewall profiles
                {"Name": "Domain", "Enabled": True},
                {"Name": "Private", "Enabled": True},
                {"Name": "Public", "Enabled": True},
            ])),
            _cmd("True"),                         # SMBv1 enabled
            _cmd(""),                             # NetBIOS
        ]
        mock_session.read_registry.return_value = None  # LLMNR not set

        mod = NetworkServiceDiscovery()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("SMBv1" in d for d in descs)
        assert any("LLMNR" in d for d in descs)

    def test_firewall_disabled(self, mock_session):
        from modules.discovery.T1046_network_service import NetworkServiceDiscovery

        mock_session.run_powershell.side_effect = [
            _cmd("[]"),                           # No listeners
            _cmd(json.dumps([
                {"Name": "Public", "Enabled": False},
            ])),
            _cmd("False"),                        # SMBv1 off
            _cmd(""),                             # NetBIOS
        ]
        mock_session.read_registry.return_value = "0"  # LLMNR disabled

        mod = NetworkServiceDiscovery()
        result = mod.check(mock_session)

        severities = [f.severity for f in result.findings]
        assert Severity.CRITICAL in severities


# ── T1083 File and Directory Discovery ───────────────────────────

class TestT1083FileDirectory:
    def test_sensitive_files_found(self, mock_session):
        from modules.discovery.T1083_file_directory import FileDirectoryDiscovery

        # Return file found for unattend.xml, empty for others
        def ps_side_effect(script, **kwargs):
            if "unattend.xml" in script and "Panther" in script and "Unattend\\" not in script:
                return _cmd("C:\\Windows\\Panther\\unattend.xml")
            if "Acl" in script or "PATH" in script:
                return _cmd("")
            return _cmd("")

        mock_session.run_powershell.side_effect = ps_side_effect

        mod = FileDirectoryDiscovery()
        result = mod.check(mock_session)

        assert result.has_findings
        descs = [f.description for f in result.findings]
        assert any("Unattend.xml" in d for d in descs)

    def test_module_metadata(self):
        from modules.discovery.T1083_file_directory import FileDirectoryDiscovery

        mod = FileDirectoryDiscovery()
        assert mod.TECHNIQUE_ID == "T1083"


# ── T1057 Process Discovery ─────────────────────────────────────

class TestT1057ProcessDiscovery:
    def test_defender_not_running(self, mock_session):
        from modules.discovery.T1057_process_discovery import ProcessDiscovery

        mock_session.run_powershell.side_effect = [
            _cmd("svchost\nchrome\nexplorer\n"),   # Process names (no MsMpEng)
            _cmd("[]"),                              # Process list JSON
            _cmd("No Auditing"),                     # Audit policy
        ]
        mock_session.read_registry.return_value = None  # No cmd-line logging

        mod = ProcessDiscovery()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("Key security tools" in d for d in descs)
        assert any("Process creation auditing" in d for d in descs)

    def test_module_metadata(self):
        from modules.discovery.T1057_process_discovery import ProcessDiscovery

        mod = ProcessDiscovery()
        assert mod.TECHNIQUE_ID == "T1057"


# ── T1049 Network Connections Discovery ──────────────────────────

class TestT1049NetworkConnections:
    def test_suspicious_outbound_port(self, mock_session):
        from modules.discovery.T1049_network_connections import NetworkConnectionsDiscovery

        conns = json.dumps([
            {"LocalAddress": "192.168.1.5", "LocalPort": 52000,
             "RemoteAddress": "10.20.30.40", "RemotePort": 4444,
             "OwningProcess": 1234},
        ])
        mock_session.run_powershell.side_effect = [
            _cmd(conns),   # Established connections
            _cmd(conns),   # Suspicious outbound check (same data)
            _cmd(""),      # DNS cache
        ]

        mod = NetworkConnectionsDiscovery()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("4444" in d for d in descs)

    def test_module_metadata(self):
        from modules.discovery.T1049_network_connections import NetworkConnectionsDiscovery

        mod = NetworkConnectionsDiscovery()
        assert mod.TECHNIQUE_ID == "T1049"


# ── T1016 Network Configuration Discovery ───────────────────────

class TestT1016NetworkConfig:
    def test_wpad_enabled(self, mock_session):
        from modules.discovery.T1016_network_config import NetworkConfigDiscovery

        mock_session.run_powershell.side_effect = [
            _cmd(json.dumps([                    # DNS config
                {"InterfaceAlias": "Ethernet", "ServerAddresses": ["10.0.0.1"]},
            ])),
            _cmd(json.dumps([                    # IPv6
                {"Name": "Ethernet"},
            ])),
            _cmd(""),                            # WINS
            _cmd(json.dumps([                    # Network profile
                {"Name": "corp", "NetworkCategory": 2},
            ])),
        ]
        mock_session.read_registry.side_effect = [
            "1",     # WPAD AutoDetect enabled
            None,    # IP forwarding not set
        ]

        mod = NetworkConfigDiscovery()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("WPAD" in d for d in descs)

    def test_module_metadata(self):
        from modules.discovery.T1016_network_config import NetworkConfigDiscovery

        mod = NetworkConfigDiscovery()
        assert mod.TECHNIQUE_ID == "T1016"


# ── T1595 Active Scanning ───────────────────────────────────────

class TestT1595ActiveScanning:
    def test_rdp_without_nla(self, mock_session):
        from modules.reconnaissance.T1595_active_scanning import ActiveScanning

        mock_session.run_powershell.side_effect = [
            _cmd(""),            # ICMP rules
            _cmd("[]"),          # Management ports
            _cmd("winrm_disabled"),  # WinRM not configured
            _cmd(json.dumps([    # Firewall logging
                {"Name": "Domain", "LogBlocked": "False"},
            ])),
        ]
        mock_session.read_registry.side_effect = [
            "0",    # fDenyTSConnections = 0 (RDP enabled)
            "0",    # UserAuthentication = 0 (NLA disabled)
            "0",    # SecurityLayer = 0 (weakest)
        ]

        mod = ActiveScanning()
        result = mod.check(mock_session)

        descs = [f.description for f in result.findings]
        assert any("NLA" in d for d in descs)
        assert any("security layer" in d.lower() for d in descs)

    def test_module_metadata(self):
        from modules.reconnaissance.T1595_active_scanning import ActiveScanning

        mod = ActiveScanning()
        assert mod.TECHNIQUE_ID == "T1595"
        assert mod.TACTIC == "Reconnaissance"


# ── Engine Integration ───────────────────────────────────────────

class TestModuleDiscovery:
    """Test that the engine discovers all Phase 2 modules."""

    def test_engine_discovers_phase2_modules(self):
        from core.engine import ScanEngine

        engine = ScanEngine()
        ids = {m["technique_id"] for m in engine.discovered_modules}

        expected = {
            "T1082", "T1087", "T1069", "T1046", "T1083",
            "T1057", "T1049", "T1016", "T1595",
        }
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_list_modules_count(self):
        from core.engine import ScanEngine

        engine = ScanEngine()
        assert len(engine.discovered_modules) >= 9
