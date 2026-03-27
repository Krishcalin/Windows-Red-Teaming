"""T1021.001 — Remote Desktop Protocol.

Audits RDP configuration to identify insecure settings that could
allow adversaries to use RDP for lateral movement, including
disabled NLA, non-standard ports, and permissive firewall rules.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class RDPConfigAudit(BaseModule):
    """T1021.001 — Remote Desktop Protocol.

    Checks whether RDP is securely configured, including Network
    Level Authentication, port settings, and firewall rules.
    """

    TECHNIQUE_ID = "T1021.001"
    TECHNIQUE_NAME = "Remote Desktop Protocol"
    TACTIC = "Lateral Movement"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Check if RDP is enabled ───────────────────────────────
        rdp_enabled = session.run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
            "/v fDenyTSConnections"
        )
        rdp_is_enabled = False
        if rdp_enabled and rdp_enabled.stdout:
            self._log.info("rdp_status_checked", output=rdp_enabled.stdout[:200])
            if "0x0" in rdp_enabled.stdout:
                rdp_is_enabled = True

        # ── Check NLA (Network Level Authentication) ──────────────
        nla = session.run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'
            '\\WinStations\\RDP-Tcp" /v UserAuthentication'
        )
        nla_enabled = False
        if nla and nla.stdout:
            if "0x1" in nla.stdout:
                nla_enabled = True

        if rdp_is_enabled and not nla_enabled:
            self.add_finding(
                result,
                description="RDP is enabled without Network Level Authentication (NLA)",
                severity=Severity.HIGH,
                evidence=f"fDenyTSConnections=0x0, UserAuthentication={'0x1' if nla_enabled else '0x0 or missing'}",
                recommendation=(
                    "Enable NLA: Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
                    "Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication to 1"
                ),
                cwe="CWE-287",
            )

        # ── Check RDP port ────────────────────────────────────────
        port = session.run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'
            '\\WinStations\\RDP-Tcp" /v PortNumber'
        )
        if port and port.stdout:
            # Registry value is in hex, e.g. 0xd3d = 3389
            for token in port.stdout.split():
                if token.startswith("0x"):
                    try:
                        port_num = int(token, 16)
                        if port_num != 3389:
                            self.add_finding(
                                result,
                                description=f"RDP is running on non-standard port {port_num}",
                                severity=Severity.LOW,
                                evidence=f"PortNumber = {token} ({port_num})",
                                recommendation=(
                                    "Non-standard ports provide minimal security benefit. "
                                    "Consider restricting RDP access via firewall rules and VPN instead."
                                ),
                            )
                    except ValueError:
                        pass

        # ── Check firewall rules for RDP ──────────────────────────
        fw = session.run_powershell(
            "Get-NetFirewallRule -DisplayName '*Remote Desktop*' "
            "| Select-Object Enabled,Direction,Action | ConvertTo-Json"
        )
        if fw and fw.stdout.strip():
            fw_output = fw.stdout.strip()
            if '"Enabled":  true' in fw_output.lower() or '"Enabled": true' in fw_output.lower():
                if '"Action":  2' in fw_output or '"Action": "Allow"' in fw_output or '"Action":  "Allow"' in fw_output:
                    self.add_finding(
                        result,
                        description="Firewall allows inbound RDP connections",
                        severity=Severity.MEDIUM,
                        evidence=fw_output[:500],
                        recommendation=(
                            "Restrict RDP firewall rules to specific source IP ranges. "
                            "Use a VPN or jump box for remote administration."
                        ),
                        cwe="CWE-284",
                    )

        if rdp_is_enabled:
            self.add_finding(
                result,
                description="RDP is enabled on this system",
                severity=Severity.MEDIUM,
                evidence="fDenyTSConnections = 0x0",
                recommendation=(
                    "Disable RDP if not required. If needed, enforce NLA, "
                    "restrict access via firewall rules, and use a VPN."
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary RDP reconnaissance commands."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        # ── List active RDP sessions ──────────────────────────────
        sessions = session.run_cmd("qwinsta")
        if sessions and sessions.stdout:
            self.add_finding(
                result,
                description="Simulated: Enumerated active RDP sessions via qwinsta",
                severity=Severity.INFO,
                evidence=sessions.stdout[:500],
                recommendation="Monitor for unauthorized use of qwinsta/query session commands",
            )

        # ── Check port 3389 listeners ─────────────────────────────
        netstat = session.run_cmd("netstat -an | findstr :3389")
        if netstat and netstat.stdout:
            self.add_finding(
                result,
                description="Simulated: Found RDP port 3389 listeners via netstat",
                severity=Severity.INFO,
                evidence=netstat.stdout[:500],
                recommendation="Monitor for network reconnaissance targeting RDP ports",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass  # Read-only checks — nothing to revert

    def get_mitigations(self) -> list[str]:
        return [
            "M1042 — Disable or Remove Feature: Disable RDP if not required",
            "M1035 — Limit Access to Resource Over Network: Restrict RDP to specific IP ranges via firewall",
            "M1032 — Multi-factor Authentication: Require MFA for RDP sessions via NLA + smart card or third-party",
            "M1030 — Network Segmentation: Isolate systems that require RDP behind a VPN or jump server",
            "M1026 — Privileged Account Management: Limit which accounts can use RDP",
        ]
