"""T1046 — Network Service Discovery.

Checks for exposed network services, open ports, and firewall
configuration weaknesses that could be leveraged for lateral
movement or initial access.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# High-risk services that are commonly targeted
_RISKY_SERVICES = {
    "21": ("FTP", Severity.HIGH),
    "23": ("Telnet", Severity.CRITICAL),
    "25": ("SMTP", Severity.MEDIUM),
    "135": ("RPC/WMI", Severity.MEDIUM),
    "139": ("NetBIOS", Severity.HIGH),
    "445": ("SMB", Severity.MEDIUM),
    "1433": ("MSSQL", Severity.HIGH),
    "3306": ("MySQL", Severity.HIGH),
    "3389": ("RDP", Severity.MEDIUM),
    "5985": ("WinRM-HTTP", Severity.MEDIUM),
    "5986": ("WinRM-HTTPS", Severity.LOW),
}


class NetworkServiceDiscovery(BaseModule):
    """T1046 — Network Service Discovery.

    Discovers listening network services and evaluates firewall
    configuration for security weaknesses.
    """

    TECHNIQUE_ID = "T1046"
    TECHNIQUE_NAME = "Network Service Discovery"
    TACTIC = "Discovery"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Check listening TCP services ─────────────────────────
        self._check_listening_services(session, result)

        # ── Check Windows Firewall status ────────────────────────
        self._check_firewall_status(session, result)

        # ── Check SMB v1 ─────────────────────────────────────────
        self._check_smb_v1(session, result)

        # ── Check LLMNR / NetBIOS over TCP ───────────────────────
        self._check_llmnr(session, result)
        self._check_netbios(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_listening_services(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Identify listening TCP services and flag risky ones."""
        listeners = session.run_powershell(
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort, OwningProcess | "
            "ConvertTo-Json -Compress"
        )
        if not listeners or not listeners.stdout.strip():
            return

        try:
            conns = json.loads(listeners.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(conns, list):
            conns = [conns]

        # Deduplicate by port
        seen_ports: set[str] = set()
        for conn in conns:
            port = str(conn.get("LocalPort", ""))
            addr = conn.get("LocalAddress", "")
            if port in seen_ports:
                continue
            seen_ports.add(port)

            # Only flag services listening on all interfaces or external
            if addr in ("127.0.0.1", "::1"):
                continue

            if port in _RISKY_SERVICES:
                svc_name, sev = _RISKY_SERVICES[port]
                self.add_finding(
                    result,
                    description=(
                        f"{svc_name} service listening on port {port} "
                        f"(bound to {addr})"
                    ),
                    severity=sev,
                    evidence=f"LocalAddress={addr}, LocalPort={port}, PID={conn.get('OwningProcess', '?')}",
                    recommendation=(
                        f"Disable {svc_name} if not required, or restrict "
                        f"access via Windows Firewall rules"
                    ),
                    cwe="CWE-200",
                )

    def _check_firewall_status(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Windows Firewall is enabled on all profiles."""
        fw = session.run_powershell(
            "Get-NetFirewallProfile | "
            "Select-Object Name, Enabled | "
            "ConvertTo-Json -Compress"
        )
        if not fw or not fw.stdout.strip():
            return

        try:
            profiles = json.loads(fw.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(profiles, list):
            profiles = [profiles]

        for profile in profiles:
            name = profile.get("Name", "")
            enabled = profile.get("Enabled", True)
            if not enabled:
                self.add_finding(
                    result,
                    description=f"Windows Firewall is disabled on the '{name}' profile",
                    severity=Severity.CRITICAL,
                    evidence=f"Profile: {name}, Enabled: {enabled}",
                    recommendation=(
                        f"Enable Windows Firewall on the {name} profile. "
                        f"CIS Benchmark 9.1.1 / 9.2.1 / 9.3.1"
                    ),
                    cwe="CWE-284",
                )

    def _check_smb_v1(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if SMBv1 protocol is enabled."""
        smb1 = session.run_powershell(
            "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
        )
        if smb1 and smb1.stdout.strip().lower() == "true":
            self.add_finding(
                result,
                description="SMBv1 protocol is enabled (vulnerable to EternalBlue/WannaCry)",
                severity=Severity.CRITICAL,
                evidence="EnableSMB1Protocol = True",
                recommendation=(
                    "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false. "
                    "CIS Benchmark 18.4.8"
                ),
                cwe="CWE-327",
            )

    def _check_llmnr(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if LLMNR is enabled (poisoning risk)."""
        llmnr = session.read_registry(
            "HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "EnableMulticast",
        )
        if llmnr is None or str(llmnr) != "0":
            self.add_finding(
                result,
                description="LLMNR is enabled (susceptible to name resolution poisoning)",
                severity=Severity.HIGH,
                evidence=f"EnableMulticast = {llmnr}",
                recommendation=(
                    "Disable LLMNR via Group Policy: Computer Configuration > "
                    "Administrative Templates > Network > DNS Client > "
                    "Turn off multicast name resolution = Enabled"
                ),
                cwe="CWE-346",
            )

    def _check_netbios(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if NetBIOS over TCP/IP is enabled."""
        nb = session.run_powershell(
            "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "
            "'IPEnabled=true' | Select-Object Description, TcpipNetbiosOptions | "
            "ConvertTo-Json -Compress"
        )
        if not nb or not nb.stdout.strip():
            return

        try:
            adapters = json.loads(nb.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(adapters, list):
            adapters = [adapters]

        for adapter in adapters:
            opt = adapter.get("TcpipNetbiosOptions")
            desc = adapter.get("Description", "Unknown adapter")
            # 0=Default(DHCP), 1=Enabled, 2=Disabled
            if opt is not None and opt != 2:
                self.add_finding(
                    result,
                    description=f"NetBIOS over TCP/IP is enabled on '{desc}'",
                    severity=Severity.MEDIUM,
                    evidence=f"TcpipNetbiosOptions = {opt} (0=default, 1=enabled, 2=disabled)",
                    recommendation=(
                        "Disable NetBIOS over TCP/IP on all network adapters. "
                        "Prevents NBT-NS poisoning attacks (Responder)."
                    ),
                    cwe="CWE-346",
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary network service discovery."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("netstat -ano | findstr LISTENING", "Listening ports enumeration"),
            ("net share", "Network share enumeration"),
            ("arp -a", "ARP table enumeration"),
        ]

        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Monitor for network reconnaissance activity",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1031 — Network Intrusion Prevention: Enable Windows Firewall on all profiles",
            "M1030 — Network Segmentation: Restrict lateral movement with host-based firewall rules",
            "M1042 — Disable or Remove Feature or Program: Disable SMBv1, LLMNR, and NetBIOS",
            "M1035 — Limit Access to Resource Over Network: Minimize exposed network services",
        ]
