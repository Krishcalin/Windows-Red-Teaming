"""T1016 — System Network Configuration Discovery.

Checks network adapter configuration, DNS settings, routing table,
proxy settings, and network security parameters.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class NetworkConfigDiscovery(BaseModule):
    """T1016 — System Network Configuration Discovery.

    Evaluates network configuration for security weaknesses
    including DNS settings, WPAD, IPv6 exposure, and proxy config.
    """

    TECHNIQUE_ID = "T1016"
    TECHNIQUE_NAME = "System Network Configuration Discovery"
    TACTIC = "Discovery"
    SEVERITY = Severity.LOW
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Check DNS configuration ──────────────────────────────
        self._check_dns_config(session, result)

        # ── Check WPAD (auto-proxy detection) ────────────────────
        self._check_wpad(session, result)

        # ── Check IPv6 status ────────────────────────────────────
        self._check_ipv6(session, result)

        # ── Check IP forwarding ──────────────────────────────────
        self._check_ip_forwarding(session, result)

        # ── Check WINS configuration ─────────────────────────────
        self._check_wins(session, result)

        # ── Check network profile (Public vs Private) ────────────
        self._check_network_profile(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_dns_config(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check DNS server configuration for potential abuse."""
        dns = session.run_powershell(
            "Get-DnsClientServerAddress -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
            "Select-Object InterfaceAlias, ServerAddresses | "
            "ConvertTo-Json -Compress"
        )
        if not dns or not dns.stdout.strip():
            return

        try:
            interfaces = json.loads(dns.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(interfaces, list):
            interfaces = [interfaces]

        for iface in interfaces:
            alias = iface.get("InterfaceAlias", "")
            servers = iface.get("ServerAddresses", [])

            # Check for DNS over non-corporate/non-standard resolvers
            public_dns = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                          "9.9.9.9", "208.67.222.222", "208.67.220.220"}
            using_public = [s for s in servers if s in public_dns]

            if using_public:
                self.add_finding(
                    result,
                    description=(
                        f"Interface '{alias}' uses public DNS resolvers "
                        f"({', '.join(using_public)})"
                    ),
                    severity=Severity.INFO,
                    evidence=f"Interface: {alias}, DNS: {servers}",
                    recommendation=(
                        "In enterprise environments, use internal DNS servers "
                        "for visibility and DNS-based security controls."
                    ),
                )

    def _check_wpad(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if WPAD auto-proxy discovery is enabled."""
        wpad = session.read_registry(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "AutoDetect",
        )
        if wpad is not None and str(wpad) == "1":
            self.add_finding(
                result,
                description="WPAD auto-proxy detection is enabled (proxy poisoning risk)",
                severity=Severity.MEDIUM,
                evidence=f"AutoDetect = {wpad}",
                recommendation=(
                    "Disable WPAD if not needed: Set AutoDetect to 0 in "
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings. "
                    "WPAD is vulnerable to MITM proxy poisoning attacks."
                ),
                cwe="CWE-346",
            )

    def _check_ipv6(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if IPv6 is enabled when not in use."""
        ipv6 = session.run_powershell(
            "Get-NetAdapterBinding -ComponentId ms_tcpip6 "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.Enabled -eq $true } | "
            "Select-Object Name | ConvertTo-Json -Compress"
        )
        if ipv6 and ipv6.stdout.strip():
            try:
                adapters = json.loads(ipv6.stdout)
            except json.JSONDecodeError:
                return

            if not isinstance(adapters, list):
                adapters = [adapters]

            names = [a.get("Name", "") for a in adapters]
            self.add_finding(
                result,
                description=f"IPv6 is enabled on {len(names)} adapter(s)",
                severity=Severity.LOW,
                evidence=f"Adapters with IPv6: {', '.join(names)}",
                recommendation=(
                    "If IPv6 is not used in this environment, consider disabling it "
                    "to reduce the attack surface. IPv6 can be used for MITM attacks "
                    "via SLAAC/DHCPv6 spoofing."
                ),
            )

    def _check_ip_forwarding(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if IP forwarding is enabled (routing between interfaces)."""
        fwd = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "IPEnableRouter",
        )
        if fwd is not None and str(fwd) == "1":
            self.add_finding(
                result,
                description="IP forwarding is enabled — this machine can route between networks",
                severity=Severity.MEDIUM,
                evidence=f"IPEnableRouter = {fwd}",
                recommendation=(
                    "Disable IP forwarding unless this machine is intentionally "
                    "configured as a router. Attackers can abuse forwarding for "
                    "lateral movement pivoting."
                ),
                cwe="CWE-284",
            )

    def _check_wins(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if WINS is configured (legacy name resolution)."""
        wins = session.run_powershell(
            "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "
            "'IPEnabled=true' | Where-Object { "
            "$_.WINSPrimaryServer -ne $null } | "
            "Select-Object Description, WINSPrimaryServer | "
            "ConvertTo-Json -Compress"
        )
        if wins and wins.stdout.strip() and wins.stdout.strip() != "":
            self.add_finding(
                result,
                description="WINS name resolution is configured (legacy, poisoning risk)",
                severity=Severity.MEDIUM,
                evidence=wins.stdout[:300],
                recommendation=(
                    "Remove WINS configuration if not required. WINS is "
                    "a legacy name resolution protocol vulnerable to poisoning."
                ),
                cwe="CWE-346",
            )

    def _check_network_profile(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if network connection profile is set to Public."""
        profiles = session.run_powershell(
            "Get-NetConnectionProfile | "
            "Select-Object Name, NetworkCategory | "
            "ConvertTo-Json -Compress"
        )
        if not profiles or not profiles.stdout.strip():
            return

        try:
            items = json.loads(profiles.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(items, list):
            items = [items]

        for item in items:
            name = item.get("Name", "")
            # NetworkCategory: 0=Public, 1=Private, 2=DomainAuthenticated
            cat = item.get("NetworkCategory", -1)
            if cat == 1:  # Private
                self.add_finding(
                    result,
                    description=f"Network '{name}' is set to Private profile",
                    severity=Severity.LOW,
                    evidence=f"Network: {name}, Category: Private",
                    recommendation=(
                        "In corporate environments, domain-authenticated networks "
                        "should use the Domain profile. Manually set networks may "
                        "have relaxed firewall rules on Private."
                    ),
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary network configuration discovery."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("ipconfig /all", "Full IP configuration"),
            ("route print", "Routing table"),
            ("ipconfig /displaydns", "DNS resolver cache"),
            ("netsh wlan show profiles 2>nul", "Wi-Fi saved profiles"),
        ]

        for cmd, desc in commands:
            out = session.run_cmd(cmd, timeout=10)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Monitor for network configuration enumeration",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1028 — Operating System Configuration: Disable WPAD, WINS, and IPv6 if not needed",
            "M1030 — Network Segmentation: Ensure proper network profile and firewall rules",
            "M1031 — Network Intrusion Prevention: Use internal DNS for visibility",
            "M1042 — Disable or Remove Feature or Program: Remove legacy network protocols",
        ]
