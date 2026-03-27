"""T1048 — Exfiltration Over Alternative Protocol.

Checks for exfiltration vectors using alternative protocols
such as DNS, ICMP, and non-standard ports, as well as
removable storage device policies.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class ExfiltrationAltProtocolCheck(BaseModule):
    """T1048 — Exfiltration over alternative protocol audit.

    Evaluates DNS configuration, outbound firewall rules for
    non-standard ports, ICMP reachability, and USB/removable
    device policies.
    """

    TECHNIQUE_ID = "T1048"
    TECHNIQUE_NAME = "Exfiltration Over Alternative Protocol"
    TACTIC = "Exfiltration"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_dns_config(session, result)
        self._check_nonstandard_outbound_ports(session, result)
        self._check_icmp_outbound(session, result)
        self._check_usb_policy(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_dns_config(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check DNS client configuration for external DNS servers."""
        dns = session.run_powershell(
            "Get-DnsClientServerAddress | "
            "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json"
        )
        if not dns or not dns.stdout.strip():
            return

        try:
            dns_config = json.loads(dns.stdout)
            if isinstance(dns_config, dict):
                dns_config = [dns_config]
        except json.JSONDecodeError:
            return

        external_dns = []
        for entry in dns_config:
            addresses = entry.get("ServerAddresses", [])
            if isinstance(addresses, str):
                addresses = [addresses]
            for addr in addresses:
                addr_str = str(addr)
                if addr_str and not addr_str.startswith(("10.", "172.", "192.168.", "127.", "::1")):
                    external_dns.append(addr_str)

        if external_dns:
            self.add_finding(
                result,
                description=f"External DNS servers configured ({len(set(external_dns))} server(s))",
                severity=Severity.MEDIUM,
                evidence=f"External DNS servers: {', '.join(set(external_dns))}",
                recommendation=(
                    "Use internal DNS servers only. External DNS can be used "
                    "for DNS tunneling and data exfiltration. Deploy DNS "
                    "filtering and monitoring."
                ),
                cwe="CWE-200",
            )

    def _check_nonstandard_outbound_ports(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for outbound firewall rules on non-standard ports."""
        ports = session.run_powershell(
            "Get-NetFirewallRule -Direction Outbound -Action Allow | "
            "Get-NetFirewallPortFilter | "
            "Where-Object {$_.LocalPort -notin @('80','443','53') -and $_.LocalPort -ne 'Any'} | "
            "Select-Object LocalPort,Protocol | ConvertTo-Json"
        )
        if ports and ports.stdout.strip() and ports.stdout.strip() not in ("", "null"):
            try:
                port_list = json.loads(ports.stdout)
                if isinstance(port_list, dict):
                    port_list = [port_list]
            except json.JSONDecodeError:
                port_list = []

            if port_list:
                self.add_finding(
                    result,
                    description=f"Outbound firewall rules allow non-standard ports ({len(port_list)} rule(s))",
                    severity=Severity.MEDIUM,
                    evidence=ports.stdout[:500],
                    recommendation=(
                        "Review and restrict outbound firewall rules to only "
                        "necessary ports. Non-standard ports can be used for "
                        "data exfiltration over alternative protocols."
                    ),
                    cwe="CWE-284",
                )

    def _check_icmp_outbound(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if ICMP outbound traffic is allowed."""
        icmp = session.run_powershell(
            "Test-NetConnection -ComputerName 8.8.8.8 -InformationLevel Quiet"
        )
        if icmp and icmp.stdout.strip().lower() == "true":
            self.add_finding(
                result,
                description="Outbound ICMP traffic is allowed",
                severity=Severity.LOW,
                evidence="Test-NetConnection to 8.8.8.8 succeeded (ICMP reachable)",
                recommendation=(
                    "Consider blocking outbound ICMP at the firewall. ICMP "
                    "tunneling can be used for covert data exfiltration."
                ),
                cwe="CWE-200",
            )

    def _check_usb_policy(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if USB/removable storage devices are restricted."""
        usb = session.run_cmd(
            'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows'
            '\\RemovableStorageDevices" /s'
        )
        if not usb or not usb.stdout.strip() or "ERROR" in (usb.stdout or ""):
            self.add_finding(
                result,
                description="No USB/removable storage device restrictions configured",
                severity=Severity.MEDIUM,
                evidence="Registry key HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices not found or empty",
                recommendation=(
                    "Configure Group Policy to restrict USB and removable "
                    "storage devices. Use 'Removable Storage Access' GPO "
                    "settings to deny read/write access."
                ),
                cwe="CWE-284",
            )
        else:
            # Check if deny policies are actually set
            if "Deny_All" not in usb.stdout and "Deny_Write" not in usb.stdout:
                self.add_finding(
                    result,
                    description="USB/removable storage policy exists but deny rules may not be enforced",
                    severity=Severity.LOW,
                    evidence=usb.stdout[:500],
                    recommendation=(
                        "Verify that Deny_All or Deny_Write values are set "
                        "for removable storage device classes."
                    ),
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate alternative protocol exfiltration enumeration."""
        result = self.create_result(target_host=session.target.host, simulated=True)

        # Check active connections on non-standard ports
        netstat = session.run_cmd("netstat -an")
        if netstat and netstat.stdout:
            lines = netstat.stdout.splitlines()
            nonstandard = [
                l for l in lines
                if "ESTABLISHED" in l
                and not any(f":{p} " in l for p in ("80", "443", "53", "389", "636"))
            ]
            self.add_finding(
                result,
                description=f"Simulated: Found {len(nonstandard)} connection(s) on non-standard ports",
                severity=Severity.INFO,
                evidence="\n".join(nonstandard[:20]) if nonstandard else "No non-standard port connections",
                recommendation="Monitor connections on non-standard ports for potential exfiltration",
            )

        # List USB/removable drives
        usb_drives = session.run_powershell(
            "Get-WmiObject Win32_DiskDrive | "
            "Where-Object {$_.InterfaceType -eq 'USB'} | "
            "Select-Object Model,Size | ConvertTo-Json"
        )
        if usb_drives and usb_drives.stdout.strip() and usb_drives.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Simulated: USB/removable drives detected",
                severity=Severity.INFO,
                evidence=usb_drives.stdout[:500],
                recommendation="Monitor USB device connections and enforce removable storage policies",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1037 — Filter Network Traffic: Block non-standard outbound ports and ICMP tunneling",
            "M1031 — Network Intrusion Prevention: Deploy DPI to detect protocol-based exfiltration",
            "M1028 — Operating System Configuration: Restrict USB and removable storage via GPO",
            "M1057 — Data Loss Prevention: Deploy DLP solutions to monitor data transfers",
        ]
