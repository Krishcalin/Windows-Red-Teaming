"""T1595 — Active Scanning.

Checks the target's exposure to active scanning by evaluating
ICMP response, exposed management interfaces, service banners,
and network-level protections.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Management interfaces that should not be exposed
_MGMT_PORTS = {
    "22": ("SSH", Severity.MEDIUM),
    "3389": ("RDP", Severity.MEDIUM),
    "5985": ("WinRM HTTP", Severity.HIGH),
    "5986": ("WinRM HTTPS", Severity.MEDIUM),
    "135": ("RPC Endpoint Mapper", Severity.MEDIUM),
    "445": ("SMB", Severity.MEDIUM),
    "1433": ("MSSQL", Severity.HIGH),
    "161": ("SNMP", Severity.HIGH),
    "3306": ("MySQL", Severity.HIGH),
    "5432": ("PostgreSQL", Severity.HIGH),
}


class ActiveScanning(BaseModule):
    """T1595 — Active Scanning.

    Evaluates the target's exposure to network reconnaissance
    and active scanning techniques.
    """

    TECHNIQUE_ID = "T1595"
    TECHNIQUE_NAME = "Active Scanning"
    TACTIC = "Reconnaissance"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Check ICMP response (ping-ability) ───────────────────
        self._check_icmp(session, result)

        # ── Check exposed management ports ───────────────────────
        self._check_management_ports(session, result)

        # ── Check Windows Remote Management config ───────────────
        self._check_winrm_config(session, result)

        # ── Check firewall logging ───────────────────────────────
        self._check_firewall_logging(session, result)

        # ── Check if RDP is enabled ──────────────────────────────
        self._check_rdp_config(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_icmp(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if ICMP echo (ping) is allowed through the firewall."""
        icmp = session.run_powershell(
            "Get-NetFirewallRule -DisplayName '*ICMPv4*' "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' } | "
            "Select-Object DisplayName, Profile | "
            "ConvertTo-Json -Compress"
        )
        if icmp and icmp.stdout.strip() and icmp.stdout.strip() not in ("", "null"):
            try:
                rules = json.loads(icmp.stdout)
            except json.JSONDecodeError:
                return

            if not isinstance(rules, list):
                rules = [rules]

            if rules:
                self.add_finding(
                    result,
                    description=f"ICMP echo (ping) is allowed through the firewall ({len(rules)} rule(s))",
                    severity=Severity.LOW,
                    evidence="\n".join(
                        f"{r.get('DisplayName', '')}: Profile={r.get('Profile', '')}"
                        for r in rules
                    ),
                    recommendation=(
                        "Consider blocking inbound ICMP echo requests on "
                        "external-facing interfaces to reduce reconnaissance exposure."
                    ),
                )

    def _check_management_ports(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for management services listening on all interfaces."""
        listeners = session.run_powershell(
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort | "
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

        seen: set[str] = set()
        for conn in conns:
            addr = conn.get("LocalAddress", "")
            port = str(conn.get("LocalPort", ""))

            if port in seen:
                continue

            # Only flag if listening on all interfaces (0.0.0.0 or ::)
            if addr not in ("0.0.0.0", "::", ""):
                continue

            if port in _MGMT_PORTS:
                svc, sev = _MGMT_PORTS[port]
                seen.add(port)
                self.add_finding(
                    result,
                    description=(
                        f"{svc} (port {port}) is listening on all interfaces — "
                        f"exposed to network scanning"
                    ),
                    severity=sev,
                    evidence=f"Listener: {addr}:{port}",
                    recommendation=(
                        f"Restrict {svc} to specific IP addresses via Windows "
                        f"Firewall rules. Bind to management VLANs only."
                    ),
                    cwe="CWE-200",
                )

    def _check_winrm_config(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check WinRM configuration for security issues."""
        winrm = session.run_powershell(
            "try { "
            "  $ws = Get-WSManInstance winrm/config/service -ErrorAction Stop; "
            "  @{ "
            "    AllowUnencrypted = $ws.AllowUnencrypted; "
            "    Auth_Basic = $ws.Auth.Basic; "
            "    Auth_Kerberos = $ws.Auth.Kerberos; "
            "    MaxConcurrentUsers = $ws.MaxConcurrentUsers "
            "  } | ConvertTo-Json -Compress "
            "} catch { 'winrm_disabled' }"
        )
        if not winrm or "winrm_disabled" in winrm.stdout:
            return

        try:
            cfg = json.loads(winrm.stdout)
        except json.JSONDecodeError:
            return

        if str(cfg.get("AllowUnencrypted", "")).lower() == "true":
            self.add_finding(
                result,
                description="WinRM allows unencrypted traffic",
                severity=Severity.HIGH,
                evidence="AllowUnencrypted = True",
                recommendation=(
                    "Disable unencrypted WinRM: "
                    "Set-WSManInstance winrm/config/service @{AllowUnencrypted='false'}"
                ),
                cwe="CWE-319",
            )

        if str(cfg.get("Auth_Basic", "")).lower() == "true":
            self.add_finding(
                result,
                description="WinRM Basic authentication is enabled (sends credentials in cleartext)",
                severity=Severity.HIGH,
                evidence="Auth.Basic = True",
                recommendation=(
                    "Disable Basic auth for WinRM. Use Kerberos or NTLM with "
                    "encryption instead."
                ),
                cwe="CWE-319",
            )

    def _check_firewall_logging(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Windows Firewall logging is enabled."""
        fw_log = session.run_powershell(
            "Get-NetFirewallProfile | "
            "Select-Object Name, "
            "@{N='LogAllowed';E={$_.LogAllowed}}, "
            "@{N='LogBlocked';E={$_.LogBlocked}}, "
            "@{N='LogFileName';E={$_.LogFileName}} | "
            "ConvertTo-Json -Compress"
        )
        if not fw_log or not fw_log.stdout.strip():
            return

        try:
            profiles = json.loads(fw_log.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(profiles, list):
            profiles = [profiles]

        for profile in profiles:
            name = profile.get("Name", "")
            log_blocked = str(profile.get("LogBlocked", "")).lower()
            if log_blocked in ("false", "notconfigured", "0"):
                self.add_finding(
                    result,
                    description=f"Firewall logging for blocked connections is disabled on '{name}' profile",
                    severity=Severity.MEDIUM,
                    evidence=f"Profile: {name}, LogBlocked: {log_blocked}",
                    recommendation=(
                        "Enable firewall logging for blocked connections: "
                        f"Set-NetFirewallProfile -Name {name} -LogBlocked True. "
                        "CIS Benchmark 9.x.3"
                    ),
                    cwe="CWE-778",
                )

    def _check_rdp_config(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check RDP configuration security settings."""
        rdp_enabled = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
        if rdp_enabled is not None and str(rdp_enabled) == "0":
            # RDP is enabled — check NLA requirement
            nla = session.read_registry(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication",
            )
            if nla is None or str(nla) != "1":
                self.add_finding(
                    result,
                    description="RDP is enabled without Network Level Authentication (NLA)",
                    severity=Severity.HIGH,
                    evidence=f"fDenyTSConnections=0, UserAuthentication={nla}",
                    recommendation=(
                        "Enable NLA for RDP: Set UserAuthentication to 1 under "
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
                        "WinStations\\RDP-Tcp. CIS Benchmark 18.10.57.3.3.1"
                    ),
                    cwe="CWE-287",
                )

            # Check minimum encryption level
            sec_layer = session.read_registry(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "SecurityLayer",
            )
            if sec_layer is not None and str(sec_layer) == "0":
                self.add_finding(
                    result,
                    description="RDP security layer is set to 'RDP Security Layer' (weakest)",
                    severity=Severity.MEDIUM,
                    evidence=f"SecurityLayer = {sec_layer} (0=RDP, 1=Negotiate, 2=TLS)",
                    recommendation=(
                        "Set RDP security layer to TLS (2) or at minimum Negotiate (1)"
                    ),
                    cwe="CWE-327",
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate active scanning reconnaissance."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("netsh advfirewall show allprofiles state",
             "Firewall state enumeration"),
            ("netsh advfirewall firewall show rule name=all dir=in | findstr \"Rule Name\"",
             "Inbound firewall rule enumeration"),
        ]

        for cmd, desc in commands:
            out = session.run_cmd(cmd, timeout=15)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Monitor for reconnaissance command execution",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1030 — Network Segmentation: Restrict management ports to dedicated VLANs",
            "M1031 — Network Intrusion Prevention: Block inbound scanning at the perimeter",
            "M1035 — Limit Access to Resource Over Network: Bind services to specific interfaces",
            "M1042 — Disable or Remove Feature or Program: Disable unused services (RDP, WinRM, SNMP)",
        ]
