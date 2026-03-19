"""T1049 — System Network Connections Discovery.

Checks active network connections, identifies suspicious outbound
connections, and evaluates network monitoring capabilities.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Well-known ports that are normal for outbound
_NORMAL_OUTBOUND = {443, 80, 53}

# Suspicious outbound ports (common C2, exfil, tunnel)
_SUSPICIOUS_PORTS = {
    4444: "Metasploit default handler",
    5555: "Common reverse shell",
    8080: "HTTP proxy / C2",
    8443: "HTTPS alternate / C2",
    1080: "SOCKS proxy",
    9090: "Common web admin / C2",
    6667: "IRC (C2 channel)",
    6697: "IRC over TLS (C2 channel)",
    4443: "Common C2 port",
    8888: "Common C2 / debug port",
    1337: "Common hacker backdoor",
    31337: "Back Orifice / legacy backdoor",
}


class NetworkConnectionsDiscovery(BaseModule):
    """T1049 — System Network Connections Discovery.

    Enumerates active network connections and identifies
    potentially suspicious communication patterns.
    """

    TECHNIQUE_ID = "T1049"
    TECHNIQUE_NAME = "System Network Connections Discovery"
    TACTIC = "Discovery"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Check active established connections ─────────────────
        self._check_established_connections(session, result)

        # ── Check for connections to non-standard ports ──────────
        self._check_suspicious_outbound(session, result)

        # ── Check DNS client cache for suspicious entries ────────
        self._check_dns_cache(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_established_connections(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Enumerate established TCP connections."""
        conns = session.run_powershell(
            "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, "
            "OwningProcess | ConvertTo-Json -Compress"
        )
        if not conns or not conns.stdout.strip():
            return

        try:
            connections = json.loads(conns.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(connections, list):
            connections = [connections]

        external_count = 0
        for conn in connections:
            remote = conn.get("RemoteAddress", "")
            if remote and not remote.startswith(("127.", "::1", "0.0.0.0")):
                external_count += 1

        if external_count > 50:
            self.add_finding(
                result,
                description=f"High number of external connections detected ({external_count})",
                severity=Severity.LOW,
                evidence=f"Established external TCP connections: {external_count}",
                recommendation=(
                    "Review outbound connections for unauthorized or unexpected "
                    "communication. Consider network segmentation."
                ),
            )

    def _check_suspicious_outbound(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for outbound connections to suspicious ports."""
        conns = session.run_powershell(
            "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
            "Where-Object { $_.RemoteAddress -notmatch '^(127\\.|::1|0\\.0)' } | "
            "Select-Object RemoteAddress, RemotePort, OwningProcess | "
            "ConvertTo-Json -Compress"
        )
        if not conns or not conns.stdout.strip():
            return

        try:
            connections = json.loads(conns.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(connections, list):
            connections = [connections]

        for conn in connections:
            port = conn.get("RemotePort", 0)
            if port in _SUSPICIOUS_PORTS:
                remote = conn.get("RemoteAddress", "?")
                pid = conn.get("OwningProcess", "?")
                desc = _SUSPICIOUS_PORTS[port]
                self.add_finding(
                    result,
                    description=f"Suspicious outbound connection to port {port} ({desc})",
                    severity=Severity.HIGH,
                    evidence=f"Remote={remote}:{port}, PID={pid}",
                    recommendation=(
                        f"Investigate process PID {pid} connecting to {remote}:{port}. "
                        f"Port {port} is commonly associated with: {desc}"
                    ),
                    cwe="CWE-200",
                )

    def _check_dns_cache(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check DNS cache for suspicious entries (very long domains, high entropy)."""
        dns = session.run_powershell(
            "Get-DnsClientCache -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Entry"
        )
        if not dns or not dns.stdout.strip():
            return

        entries = [e.strip() for e in dns.stdout.splitlines() if e.strip()]

        # Check for very long domain names (possible DNS tunneling)
        long_domains = [e for e in entries if len(e) > 80]
        if long_domains:
            self.add_finding(
                result,
                description=f"Unusually long DNS entries detected ({len(long_domains)} entries > 80 chars)",
                severity=Severity.MEDIUM,
                evidence="\n".join(long_domains[:5]),
                recommendation=(
                    "Investigate long DNS queries — they may indicate DNS "
                    "tunneling (T1071.004) for C2 or data exfiltration."
                ),
                cwe="CWE-200",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary network connection enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("netstat -ano", "Full connection table"),
            ("netstat -anb 2>nul", "Connections with owning process names"),
        ]

        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Monitor for network enumeration commands",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1031 — Network Intrusion Prevention: Monitor for suspicious outbound connections",
            "M1030 — Network Segmentation: Restrict outbound access to known-good destinations",
            "M1037 — Filter Network Traffic: Block known C2 ports at the network perimeter",
            "M1047 — Audit: Enable network connection logging for forensic analysis",
        ]
