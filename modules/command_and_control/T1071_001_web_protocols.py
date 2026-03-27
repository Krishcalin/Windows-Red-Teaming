"""T1071.001 — Application Layer Protocol: Web Protocols.

Checks for outbound HTTP/HTTPS communication channels that
could be used for command and control, including proxy settings,
firewall rules, and suspicious scheduled tasks making web calls.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class WebProtocolC2Check(BaseModule):
    """T1071.001 — Web protocol C2 channel audit.

    Evaluates proxy configuration, outbound HTTP/HTTPS firewall
    rules, suspicious web-calling scheduled tasks, and certificate
    validation settings.
    """

    TECHNIQUE_ID = "T1071.001"
    TECHNIQUE_NAME = "Application Layer Protocol: Web Protocols"
    TACTIC = "Command and Control"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_proxy_settings(session, result)
        self._check_outbound_http_rules(session, result)
        self._check_suspicious_web_tasks(session, result)
        self._check_certificate_validation(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_proxy_settings(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if a proxy is configured for outbound web traffic."""
        proxy_enable = session.run_cmd(
            'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
            '\\Internet Settings" /v ProxyEnable'
        )
        proxy_server = session.run_cmd(
            'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
            '\\Internet Settings" /v ProxyServer'
        )

        proxy_enabled = False
        if proxy_enable and proxy_enable.stdout:
            proxy_enabled = "0x1" in proxy_enable.stdout

        if not proxy_enabled:
            self.add_finding(
                result,
                description="No web proxy configured — outbound HTTP/HTTPS traffic is unrestricted",
                severity=Severity.MEDIUM,
                evidence=(
                    f"ProxyEnable: {proxy_enable.stdout.strip() if proxy_enable else 'not found'}\n"
                    f"ProxyServer: {proxy_server.stdout.strip() if proxy_server and proxy_server.stdout else 'not configured'}"
                ),
                recommendation=(
                    "Configure a web proxy or web filtering solution to inspect "
                    "and control outbound HTTP/HTTPS traffic. This limits C2 "
                    "communication channels."
                ),
                cwe="CWE-284",
            )

    def _check_outbound_http_rules(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check outbound firewall rules allowing HTTP/HTTPS traffic."""
        fw_rules = session.run_powershell(
            "Get-NetFirewallRule -Direction Outbound -Action Allow | "
            "Where-Object {$_.DisplayName -match 'HTTP|Web|Internet'} | "
            "Select-Object DisplayName,Enabled | ConvertTo-Json"
        )
        if fw_rules and fw_rules.stdout.strip() and fw_rules.stdout.strip() not in ("", "null"):
            try:
                rules = json.loads(fw_rules.stdout)
                if isinstance(rules, dict):
                    rules = [rules]
            except json.JSONDecodeError:
                rules = []

            if rules:
                self.add_finding(
                    result,
                    description=f"Outbound HTTP/HTTPS firewall rules found ({len(rules)} rule(s))",
                    severity=Severity.MEDIUM,
                    evidence=fw_rules.stdout[:500],
                    recommendation=(
                        "Review outbound firewall rules allowing HTTP/HTTPS traffic. "
                        "Restrict outbound web access to approved applications and "
                        "destinations only."
                    ),
                    cwe="CWE-284",
                )

    def _check_suspicious_web_tasks(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for scheduled tasks that invoke web request tools."""
        tasks = session.run_powershell(
            "Get-ScheduledTask | Where-Object "
            "{$_.Actions.Execute -match 'curl|wget|Invoke-WebRequest|certutil|bitsadmin'} | "
            "Select-Object TaskName,State | ConvertTo-Json"
        )
        if tasks and tasks.stdout.strip() and tasks.stdout.strip() not in ("", "null"):
            try:
                task_list = json.loads(tasks.stdout)
                if isinstance(task_list, dict):
                    task_list = [task_list]
            except json.JSONDecodeError:
                task_list = []

            if task_list:
                self.add_finding(
                    result,
                    description=f"Scheduled tasks using web request tools found ({len(task_list)} task(s))",
                    severity=Severity.HIGH,
                    evidence=tasks.stdout[:500],
                    recommendation=(
                        "Investigate scheduled tasks that use curl, wget, "
                        "Invoke-WebRequest, certutil, or bitsadmin. These tools "
                        "are commonly abused for C2 communication and payload delivery."
                    ),
                    cwe="CWE-506",
                )

    def _check_certificate_validation(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if certificate validation callback is overridden."""
        cert_check = session.run_powershell(
            "[System.Net.ServicePointManager]::ServerCertificateValidationCallback"
        )
        if cert_check and cert_check.stdout.strip():
            callback_value = cert_check.stdout.strip()
            if callback_value and callback_value.lower() not in ("", "null"):
                self.add_finding(
                    result,
                    description="Custom certificate validation callback is configured",
                    severity=Severity.HIGH,
                    evidence=f"ServerCertificateValidationCallback: {callback_value[:300]}",
                    recommendation=(
                        "Investigate the custom certificate validation callback. "
                        "Overriding certificate validation can allow C2 channels "
                        "to bypass TLS inspection."
                    ),
                    cwe="CWE-295",
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate web protocol C2 channel enumeration."""
        result = self.create_result(target_host=session.target.host, simulated=True)

        # Check for established HTTP/HTTPS connections
        netstat = session.run_cmd("netstat -an")
        if netstat and netstat.stdout:
            lines = netstat.stdout.splitlines()
            http_conns = [
                l for l in lines
                if "ESTABLISHED" in l and (":80 " in l or ":443 " in l)
            ]
            self.add_finding(
                result,
                description=f"Simulated: Found {len(http_conns)} established HTTP/HTTPS connection(s)",
                severity=Severity.INFO,
                evidence="\n".join(http_conns[:20]) if http_conns else "No active HTTP/HTTPS connections",
                recommendation="Monitor outbound HTTP/HTTPS connections for anomalous destinations",
            )

        # Check DNS cache for suspicious entries
        dns_cache = session.run_cmd("ipconfig /displaydns")
        if dns_cache and dns_cache.stdout:
            self.add_finding(
                result,
                description="Simulated: DNS cache enumeration for C2 indicators",
                severity=Severity.INFO,
                evidence=dns_cache.stdout[:500],
                recommendation=(
                    "Review DNS cache for unusual or recently resolved domains "
                    "that may indicate C2 activity"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1031 — Network Intrusion Prevention: Deploy IDS/IPS to detect C2 traffic patterns",
            "M1030 — Network Segmentation: Restrict outbound HTTP/HTTPS to approved hosts",
            "M1037 — Filter Network Traffic: Use web proxy with SSL inspection",
            "M1021 — Restrict Web-Based Content: Block unnecessary outbound web traffic at the firewall",
        ]
