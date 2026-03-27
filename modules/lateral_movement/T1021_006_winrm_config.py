"""T1021.006 — Windows Remote Management.

Audits WinRM configuration for insecure settings including HTTP
listeners, overly broad trusted hosts, and unencrypted transport
that could allow adversaries to use WinRM for lateral movement.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class WinRMConfigAudit(BaseModule):
    """T1021.006 — Windows Remote Management.

    Checks whether WinRM is securely configured, including listener
    transport, trusted hosts restrictions, and encryption settings.
    """

    TECHNIQUE_ID = "T1021.006"
    TECHNIQUE_NAME = "Windows Remote Management"
    TACTIC = "Lateral Movement"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Check WinRM service status ────────────────────────────
        svc = session.run_powershell(
            "Get-Service WinRM | Select-Object Status,StartType | ConvertTo-Json"
        )
        winrm_running = False
        if svc and svc.stdout:
            output = svc.stdout.strip()
            self._log.info("winrm_service_checked", output=output[:200])
            if '"Running"' in output or '"Status":  4' in output:
                winrm_running = True

        if not winrm_running:
            self.add_finding(
                result,
                description="WinRM service is not running",
                severity=Severity.INFO,
                evidence=svc.stdout[:500] if svc and svc.stdout else "Service not found",
                recommendation="WinRM is not running — no lateral movement risk via WinRM",
            )
            result.complete(ModuleStatus.SUCCESS)
            return result

        # ── Check WinRM listeners ─────────────────────────────────
        listeners = session.run_cmd("winrm enumerate winrm/config/listener")
        if listeners and listeners.stdout:
            output = listeners.stdout
            if "Transport = HTTP" in output and "Transport = HTTPS" not in output:
                self.add_finding(
                    result,
                    description="WinRM is configured with HTTP listener only (no HTTPS)",
                    severity=Severity.HIGH,
                    evidence=output[:500],
                    recommendation=(
                        "Configure WinRM with HTTPS listener: "
                        "winrm quickconfig -transport:https. "
                        "Remove HTTP listener after HTTPS is configured."
                    ),
                    cwe="CWE-319",
                )
            elif "Transport = HTTP" in output:
                self.add_finding(
                    result,
                    description="WinRM has an HTTP listener in addition to HTTPS",
                    severity=Severity.MEDIUM,
                    evidence=output[:500],
                    recommendation="Remove the HTTP listener and use HTTPS only",
                    cwe="CWE-319",
                )

        # ── Check trusted hosts ───────────────────────────────────
        trusted = session.run_powershell(
            "(Get-Item WSMan:\\localhost\\Client\\TrustedHosts).Value"
        )
        if trusted and trusted.stdout:
            hosts_value = trusted.stdout.strip()
            if hosts_value == "*":
                self.add_finding(
                    result,
                    description="WinRM TrustedHosts is set to wildcard (*) — any host is trusted",
                    severity=Severity.CRITICAL,
                    evidence=f"TrustedHosts = {hosts_value}",
                    recommendation=(
                        "Restrict TrustedHosts to specific hosts: "
                        "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value 'host1,host2'"
                    ),
                    cwe="CWE-284",
                )
            elif hosts_value:
                self.add_finding(
                    result,
                    description=f"WinRM TrustedHosts is configured: {hosts_value}",
                    severity=Severity.LOW,
                    evidence=f"TrustedHosts = {hosts_value}",
                    recommendation="Review TrustedHosts list and ensure only authorized hosts are included",
                )

        # ── Check AllowUnencrypted ────────────────────────────────
        unencrypted = session.run_powershell(
            "(Get-Item WSMan:\\localhost\\Service\\AllowUnencrypted).Value"
        )
        if unencrypted and unencrypted.stdout:
            val = unencrypted.stdout.strip().lower()
            if val == "true":
                self.add_finding(
                    result,
                    description="WinRM allows unencrypted traffic",
                    severity=Severity.HIGH,
                    evidence=f"AllowUnencrypted = {unencrypted.stdout.strip()}",
                    recommendation=(
                        "Disable unencrypted WinRM: "
                        "Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false"
                    ),
                    cwe="CWE-319",
                )

        # ── General WinRM running finding ─────────────────────────
        self.add_finding(
            result,
            description="WinRM service is running and accepting connections",
            severity=Severity.MEDIUM,
            evidence=svc.stdout[:500] if svc and svc.stdout else "WinRM running",
            recommendation=(
                "Ensure WinRM is required for operations. If not needed, "
                "disable the service. If needed, enforce HTTPS and restrict access."
            ),
        )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary WinRM reconnaissance commands."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        # ── Enumerate full WinRM configuration ────────────────────
        config = session.run_cmd("winrm get winrm/config")
        if config and config.stdout:
            self.add_finding(
                result,
                description="Simulated: Enumerated full WinRM configuration",
                severity=Severity.INFO,
                evidence=config.stdout[:500],
                recommendation="Monitor for unauthorized winrm configuration enumeration",
            )

        # ── Check PSRemoting connectivity ─────────────────────────
        wsman = session.run_powershell(
            "Test-WSMan -ComputerName localhost"
        )
        if wsman and wsman.stdout:
            self.add_finding(
                result,
                description="Simulated: Test-WSMan confirmed WinRM is accessible on localhost",
                severity=Severity.INFO,
                evidence=wsman.stdout[:500],
                recommendation="Monitor for Test-WSMan and Enter-PSSession usage",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass  # Read-only checks — nothing to revert

    def get_mitigations(self) -> list[str]:
        return [
            "M1042 — Disable or Remove Feature: Disable WinRM if not required",
            "M1030 — Network Segmentation: Restrict WinRM access to management networks only",
            "M1035 — Limit Access to Resource Over Network: Use firewall rules to limit WinRM access",
            "M1032 — Multi-factor Authentication: Require certificate-based authentication for WinRM",
            "M1026 — Privileged Account Management: Limit accounts permitted to use WinRM",
        ]
