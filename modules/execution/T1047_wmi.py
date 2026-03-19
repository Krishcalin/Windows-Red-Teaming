"""T1047 — Windows Management Instrumentation.

Checks WMI access controls, remote WMI configuration,
WMI event subscriptions (persistence), and auditing
for WMI-based attacks.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class WmiAccessCheck(BaseModule):
    """T1047 — WMI access controls audit.

    Evaluates WMI security configuration including namespace
    permissions, remote access, event subscriptions, and
    monitoring capabilities.
    """

    TECHNIQUE_ID = "T1047"
    TECHNIQUE_NAME = "Windows Management Instrumentation"
    TACTIC = "Execution"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_wmi_service(session, result)
        self._check_remote_wmi(session, result)
        self._check_wmi_subscriptions(session, result)
        self._check_wmi_logging(session, result)
        self._check_wmi_namespace_audit(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_wmi_service(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check WMI service status."""
        svc = session.run_powershell(
            "(Get-Service -Name Winmgmt -ErrorAction SilentlyContinue).Status"
        )
        if svc and svc.stdout.strip().lower() == "running":
            self.add_finding(
                result,
                description="WMI service (Winmgmt) is running",
                severity=Severity.INFO,
                evidence="Winmgmt service: Running",
                recommendation="WMI is required for system management. Restrict remote access if not needed.",
            )

    def _check_remote_wmi(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if remote WMI/DCOM access is permitted."""
        # Check DCOM configuration for remote WMI
        firewall_rule = session.run_powershell(
            "Get-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' } | "
            "Select-Object DisplayName, Profile | "
            "ConvertTo-Json -Compress"
        )
        if firewall_rule and firewall_rule.stdout.strip() and firewall_rule.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Remote WMI access is allowed through the firewall",
                severity=Severity.MEDIUM,
                evidence=firewall_rule.stdout[:500],
                recommendation=(
                    "Disable remote WMI firewall rules if remote management is "
                    "not required. WMI lateral movement is a common attack vector."
                ),
            )

    def _check_wmi_subscriptions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for WMI event subscriptions (persistence mechanism)."""
        subs = session.run_powershell(
            "Get-CimInstance -Namespace root/subscription "
            "-ClassName __EventConsumer -ErrorAction SilentlyContinue | "
            "Select-Object __CLASS, Name | ConvertTo-Json -Compress"
        )
        if subs and subs.stdout.strip() and subs.stdout.strip() not in ("", "null"):
            try:
                consumers = json.loads(subs.stdout)
            except json.JSONDecodeError:
                return

            if not isinstance(consumers, list):
                consumers = [consumers]

            if consumers:
                # Also get bindings
                bindings = session.run_powershell(
                    "Get-CimInstance -Namespace root/subscription "
                    "-ClassName __FilterToConsumerBinding "
                    "-ErrorAction SilentlyContinue | "
                    "Select-Object -ExpandProperty __PATH"
                )
                self.add_finding(
                    result,
                    description=f"WMI event subscriptions found ({len(consumers)} consumer(s))",
                    severity=Severity.HIGH,
                    evidence=subs.stdout[:500],
                    recommendation=(
                        "Review WMI event subscriptions for malicious persistence. "
                        "Legitimate subscriptions are rare. Use: "
                        "Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer"
                    ),
                    cwe="CWE-284",
                )

    def _check_wmi_logging(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if WMI activity logging is configured."""
        # Check WMI Operational log
        wmi_log = session.run_powershell(
            "$log = Get-WinEvent -ListLog 'Microsoft-Windows-WMI-Activity/Operational' "
            "-ErrorAction SilentlyContinue; "
            "if ($log) { "
            "  @{ Enabled=$log.IsEnabled; MaxSize=$log.MaximumSizeInBytes; "
            "     Records=$log.RecordCount } | ConvertTo-Json -Compress "
            "} else { 'unavailable' }"
        )
        if wmi_log and "unavailable" not in wmi_log.stdout:
            try:
                cfg = json.loads(wmi_log.stdout)
            except json.JSONDecodeError:
                return

            if not cfg.get("Enabled", True):
                self.add_finding(
                    result,
                    description="WMI Operational event log is disabled",
                    severity=Severity.MEDIUM,
                    evidence=wmi_log.stdout,
                    recommendation=(
                        "Enable Microsoft-Windows-WMI-Activity/Operational log. "
                        "This logs WMI queries and is essential for detecting "
                        "WMI-based attacks."
                    ),
                    cwe="CWE-778",
                )

    def _check_wmi_namespace_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check WMI namespace security (SACL) for auditing."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Other Object Access Events' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="WMI namespace auditing is not enabled (Other Object Access Events)",
                severity=Severity.LOW,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Other Object Access Events' to log "
                    "WMI namespace access attempts"
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        commands = [
            ("wmic process list brief /format:list",
             "WMI process enumeration"),
            ("wmic service list brief /format:list",
             "WMI service enumeration"),
        ]
        for cmd, desc in commands:
            out = session.run_cmd(cmd, timeout=15)
            if out:
                self.add_finding(
                    result, description=f"Simulated: {desc}",
                    severity=Severity.INFO, evidence=out.stdout[:500],
                    recommendation="Monitor WMI activity via Operational event log",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1026 — Privileged Account Management: Restrict WMI namespace permissions",
            "M1040 — Behavior Prevention on Endpoint: Monitor WMI event subscriptions",
            "M1038 — Execution Prevention: Block remote WMI via firewall if not needed",
            "M1047 — Audit: Enable WMI Operational log and Object Access auditing",
        ]
