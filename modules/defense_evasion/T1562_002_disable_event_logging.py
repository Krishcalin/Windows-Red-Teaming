"""T1562.002 — Impair Defenses: Disable Windows Event Logging.

Checks event logging configuration, log sizes, auditing policy,
and the Windows Event Log service to detect logging impairment.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Critical event logs and minimum recommended sizes (bytes)
_CRITICAL_LOGS = {
    "Security": 1073741824,         # 1 GB
    "System": 134217728,            # 128 MB
    "Application": 134217728,       # 128 MB
    "Microsoft-Windows-Sysmon/Operational": 134217728,
    "Microsoft-Windows-PowerShell/Operational": 134217728,
    "Windows PowerShell": 134217728,
}


class DisableEventLoggingCheck(BaseModule):
    """T1562.002 — Event logging impairment audit.

    Evaluates event log configuration for evidence of
    tampering, inadequate log sizes, or missing audit policies.
    """

    TECHNIQUE_ID = "T1562.002"
    TECHNIQUE_NAME = "Impair Defenses: Disable Windows Event Logging"
    TACTIC = "Defense Evasion"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_event_log_service(session, result)
        self._check_log_sizes(session, result)
        self._check_audit_policy(session, result)
        self._check_sysmon(session, result)
        self._check_log_forwarding(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_event_log_service(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if the Event Log service is running."""
        svc = session.run_powershell(
            "(Get-Service -Name EventLog -ErrorAction SilentlyContinue).Status"
        )
        if not svc or svc.stdout.strip().lower() != "running":
            self.add_finding(
                result,
                description="Windows Event Log service is not running",
                severity=Severity.CRITICAL,
                evidence=f"EventLog service: {svc.stdout.strip() if svc else 'not found'}",
                recommendation="Start the Event Log service immediately. Investigate potential tampering.",
                cwe="CWE-778",
            )

    def _check_log_sizes(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check event log maximum sizes."""
        for log_name, min_size in _CRITICAL_LOGS.items():
            log_cfg = session.run_powershell(
                f"$l = Get-WinEvent -ListLog '{log_name}' -ErrorAction SilentlyContinue; "
                f"if ($l) {{ "
                f"  @{{ Enabled=$l.IsEnabled; MaxSize=$l.MaximumSizeInBytes; "
                f"     LogMode=$l.LogMode }} | ConvertTo-Json -Compress "
                f"}} else {{ 'missing' }}"
            )
            if not log_cfg or "missing" in log_cfg.stdout:
                if log_name == "Microsoft-Windows-Sysmon/Operational":
                    continue  # Sysmon might not be installed
                continue

            try:
                cfg = json.loads(log_cfg.stdout)
            except json.JSONDecodeError:
                continue

            if not cfg.get("Enabled", True):
                self.add_finding(
                    result,
                    description=f"Event log '{log_name}' is disabled",
                    severity=Severity.CRITICAL,
                    evidence=f"Log: {log_name}, Enabled: False",
                    recommendation=f"Enable the '{log_name}' event log immediately",
                    cwe="CWE-778",
                )

            max_size = cfg.get("MaxSize", 0)
            if max_size < min_size:
                min_mb = min_size // 1048576
                cur_mb = max_size // 1048576
                self.add_finding(
                    result,
                    description=f"Event log '{log_name}' max size is too small ({cur_mb} MB, recommended {min_mb}+ MB)",
                    severity=Severity.MEDIUM,
                    evidence=f"Log: {log_name}, MaxSize: {cur_mb} MB, Recommended: {min_mb}+ MB",
                    recommendation=(
                        f"Increase '{log_name}' log size to at least {min_mb} MB "
                        f"to prevent event loss from log rotation"
                    ),
                )

    def _check_audit_policy(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check critical audit policy categories."""
        critical_categories = [
            ("Logon", "Logon Events", Severity.HIGH),
            ("Account Logon", "Account Logon", Severity.HIGH),
            ("Object Access", "Object Access", Severity.MEDIUM),
            ("Policy Change", "Policy Change", Severity.HIGH),
            ("Account Management", "Account Management", Severity.HIGH),
            ("Privilege Use", "Privilege Use", Severity.MEDIUM),
        ]

        audit = session.run_powershell("auditpol /get /category:* 2>$null")
        if not audit or not audit.stdout:
            self.add_finding(
                result,
                description="Unable to query audit policy — auditpol access may be restricted",
                severity=Severity.MEDIUM,
                evidence="auditpol returned no output",
                recommendation="Verify audit policy configuration via Group Policy",
            )
            return

        for category, name, severity in critical_categories:
            # Find the category section in auditpol output
            found = False
            for line in audit.stdout.splitlines():
                if category.lower() in line.lower() and "No Auditing" in line:
                    self.add_finding(
                        result,
                        description=f"Audit policy '{name}' is set to 'No Auditing'",
                        severity=severity,
                        evidence=line.strip(),
                        recommendation=f"Enable {name} auditing (Success, Failure) via GPO",
                        cwe="CWE-778",
                    )
                    found = True
                    break

    def _check_sysmon(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Sysmon is installed for enhanced logging."""
        sysmon = session.run_powershell(
            "(Get-Service -Name Sysmon* -ErrorAction SilentlyContinue).Status"
        )
        if not sysmon or not sysmon.stdout.strip():
            self.add_finding(
                result,
                description="Sysmon is not installed (limited endpoint telemetry)",
                severity=Severity.MEDIUM,
                evidence="No Sysmon service detected",
                recommendation=(
                    "Deploy Sysmon with a comprehensive configuration for "
                    "process creation, network, file, and registry telemetry. "
                    "Recommended configs: SwiftOnSecurity/sysmon-config or olafhartong/sysmon-modular"
                ),
            )

    def _check_log_forwarding(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if event log forwarding is configured (WEF/SIEM)."""
        wef = session.run_powershell(
            "(Get-Service -Name Wecsvc -ErrorAction SilentlyContinue).Status"
        )
        winlogbeat = session.run_powershell(
            "(Get-Service -Name winlogbeat -ErrorAction SilentlyContinue).Status"
        )
        nxlog = session.run_powershell(
            "(Get-Service -Name nxlog -ErrorAction SilentlyContinue).Status"
        )

        has_forwarding = False
        for svc, name in [(wef, "WEF"), (winlogbeat, "Winlogbeat"), (nxlog, "NXLog")]:
            if svc and svc.stdout.strip().lower() == "running":
                has_forwarding = True

        if not has_forwarding:
            self.add_finding(
                result,
                description="No event log forwarding agent detected (WEF, Winlogbeat, NXLog)",
                severity=Severity.MEDIUM,
                evidence="No log forwarding service found",
                recommendation=(
                    "Deploy a log forwarding agent to ship events to a SIEM. "
                    "Local logs can be cleared by attackers (T1070.001)."
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_powershell(
            "auditpol /get /category:* 2>$null | Select-Object -First 30"
        )
        if out:
            self.add_finding(
                result, description="Simulated: Audit policy enumeration",
                severity=Severity.INFO, evidence=out.stdout[:500],
                recommendation="Monitor for auditpol queries and modifications",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1047 — Audit: Enable comprehensive audit policy across all categories",
            "M1029 — Remote Data Storage: Forward logs to a SIEM to prevent local tampering",
            "M1022 — Restrict File and Directory Permissions: Protect event log files",
            "M1028 — Operating System Configuration: Deploy Sysmon for enhanced telemetry",
        ]
