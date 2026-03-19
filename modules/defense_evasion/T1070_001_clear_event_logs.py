"""T1070.001 — Indicator Removal: Clear Windows Event Logs.

Checks protections against event log clearing, verifies log
integrity controls, and evaluates event log ACLs.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class ClearEventLogsCheck(BaseModule):
    """T1070.001 — Event log clearing protection audit.

    Evaluates defenses against adversary log clearing
    including forwarding, ACLs, and audit trail for clears.
    """

    TECHNIQUE_ID = "T1070.001"
    TECHNIQUE_NAME = "Indicator Removal: Clear Windows Event Logs"
    TACTIC = "Defense Evasion"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_log_clear_audit(session, result)
        self._check_recent_log_clears(session, result)
        self._check_log_file_permissions(session, result)
        self._check_log_forwarding(session, result)
        self._check_wevtutil_access(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_log_clear_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if audit log clear events are being tracked."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Audit Policy Change' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="Audit Policy Change auditing is not enabled — log clears will not be detected",
                severity=Severity.HIGH,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Policy Change' (Success, Failure). "
                    "Event ID 1102 (Security log cleared) requires this. "
                    "CIS Benchmark 17.7.1"
                ),
                cwe="CWE-778",
            )

    def _check_recent_log_clears(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for recent event log clear events."""
        # Event ID 1102 = Security log cleared
        # Event ID 104 = System log cleared (from System log)
        clears = session.run_powershell(
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} "
            "-MaxEvents 5 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Message | "
            "ConvertTo-Json -Compress"
        )
        if clears and clears.stdout.strip() and clears.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Security log was recently cleared (Event ID 1102)",
                severity=Severity.CRITICAL,
                evidence=clears.stdout[:500],
                recommendation=(
                    "Investigate Security log clear events. This may indicate "
                    "an attacker covering their tracks. Check who initiated "
                    "the clear and correlate with other indicators."
                ),
                cwe="CWE-778",
            )

        sys_clears = session.run_powershell(
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} "
            "-MaxEvents 5 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Message | "
            "ConvertTo-Json -Compress"
        )
        if sys_clears and sys_clears.stdout.strip() and sys_clears.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="System/Application log was recently cleared (Event ID 104)",
                severity=Severity.HIGH,
                evidence=sys_clears.stdout[:500],
                recommendation=(
                    "Investigate log clear events in System log. "
                    "Correlate with login activity and process creation."
                ),
            )

    def _check_log_file_permissions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check permissions on event log files."""
        acl = session.run_powershell(
            "$logDir = 'C:\\Windows\\System32\\winevt\\Logs'; "
            "(Get-Acl $logDir -ErrorAction SilentlyContinue).Access | "
            "Where-Object { "
            "  $_.IdentityReference -match 'Users|Everyone|Authenticated Users' "
            "  -and $_.FileSystemRights -match 'Delete|Write|Modify|FullControl' "
            "} | Select-Object IdentityReference, FileSystemRights | "
            "ConvertTo-Json -Compress"
        )
        if acl and acl.stdout.strip() and acl.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Event log directory has weak permissions (log deletion risk)",
                severity=Severity.HIGH,
                evidence=acl.stdout[:500],
                recommendation=(
                    "Fix permissions on C:\\Windows\\System32\\winevt\\Logs. "
                    "Only SYSTEM and Administrators should have write/delete access."
                ),
                cwe="CWE-732",
            )

    def _check_log_forwarding(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if logs are forwarded (protection against local clearing)."""
        # Check for any log forwarding service
        forwarding = session.run_powershell(
            "$svcs = @('Wecsvc','winlogbeat','nxlog','splunkd'); "
            "$running = $svcs | Where-Object { "
            "  (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' "
            "}; "
            "if ($running) { $running -join ', ' } else { 'none' }"
        )
        if forwarding and forwarding.stdout.strip() == "none":
            self.add_finding(
                result,
                description="No log forwarding detected — logs are only stored locally",
                severity=Severity.HIGH,
                evidence="No forwarding agents (WEF, Winlogbeat, NXLog, Splunk) detected",
                recommendation=(
                    "Deploy event log forwarding to a remote SIEM or collector. "
                    "Local-only logs can be cleared by an attacker with admin access."
                ),
            )

    def _check_wevtutil_access(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if wevtutil.exe is accessible (log clearing tool)."""
        wevt = session.run_powershell(
            "Test-Path $env:SystemRoot\\System32\\wevtutil.exe"
        )
        if wevt and wevt.stdout.strip().lower() == "true":
            self.add_finding(
                result,
                description="wevtutil.exe is accessible (can be used to clear event logs)",
                severity=Severity.INFO,
                evidence="wevtutil.exe exists in System32",
                recommendation=(
                    "Monitor wevtutil.exe execution via process creation logs. "
                    "Consider AppLocker rules to restrict access to non-admins."
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_cmd("wevtutil el 2>nul")
        if out:
            self.add_finding(
                result, description="Simulated: Event log enumeration via wevtutil",
                severity=Severity.INFO, evidence=out.stdout[:500],
                recommendation="Monitor for wevtutil.exe usage (especially 'cl' clear commands)",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1029 — Remote Data Storage: Forward logs to SIEM to preserve evidence after local clearing",
            "M1047 — Audit: Enable Audit Policy Change to detect log clears (Event ID 1102)",
            "M1022 — Restrict File and Directory Permissions: Protect event log files",
            "M1038 — Execution Prevention: Restrict wevtutil.exe access via AppLocker",
        ]
