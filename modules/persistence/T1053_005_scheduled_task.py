"""T1053.005 — Scheduled Task/Job: Scheduled Task.

Audits scheduled tasks for suspicious entries, checks task
folder permissions, and evaluates task creation auditing.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Task paths that are normal and expected
_KNOWN_SAFE_PREFIXES = (
    "\\Microsoft\\",
    "\\Google\\",
    "\\Mozilla\\",
    "\\Adobe\\",
)


class ScheduledTaskCheck(BaseModule):
    """T1053.005 — Scheduled Task audit.

    Reviews scheduled tasks for persistence indicators,
    unusual task authors, and SYSTEM-level task abuse.
    """

    TECHNIQUE_ID = "T1053.005"
    TECHNIQUE_NAME = "Scheduled Task/Job: Scheduled Task"
    TACTIC = "Persistence"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_suspicious_tasks(session, result)
        self._check_task_folder_permissions(session, result)
        self._check_task_creation_audit(session, result)
        self._check_at_service(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_suspicious_tasks(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Identify potentially suspicious scheduled tasks."""
        tasks = session.run_powershell(
            "Get-ScheduledTask -ErrorAction SilentlyContinue | "
            "Where-Object { $_.State -ne 'Disabled' } | "
            "Select-Object TaskName, TaskPath, Author, "
            "@{N='Action';E={($_.Actions | Select-Object -First 1).Execute}}, "
            "@{N='RunAs';E={$_.Principal.UserId}} | "
            "ConvertTo-Json -Compress"
        )
        if not tasks or not tasks.stdout.strip():
            return

        try:
            task_list = json.loads(tasks.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(task_list, list):
            task_list = [task_list]

        suspicious_count = 0
        for task in task_list:
            name = task.get("TaskName", "")
            path = task.get("TaskPath", "")
            action = task.get("Action", "") or ""
            run_as = task.get("RunAs", "") or ""
            author = task.get("Author", "") or ""

            # Skip known-safe task prefixes
            if any(path.startswith(prefix) for prefix in _KNOWN_SAFE_PREFIXES):
                continue

            # Flag tasks running as SYSTEM from non-standard paths
            is_system = "system" in run_as.lower()
            is_root = path == "\\" or not any(
                path.startswith(p) for p in _KNOWN_SAFE_PREFIXES
            )
            action_lower = action.lower()
            has_suspicious_action = any(
                s in action_lower
                for s in ("powershell", "cmd", "wscript", "cscript",
                          "mshta", "regsvr32", "rundll32", "certutil",
                          "bitsadmin", "http://", "https://", "\\\\")
            )

            if is_system and is_root and has_suspicious_action:
                self.add_finding(
                    result,
                    description=f"Suspicious SYSTEM-level scheduled task: {name}",
                    severity=Severity.HIGH,
                    evidence=(
                        f"Task: {path}{name}\nAction: {action}\n"
                        f"RunAs: {run_as}\nAuthor: {author}"
                    ),
                    recommendation=(
                        f"Investigate task '{name}'. SYSTEM-level tasks running "
                        f"scripting engines from non-standard paths may indicate persistence."
                    ),
                    cwe="CWE-284",
                )
                suspicious_count += 1

            elif is_root and has_suspicious_action:
                self.add_finding(
                    result,
                    description=f"Non-standard scheduled task with scripting action: {name}",
                    severity=Severity.MEDIUM,
                    evidence=(
                        f"Task: {path}{name}\nAction: {action}\n"
                        f"RunAs: {run_as}\nAuthor: {author}"
                    ),
                    recommendation=f"Review task '{name}' for legitimate purpose",
                )
                suspicious_count += 1

            if suspicious_count >= 10:
                break

    def _check_task_folder_permissions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check permissions on the scheduled task XML folder."""
        acl = session.run_powershell(
            "$path = 'C:\\Windows\\System32\\Tasks'; "
            "(Get-Acl $path -ErrorAction SilentlyContinue).Access | "
            "Where-Object { "
            "  $_.IdentityReference -match 'Everyone|Users|Authenticated Users' "
            "  -and $_.FileSystemRights -match 'Write|Modify|FullControl' "
            "} | Select-Object IdentityReference, FileSystemRights | "
            "ConvertTo-Json -Compress"
        )
        if acl and acl.stdout.strip() and acl.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Scheduled Tasks folder has weak permissions (task injection risk)",
                severity=Severity.HIGH,
                evidence=acl.stdout[:500],
                recommendation=(
                    "Fix permissions on C:\\Windows\\System32\\Tasks. "
                    "Non-admin users should not have write access."
                ),
                cwe="CWE-732",
            )

    def _check_task_creation_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if scheduled task creation is audited."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Other Object Access Events' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="Scheduled task creation auditing is not enabled",
                severity=Severity.MEDIUM,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Other Object Access Events' to log "
                    "task creation (Event ID 4698) and deletion (4699)"
                ),
                cwe="CWE-778",
            )

    def _check_at_service(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if the legacy 'at' scheduler is accessible."""
        at = session.run_cmd("at 2>nul")
        if at and at.return_code == 0 and "denied" not in at.stdout.lower():
            self.add_finding(
                result,
                description="Legacy 'at' command scheduler is accessible",
                severity=Severity.LOW,
                evidence=at.stdout[:200],
                recommendation=(
                    "The 'at' command is a legacy scheduler. Restrict access "
                    "and monitor for at.exe usage in process creation logs."
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_cmd("schtasks /query /fo CSV /v 2>nul")
        if out:
            self.add_finding(
                result, description="Simulated: Scheduled task enumeration",
                severity=Severity.INFO, evidence=out.stdout[:500],
                recommendation="Monitor schtasks.exe usage and Event ID 4698/4699",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1026 — Privileged Account Management: Restrict who can create scheduled tasks",
            "M1047 — Audit: Enable task creation auditing (Event ID 4698/4699)",
            "M1022 — Restrict File and Directory Permissions: Protect task XML folder",
            "M1028 — Operating System Configuration: Disable legacy 'at' scheduler",
        ]
