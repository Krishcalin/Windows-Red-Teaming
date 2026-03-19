"""T1134 — Access Token Manipulation.

Checks for privilege and token configuration weaknesses that
allow token impersonation, SeDebug privilege abuse, and
token theft for privilege escalation.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Dangerous privileges commonly abused for token manipulation
_DANGEROUS_PRIVILEGES = {
    "SeDebugPrivilege": (
        "Debug programs — allows reading/writing any process memory (Mimikatz)",
        Severity.CRITICAL,
    ),
    "SeImpersonatePrivilege": (
        "Impersonate a client — enables potato attacks (JuicyPotato, PrintSpoofer)",
        Severity.HIGH,
    ),
    "SeAssignPrimaryTokenPrivilege": (
        "Replace a process level token — enables token manipulation",
        Severity.HIGH,
    ),
    "SeTcbPrivilege": (
        "Act as part of the operating system — god-mode privilege",
        Severity.CRITICAL,
    ),
    "SeBackupPrivilege": (
        "Back up files/directories — bypass file ACLs to read any file",
        Severity.HIGH,
    ),
    "SeRestorePrivilege": (
        "Restore files/directories — bypass file ACLs to write any file",
        Severity.HIGH,
    ),
    "SeLoadDriverPrivilege": (
        "Load/unload device drivers — kernel-level code execution",
        Severity.CRITICAL,
    ),
    "SeTakeOwnershipPrivilege": (
        "Take ownership of files/objects — bypass ACLs by becoming owner",
        Severity.HIGH,
    ),
    "SeCreateTokenPrivilege": (
        "Create a token object — forge access tokens",
        Severity.CRITICAL,
    ),
}


class AccessTokenManipulation(BaseModule):
    """T1134 — Access Token Manipulation audit.

    Evaluates privilege assignments and token security to
    identify potential privilege escalation paths.
    """

    TECHNIQUE_ID = "T1134"
    TECHNIQUE_NAME = "Access Token Manipulation"
    TACTIC = "Privilege Escalation"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_current_privileges(session, result)
        self._check_privilege_assignments(session, result)
        self._check_token_integrity(session, result)
        self._check_privilege_audit(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_current_privileges(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check current user's token privileges."""
        privs = session.run_cmd("whoami /priv")
        if not privs or not privs.stdout:
            return

        for priv_name, (desc, sev) in _DANGEROUS_PRIVILEGES.items():
            if priv_name in privs.stdout:
                # Check if enabled
                enabled = False
                for line in privs.stdout.splitlines():
                    if priv_name in line and "Enabled" in line:
                        enabled = True
                        break

                status = "Enabled" if enabled else "Disabled (but assigned)"
                self.add_finding(
                    result,
                    description=f"Dangerous privilege assigned: {priv_name} ({status})",
                    severity=sev if enabled else Severity.MEDIUM,
                    evidence=f"Privilege: {priv_name}\nStatus: {status}\nRisk: {desc}",
                    recommendation=(
                        f"Remove {priv_name} from this account unless absolutely "
                        f"required. Even disabled privileges can be enabled by "
                        f"the token holder."
                    ),
                    cwe="CWE-250",
                )

    def _check_privilege_assignments(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check which accounts have dangerous privileges assigned via policy."""
        # Export security policy and check privilege assignments
        export = session.run_powershell(
            "secedit /export /cfg $env:TEMP\\privcheck.cfg /quiet 2>$null; "
            "Get-Content $env:TEMP\\privcheck.cfg -ErrorAction SilentlyContinue; "
            "Remove-Item $env:TEMP\\privcheck.cfg -ErrorAction SilentlyContinue"
        )
        if not export or not export.stdout:
            return

        for line in export.stdout.splitlines():
            line = line.strip()
            for priv_name in ("SeDebugPrivilege", "SeImpersonatePrivilege",
                              "SeTcbPrivilege", "SeCreateTokenPrivilege"):
                if priv_name in line and "=" in line:
                    assigned = line.split("=", 1)[1].strip()
                    # Check for non-standard assignments (not just *S-1-5-32-544 Administrators)
                    sids = [s.strip() for s in assigned.split(",")]
                    non_admin = [s for s in sids if s not in ("*S-1-5-32-544", "")]
                    if non_admin:
                        desc, sev = _DANGEROUS_PRIVILEGES.get(
                            priv_name, ("Unknown", Severity.MEDIUM)
                        )
                        self.add_finding(
                            result,
                            description=f"{priv_name} assigned to non-admin accounts via Group Policy",
                            severity=Severity.HIGH,
                            evidence=f"{priv_name} = {assigned}",
                            recommendation=(
                                f"Review and restrict {priv_name} assignment. "
                                f"Only Administrators should have this privilege."
                            ),
                            cwe="CWE-250",
                        )

    def _check_token_integrity(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check current process integrity level."""
        integrity = session.run_powershell(
            "whoami /groups | Select-String 'Mandatory Label'"
        )
        if integrity and integrity.stdout.strip():
            level = integrity.stdout.strip()
            if "Medium Mandatory Level" in level:
                self.add_finding(
                    result,
                    description="Current process runs at Medium integrity (standard user token)",
                    severity=Severity.INFO,
                    evidence=level,
                    recommendation="This is expected for non-elevated processes",
                )
            elif "High Mandatory Level" in level:
                self.add_finding(
                    result,
                    description="Current process runs at High integrity (elevated admin token)",
                    severity=Severity.LOW,
                    evidence=level,
                    recommendation=(
                        "Avoid running with elevated privileges unless required. "
                        "Use least privilege principle."
                    ),
                )

    def _check_privilege_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if privilege use auditing is enabled."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Sensitive Privilege Use' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="Sensitive Privilege Use auditing is not enabled",
                severity=Severity.MEDIUM,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Sensitive Privilege Use' (Success, Failure). "
                    "Event ID 4673/4674 tracks privilege usage. CIS Benchmark 17.8.1"
                ),
                cwe="CWE-778",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate token enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("whoami /priv", "Token privilege enumeration"),
            ("whoami /groups", "Token group and integrity enumeration"),
            ("whoami /all", "Full token information dump"),
        ]
        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Monitor for whoami and token enumeration commands",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1026 — Privileged Account Management: Restrict dangerous privilege assignments",
            "M1018 — User Account Management: Remove SeDebugPrivilege from non-admin accounts",
            "M1047 — Audit: Enable Sensitive Privilege Use auditing (Event ID 4673/4674)",
            "M1038 — Execution Prevention: Monitor for token manipulation tools (Mimikatz, Rubeus)",
        ]
