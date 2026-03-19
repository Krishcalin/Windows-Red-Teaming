"""T1069 — Permission Groups Discovery.

Checks local and domain group membership exposure, identifies
overprivileged groups, and verifies group policy hygiene.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Privileged local groups that should have minimal membership
_SENSITIVE_GROUPS = [
    "Administrators",
    "Remote Desktop Users",
    "Remote Management Users",
    "Backup Operators",
    "Hyper-V Administrators",
    "Network Configuration Operators",
]


class PermissionGroupsDiscovery(BaseModule):
    """T1069 — Permission Groups Discovery.

    Enumerates local and domain group memberships to find
    overprivileged or misconfigured access controls.
    """

    TECHNIQUE_ID = "T1069"
    TECHNIQUE_NAME = "Permission Groups Discovery"
    TACTIC = "Discovery"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── T1069.001 Local Groups ───────────────────────────────
        self._check_local_groups(session, result)

        # ── T1069.002 Domain Groups (if domain-joined) ──────────
        self._check_domain_groups(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_local_groups(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Audit membership of sensitive local groups."""
        for group in _SENSITIVE_GROUPS:
            members = session.run_powershell(
                f"Get-LocalGroupMember -Group '{group}' -ErrorAction "
                f"SilentlyContinue | Select-Object Name, ObjectClass, "
                f"PrincipalSource | ConvertTo-Json -Compress"
            )
            if not members or not members.stdout.strip():
                continue

            try:
                items = json.loads(members.stdout)
            except json.JSONDecodeError:
                continue

            if not isinstance(items, list):
                items = [items]

            member_names = [m.get("Name", "") for m in items]
            count = len(items)

            if group == "Administrators" and count > 3:
                self.add_finding(
                    result,
                    description=(
                        f"Local Administrators group has {count} members "
                        f"(excessive membership increases attack surface)"
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Members: {', '.join(member_names)}",
                    recommendation=(
                        "Limit Administrators group to named admin accounts. "
                        "Remove standard users and unnecessary service accounts."
                    ),
                    cwe="CWE-250",
                )

            if group == "Remote Desktop Users" and count > 0:
                self.add_finding(
                    result,
                    description=(
                        f"Remote Desktop Users group has {count} member(s) "
                        f"— RDP lateral movement is possible"
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Members: {', '.join(member_names)}",
                    recommendation=(
                        "Minimize Remote Desktop Users membership. "
                        "Use Network Level Authentication (NLA) and restrict "
                        "RDP via Windows Firewall."
                    ),
                )

            if group == "Backup Operators" and count > 0:
                self.add_finding(
                    result,
                    description=(
                        f"Backup Operators group has {count} member(s) "
                        f"— can bypass file ACLs to read any file"
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Members: {', '.join(member_names)}",
                    recommendation=(
                        "Audit Backup Operators membership. Members can "
                        "read/write any file regardless of NTFS permissions."
                    ),
                    cwe="CWE-732",
                )

            if group == "Remote Management Users" and count > 0:
                self.add_finding(
                    result,
                    description=(
                        f"Remote Management Users group has {count} member(s) "
                        f"— WinRM access is available"
                    ),
                    severity=Severity.LOW,
                    evidence=f"Members: {', '.join(member_names)}",
                    recommendation=(
                        "Review Remote Management Users membership. "
                        "WinRM enables PowerShell remoting for lateral movement."
                    ),
                )

    def _check_domain_groups(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check domain group enumeration exposure."""
        domain = session.run_powershell(
            "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"
        )
        if not domain or domain.stdout.strip().lower() != "true":
            return

        # Check if the current user can enumerate domain groups
        enum_test = session.run_powershell(
            "try { "
            "  ([adsisearcher]'(objectCategory=group)').FindAll().Count; "
            "  'enumerable' "
            "} catch { 'blocked' }"
        )
        if enum_test and "enumerable" in enum_test.stdout:
            count_line = enum_test.stdout.strip().splitlines()
            group_count = count_line[0] if count_line else "unknown"
            self.add_finding(
                result,
                description=(
                    f"Domain group enumeration is accessible from this host "
                    f"({group_count} groups visible)"
                ),
                severity=Severity.MEDIUM,
                evidence=f"LDAP group enumeration returned {group_count} groups",
                recommendation=(
                    "Consider tiered admin model and restrict LDAP queries "
                    "from workstation tier. Monitor for mass LDAP enumeration."
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary group enumeration commands."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("net localgroup", "Local group listing"),
            ("net localgroup Administrators", "Administrators group enumeration"),
            ("whoami /groups", "Current user group membership"),
        ]

        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Monitor for group enumeration activity",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1026 — Privileged Account Management: Minimize privileged group membership",
            "M1018 — User Account Management: Regular audit of local and domain group membership",
            "M1030 — Network Segmentation: Restrict LDAP enumeration from workstation tier",
        ]
