"""T1003.003 — OS Credential Dumping: NTDS.dit.

Checks protections around the Active Directory database file
(NTDS.dit) on Domain Controllers, including access controls,
backup exposure, and DCSync permissions.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class NtdsDitCheck(BaseModule):
    """T1003.003 — NTDS.dit access audit.

    Evaluates defenses against NTDS.dit extraction and
    DCSync attacks on Domain Controllers.
    """

    TECHNIQUE_ID = "T1003.003"
    TECHNIQUE_NAME = "OS Credential Dumping: NTDS.dit"
    TACTIC = "Credential Access"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # First check if this is a Domain Controller
        is_dc = self._is_domain_controller(session)
        if not is_dc:
            return self.skip_result(
                "Target is not a Domain Controller — NTDS.dit checks not applicable",
                target_host=session.target.host,
            )

        self._check_ntds_file_access(session, result)
        self._check_ntds_backup_files(session, result)
        self._check_volume_shadow_copies(session, result)
        self._check_dcsync_permissions(session, result)
        self._check_directory_replication_audit(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _is_domain_controller(self, session: BaseSession) -> bool:
        """Determine if the target is a Domain Controller."""
        dc_check = session.run_powershell(
            "(Get-CimInstance Win32_ComputerSystem).DomainRole"
        )
        if dc_check and dc_check.stdout.strip().isdigit():
            role = int(dc_check.stdout.strip())
            # 4 = Backup DC, 5 = Primary DC
            return role >= 4
        return False

    def _check_ntds_file_access(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check access controls on the NTDS.dit file."""
        ntds_path = r"C:\Windows\NTDS\ntds.dit"
        exists = session.file_exists(ntds_path)
        if not exists:
            return

        acl = session.run_powershell(
            f"(Get-Acl '{ntds_path}' -ErrorAction SilentlyContinue).Access | "
            f"Where-Object {{ $_.IdentityReference -notmatch "
            f"'NT AUTHORITY\\\\SYSTEM|BUILTIN\\\\Administrators' }} | "
            f"Select-Object IdentityReference, FileSystemRights | "
            f"ConvertTo-Json -Compress"
        )
        if acl and acl.stdout.strip() and acl.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Non-standard ACL entries found on NTDS.dit",
                severity=Severity.CRITICAL,
                evidence=acl.stdout[:500],
                recommendation=(
                    "Only SYSTEM and Administrators should have access to NTDS.dit. "
                    "Remove all other ACL entries."
                ),
                cwe="CWE-732",
            )

    def _check_ntds_backup_files(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for NTDS.dit backup or copy files."""
        search = session.run_powershell(
            "Get-ChildItem -Path C:\\ -Filter 'ntds.dit' -Recurse "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.DirectoryName -ne 'C:\\Windows\\NTDS' } | "
            "Select-Object -ExpandProperty FullName"
        )
        if search and search.stdout.strip():
            self.add_finding(
                result,
                description="NTDS.dit copies found outside the default directory",
                severity=Severity.CRITICAL,
                evidence=search.stdout.strip(),
                recommendation=(
                    "Remove NTDS.dit copies immediately. These contain all domain "
                    "password hashes and can be cracked offline."
                ),
                cwe="CWE-538",
            )

    def _check_volume_shadow_copies(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for VSS that could expose NTDS.dit."""
        vss = session.run_powershell(
            "(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue).Count"
        )
        if vss and vss.stdout.strip().isdigit():
            count = int(vss.stdout.strip())
            if count > 0:
                self.add_finding(
                    result,
                    description=f"{count} Volume Shadow Copies on DC — NTDS.dit extractable via VSS",
                    severity=Severity.MEDIUM,
                    evidence=f"Shadow copies: {count}",
                    recommendation=(
                        "Monitor vssadmin/wmic shadowcopy usage on DCs. "
                        "Attackers use VSS to extract a locked NTDS.dit file. "
                        "Consider restricting VSS access on DCs."
                    ),
                )

    def _check_dcsync_permissions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for non-DC accounts with DCSync (replication) permissions."""
        dcsync = session.run_powershell(
            "$domain = [System.DirectoryServices.ActiveDirectory.Domain]"
            "::GetCurrentDomain().Name; "
            "$dn = (([adsi]'').distinguishedName); "
            "$acl = (Get-Acl \"AD:\\$dn\" -ErrorAction SilentlyContinue).Access; "
            "$acl | Where-Object { "
            "  ($_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or "
            "   $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') -and "
            "  $_.IdentityReference -notmatch 'Domain Controllers|Enterprise Admins|Administrators' "
            "} | Select-Object IdentityReference, ActiveDirectoryRights | "
            "ConvertTo-Json -Compress"
        )
        if dcsync and dcsync.stdout.strip() and dcsync.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Non-standard accounts have DCSync (directory replication) permissions",
                severity=Severity.CRITICAL,
                evidence=dcsync.stdout[:500],
                recommendation=(
                    "Remove DS-Replication-Get-Changes and DS-Replication-Get-Changes-All "
                    "permissions from non-DC accounts. Only Domain Controllers and "
                    "Enterprise Admins should have replication rights."
                ),
                cwe="CWE-732",
            )

    def _check_directory_replication_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Directory Service access auditing is enabled."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Directory Service Access' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="Directory Service Access auditing is not enabled on this DC",
                severity=Severity.HIGH,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Directory Service Access' (Success, Failure) "
                    "to detect DCSync attacks. Event ID 4662 with replication "
                    "GUIDs indicates DCSync activity."
                ),
                cwe="CWE-778",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate NTDS.dit enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("dir C:\\Windows\\NTDS\\ 2>nul",
             "NTDS directory listing"),
            ("ntdsutil \"activate instance ntds\" ifm \"create full C:\\temp\" quit quit 2>nul",
             "NTDS IFM creation attempt (will fail without privileges)"),
        ]
        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500] if out.stdout else out.stderr[:300],
                    recommendation="Monitor for ntdsutil, vssadmin, and DCSync activity on DCs",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1026 — Privileged Account Management: Restrict DCSync permissions to DCs and Enterprise Admins only",
            "M1022 — Restrict File and Directory Permissions: Lock down NTDS.dit and backup ACLs",
            "M1047 — Audit: Enable Directory Service Access auditing (Event ID 4662)",
            "M1027 — Password Policies: Use strong passwords and rotate KRBTGT regularly",
        ]
