"""T1003.002 — OS Credential Dumping: Security Account Manager.

Checks protections around the SAM database, including file
ACLs, Volume Shadow Copy exposure, and registry backup access.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class SamDatabaseCheck(BaseModule):
    """T1003.002 — SAM Database access audit.

    Evaluates defenses against SAM database extraction via
    reg save, Volume Shadow Copy, or direct file access.
    """

    TECHNIQUE_ID = "T1003.002"
    TECHNIQUE_NAME = "OS Credential Dumping: SAM Database"
    TACTIC = "Credential Access"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_sam_backup_files(session, result)
        self._check_volume_shadow_copies(session, result)
        self._check_sam_registry_acl(session, result)
        self._check_syskey_additional_encryption(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_sam_backup_files(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for SAM/SYSTEM/SECURITY backup files in common locations."""
        backup_paths = [
            r"C:\Windows\Repair\SAM",
            r"C:\Windows\Repair\SYSTEM",
            r"C:\Windows\Repair\SECURITY",
            r"C:\Windows\System32\config\RegBack\SAM",
            r"C:\Windows\System32\config\RegBack\SYSTEM",
            r"C:\Windows\System32\config\RegBack\SECURITY",
        ]

        found: list[str] = []
        for path in backup_paths:
            if session.file_exists(path):
                found.append(path)

        if found:
            self.add_finding(
                result,
                description=f"SAM/SYSTEM/SECURITY backup files found ({len(found)} files)",
                severity=Severity.HIGH,
                evidence="\n".join(found),
                recommendation=(
                    "Remove or restrict access to SAM registry backup files. "
                    "These contain password hashes and can be extracted offline "
                    "with tools like secretsdump.py or samdump2."
                ),
                cwe="CWE-538",
            )

    def _check_volume_shadow_copies(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Volume Shadow Copies exist (SAM extraction vector)."""
        vss = session.run_powershell(
            "(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue).Count"
        )
        if vss and vss.stdout.strip().isdigit():
            count = int(vss.stdout.strip())
            if count > 0:
                self.add_finding(
                    result,
                    description=f"{count} Volume Shadow Copy/ies exist — SAM extraction possible via VSS",
                    severity=Severity.MEDIUM,
                    evidence=f"Shadow copies: {count}",
                    recommendation=(
                        "Monitor access to Volume Shadow Copies. Adversaries use "
                        "'vssadmin' or 'wmic shadowcopy' to extract SAM/SYSTEM "
                        "hive files from shadow copies."
                    ),
                    cwe="CWE-538",
                )

    def _check_sam_registry_acl(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check ACL on the SAM registry hive file."""
        acl = session.run_powershell(
            "(Get-Acl 'C:\\Windows\\System32\\config\\SAM' "
            "-ErrorAction SilentlyContinue).Access | "
            "Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' "
            "-and $_.FileSystemRights -match 'Read|FullControl' } | "
            "Select-Object IdentityReference, FileSystemRights | "
            "ConvertTo-Json -Compress"
        )
        if acl and acl.stdout.strip() and acl.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Non-admin users have read access to the SAM registry hive file",
                severity=Severity.CRITICAL,
                evidence=acl.stdout[:500],
                recommendation=(
                    "Restrict ACLs on C:\\Windows\\System32\\config\\SAM. "
                    "Only SYSTEM and Administrators should have access. "
                    "Check CVE-2021-36934 (HiveNightmare/SeriousSAM) patching."
                ),
                cwe="CWE-732",
            )

    def _check_syskey_additional_encryption(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if SAM encryption uses additional boot key protections."""
        # SecureBoot check — SYSKEY was deprecated in Windows 10 1709+
        # but check if the system is old enough to still be vulnerable
        build = session.run_powershell(
            "(Get-CimInstance Win32_OperatingSystem).BuildNumber"
        )
        if build and build.stdout.strip().isdigit():
            build_num = int(build.stdout.strip())
            if build_num < 16299:  # Pre-1709
                self.add_finding(
                    result,
                    description=(
                        f"OS build {build_num} predates SYSKEY deprecation — "
                        f"additional SAM encryption features may apply"
                    ),
                    severity=Severity.LOW,
                    evidence=f"BuildNumber = {build_num}",
                    recommendation="Upgrade to Windows 10 1709+ or Server 2019+ for modern SAM protections",
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate SAM database enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("reg query HKLM\\SAM\\SAM 2>nul",
             "SAM registry hive access test"),
            ("vssadmin list shadows 2>nul",
             "Volume Shadow Copy enumeration"),
        ]
        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500] if out.stdout else out.stderr[:500],
                    recommendation="Monitor for SAM/SYSTEM hive access and VSS manipulation",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1026 — Privileged Account Management: Restrict administrative access to SAM hive files",
            "M1022 — Restrict File and Directory Permissions: Lock down SAM/SYSTEM/SECURITY file ACLs",
            "M1028 — Operating System Configuration: Patch CVE-2021-36934 (HiveNightmare)",
            "M1047 — Audit: Monitor registry hive access and VSS operations",
        ]
