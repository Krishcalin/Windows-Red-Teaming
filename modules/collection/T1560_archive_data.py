"""T1560 — Archive Collected Data.

Checks for available archive/compression tools that an adversary
could use to stage and compress collected data before exfiltration.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class ArchiveDataCheck(BaseModule):
    """T1560 — Archive Collected Data.

    Evaluates the availability of archive and compression utilities
    that could be leveraged to package collected data for
    exfiltration staging.
    """

    TECHNIQUE_ID = "T1560"
    TECHNIQUE_NAME = "Archive Collected Data"
    TACTIC = "Collection"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # -- Check available archive tools --------------------------
        archive_tools = session.run_powershell(
            "Get-Command Compress-Archive,tar,7z,rar,zip "
            "-ErrorAction SilentlyContinue | Select Name,Source | ConvertTo-Json"
        )
        if archive_tools and archive_tools.stdout.strip():
            self.add_finding(
                result,
                description="Archive/compression tools are available on the system",
                severity=Severity.MEDIUM,
                evidence=archive_tools.stdout.strip()[:500],
                recommendation=(
                    "Restrict access to compression utilities via "
                    "application whitelisting on sensitive systems"
                ),
            )

        # -- Check if makecab available -----------------------------
        makecab = session.run_cmd("where makecab")
        if makecab and makecab.return_code == 0:
            self.add_finding(
                result,
                description="makecab.exe is available — can be used to create CAB archives",
                severity=Severity.LOW,
                evidence=makecab.stdout.strip()[:300],
                recommendation=(
                    "Monitor makecab.exe usage; it is a living-off-the-land "
                    "binary (LOLBin) that can compress and stage data"
                ),
            )

        # -- Check WinRAR/7-Zip installation ------------------------
        seven_zip = session.run_cmd('reg query "HKLM\\SOFTWARE\\7-Zip" /v Path')
        if seven_zip and seven_zip.return_code == 0:
            self.add_finding(
                result,
                description="7-Zip is installed on the system",
                severity=Severity.MEDIUM,
                evidence=seven_zip.stdout.strip()[:300],
                recommendation=(
                    "Audit 7-Zip usage and consider removing from "
                    "systems where it is not operationally required"
                ),
            )

        winrar = session.run_cmd('reg query "HKLM\\SOFTWARE\\WinRAR"')
        if winrar and winrar.return_code == 0:
            self.add_finding(
                result,
                description="WinRAR is installed on the system",
                severity=Severity.MEDIUM,
                evidence=winrar.stdout.strip()[:300],
                recommendation=(
                    "Audit WinRAR usage and consider removing from "
                    "systems where it is not operationally required"
                ),
            )

        # -- Check temp directory permissions (staging area) --------
        temp_acl = session.run_powershell(
            "Get-Acl $env:TEMP | Select Owner,AccessToString | ConvertTo-Json"
        )
        if temp_acl and temp_acl.stdout.strip():
            self.add_finding(
                result,
                description="Temp directory is accessible — commonly used as archive staging area",
                severity=Severity.LOW,
                evidence=temp_acl.stdout.strip()[:500],
                recommendation=(
                    "Monitor file creation in temp directories, especially "
                    "archive file types (.zip, .7z, .rar, .cab)"
                ),
            )

        if not result.findings:
            self.add_finding(
                result,
                description="Multiple archive tools available for data compression and exfiltration staging",
                severity=Severity.MEDIUM,
                evidence="Default Windows compression utilities are present",
                recommendation=(
                    "Implement monitoring for archive creation in "
                    "staging directories and restrict unnecessary tools"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary archive reconnaissance."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        # -- List archive file types in common locations -------------
        archives = session.run_powershell(
            "Get-ChildItem -Path $env:USERPROFILE -Recurse "
            "-Include *.zip,*.7z,*.rar,*.cab "
            "-ErrorAction SilentlyContinue | "
            "Select FullName,Length | ConvertTo-Json"
        )
        if archives and archives.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Found existing archive files in user profile",
                severity=Severity.INFO,
                evidence=archives.stdout.strip()[:500],
                recommendation=(
                    "Monitor for unusual archive file creation and "
                    "audit existing archives in user directories"
                ),
            )

        # -- Check for recently created archives ---------------------
        recent = session.run_powershell(
            "Get-ChildItem -Path $env:TEMP -Include *.zip,*.7z,*.rar "
            "-Recurse -ErrorAction SilentlyContinue | "
            "Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-7)} | "
            "Select FullName,CreationTime | ConvertTo-Json"
        )
        if recent and recent.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Found recently created archives in temp directory",
                severity=Severity.INFO,
                evidence=recent.stdout.strip()[:500],
                recommendation=(
                    "Investigate recent archive creation in temp "
                    "directories for potential data staging activity"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass  # Read-only checks — nothing to revert

    def get_mitigations(self) -> list[str]:
        return [
            "M1042 — Disable or Remove Feature or Program: Remove unnecessary archive utilities",
            "M1038 — Execution Prevention: Use AppLocker/WDAC to restrict compression tool execution",
            "M1057 — Data Loss Prevention: Monitor for archive creation in staging directories",
            "M1047 — Audit: Enable file system auditing on temp and staging directories",
        ]
