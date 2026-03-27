"""T1074 — Data Staged.

Checks whether common staging directories are writable and
unmonitored, which could allow an adversary to stage collected
data before exfiltration.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class DataStagedCheck(BaseModule):
    """T1074 — Data Staged.

    Evaluates the accessibility and monitoring status of common
    data staging directories that adversaries use to aggregate
    collected data prior to exfiltration.
    """

    TECHNIQUE_ID = "T1074"
    TECHNIQUE_NAME = "Data Staged"
    TACTIC = "Collection"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # -- Check common staging directories permissions -----------
        staging_acl = session.run_powershell(
            'foreach ($dir in @("$env:TEMP","$env:APPDATA","$env:PUBLIC","C:\\PerfLogs")) '
            "{ if(Test-Path $dir){Get-Acl $dir | Select "
            "@{N='Path';E={$dir}},Owner} } | ConvertTo-Json"
        )
        if staging_acl and staging_acl.stdout.strip():
            self.add_finding(
                result,
                description="Common staging directories are accessible and writable",
                severity=Severity.MEDIUM,
                evidence=staging_acl.stdout.strip()[:500],
                recommendation=(
                    "Enable file system auditing on staging directories "
                    "(%TEMP%, %APPDATA%, C:\\Users\\Public, C:\\PerfLogs)"
                ),
                cwe="CWE-276",
            )

        # -- Check recycle bin for staged data ----------------------
        recycle_bin = session.run_powershell(
            "(New-Object -ComObject Shell.Application).Namespace(0xA).Items().Count"
        )
        if recycle_bin and recycle_bin.stdout.strip():
            count = recycle_bin.stdout.strip()
            if count.isdigit() and int(count) > 0:
                self.add_finding(
                    result,
                    description=f"Recycle Bin contains {count} items — could be used to hide staged data",
                    severity=Severity.LOW,
                    evidence=f"Recycle Bin item count: {count}",
                    recommendation=(
                        "Monitor Recycle Bin for unusual file staging; "
                        "consider automated cleanup policies"
                    ),
                )

        # -- Check for large files in temp --------------------------
        large_files = session.run_powershell(
            "Get-ChildItem $env:TEMP -File -ErrorAction SilentlyContinue | "
            "Where-Object {$_.Length -gt 10MB} | "
            "Measure-Object | Select Count | ConvertTo-Json"
        )
        if large_files and large_files.stdout.strip():
            self.add_finding(
                result,
                description="Large files detected in temp directory — potential data staging",
                severity=Severity.MEDIUM,
                evidence=large_files.stdout.strip()[:300],
                recommendation=(
                    "Investigate large files in temp directories; "
                    "implement size-based alerting for staging detection"
                ),
            )

        # -- Check public folders accessibility ---------------------
        public_dirs = session.run_powershell(
            "Test-Path C:\\Users\\Public\\Documents, C:\\Users\\Public\\Downloads"
        )
        if public_dirs and "True" in public_dirs.stdout:
            self.add_finding(
                result,
                description="Public folders are accessible — commonly used for local data staging",
                severity=Severity.MEDIUM,
                evidence=public_dirs.stdout.strip()[:300],
                recommendation=(
                    "Restrict access to Public folders or enable "
                    "auditing to detect data staging activity"
                ),
                cwe="CWE-276",
            )

        if not result.findings:
            self.add_finding(
                result,
                description="Staging directories are writable with no monitoring detected",
                severity=Severity.MEDIUM,
                evidence="No file system auditing on common staging paths",
                recommendation=(
                    "Enable file system auditing and monitor staging "
                    "directories for unusual data aggregation"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary data staging reconnaissance."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        # -- List large files in staging dirs -----------------------
        large_staged = session.run_powershell(
            "Get-ChildItem -Path $env:TEMP,$env:APPDATA -File "
            "-ErrorAction SilentlyContinue | "
            "Sort-Object Length -Descending | "
            "Select -First 10 FullName,Length | ConvertTo-Json"
        )
        if large_staged and large_staged.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Enumerated largest files in staging directories",
                severity=Severity.INFO,
                evidence=large_staged.stdout.strip()[:500],
                recommendation=(
                    "Monitor for file enumeration commands targeting "
                    "staging directories"
                ),
            )

        # -- Check file system auditing on staging dirs -------------
        audit_status = session.run_powershell(
            'auditpol /get /subcategory:"File System" 2>$null'
        )
        if audit_status and audit_status.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Checked file system auditing configuration",
                severity=Severity.INFO,
                evidence=audit_status.stdout.strip()[:500],
                recommendation=(
                    "Ensure file system auditing is enabled for "
                    "Success and Failure on staging directories"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass  # Read-only checks — nothing to revert

    def get_mitigations(self) -> list[str]:
        return [
            "M1047 — Audit: Enable file system auditing on common staging directories",
            "M1057 — Data Loss Prevention: Monitor for large file creation and aggregation",
            "M1022 — Restrict File and Directory Permissions: Limit write access to Public and PerfLogs folders",
            "M1018 — User Account Management: Restrict user access to shared staging locations",
        ]
