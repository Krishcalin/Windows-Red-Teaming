"""T1486 — Data Encrypted for Impact.

Checks ransomware resilience by evaluating shadow copy status,
controlled folder access, backup configuration, and volume
shadow copy service availability.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class DataEncryptedForImpactCheck(BaseModule):
    """T1486 — Data Encrypted for Impact audit.

    Evaluates the system's resilience against ransomware-style
    encryption attacks by checking backup and recovery controls.
    """

    TECHNIQUE_ID = "T1486"
    TECHNIQUE_NAME = "Data Encrypted for Impact"
    TACTIC = "Impact"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_vss_service(session, result)
        self._check_shadow_copies(session, result)
        self._check_controlled_folder_access(session, result)
        self._check_backup_config(session, result)
        self._check_vssadmin_accessible(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_vss_service(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Volume Shadow Copy service status."""
        vss = session.run_powershell(
            "Get-Service VSS | Select-Object Status,StartType | ConvertTo-Json"
        )
        if not vss or not vss.stdout.strip():
            self.add_finding(
                result,
                description="Volume Shadow Copy (VSS) service not found",
                severity=Severity.CRITICAL,
                evidence="VSS service query returned no results",
                recommendation=(
                    "Ensure the Volume Shadow Copy service is installed "
                    "and set to Manual or Automatic start type"
                ),
                cwe="CWE-693",
            )
            return

        try:
            svc = json.loads(vss.stdout)
        except json.JSONDecodeError:
            return

        status = str(svc.get("Status", ""))
        start_type = str(svc.get("StartType", ""))

        # VSS is typically Manual start (on-demand) which is acceptable
        if start_type in ("4", "Disabled"):
            self.add_finding(
                result,
                description="Volume Shadow Copy service is disabled",
                severity=Severity.HIGH,
                evidence=f"VSS Status: {status}, StartType: {start_type}",
                recommendation=(
                    "Set VSS service to Manual or Automatic start type to "
                    "allow shadow copy creation for backup and recovery"
                ),
                cwe="CWE-693",
            )

    def _check_shadow_copies(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for existing shadow copies."""
        shadows = session.run_powershell(
            "Get-CimInstance Win32_ShadowCopy | Measure-Object | "
            "Select-Object Count | ConvertTo-Json"
        )
        if not shadows or not shadows.stdout.strip():
            self.add_finding(
                result,
                description="No volume shadow copies exist on the system",
                severity=Severity.HIGH,
                evidence="Shadow copy query returned no results",
                recommendation=(
                    "Configure scheduled shadow copies to enable system "
                    "recovery. Ransomware commonly deletes shadow copies "
                    "before encrypting files."
                ),
                cwe="CWE-693",
            )
            return

        try:
            data = json.loads(shadows.stdout)
        except json.JSONDecodeError:
            return

        count = data.get("Count", 0)
        if count == 0:
            self.add_finding(
                result,
                description="No volume shadow copies exist on the system",
                severity=Severity.HIGH,
                evidence=f"Shadow copy count: {count}",
                recommendation=(
                    "Configure scheduled shadow copies. Ransomware commonly "
                    "deletes shadow copies before encrypting files."
                ),
                cwe="CWE-693",
            )

    def _check_controlled_folder_access(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if controlled folder access (ransomware protection) is enabled."""
        cfa = session.run_powershell(
            "Get-MpPreference | "
            "Select-Object EnableControlledFolderAccess | ConvertTo-Json"
        )
        if not cfa or not cfa.stdout.strip():
            return

        try:
            data = json.loads(cfa.stdout)
        except json.JSONDecodeError:
            return

        enabled = data.get("EnableControlledFolderAccess", 0)
        if str(enabled) in ("0", "False", "Disabled"):
            self.add_finding(
                result,
                description="Controlled Folder Access (ransomware protection) is disabled",
                severity=Severity.CRITICAL,
                evidence=f"EnableControlledFolderAccess = {enabled}",
                recommendation=(
                    "Enable Controlled Folder Access via Windows Security, "
                    "GPO, or Intune to protect documents, pictures, and "
                    "other folders from unauthorized modification."
                ),
                cwe="CWE-693",
            )

    def _check_backup_config(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check system restore / backup configuration."""
        backup = session.run_cmd(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT'
            '\\CurrentVersion\\SystemRestore" /v RPSessionInterval'
        )
        if not backup or "RPSessionInterval" not in backup.stdout:
            self.add_finding(
                result,
                description="System Restore configuration not found or not configured",
                severity=Severity.MEDIUM,
                evidence="RPSessionInterval registry value not found",
                recommendation=(
                    "Configure System Restore with regular restore point "
                    "creation. Ensure backup solutions are in place and "
                    "tested regularly."
                ),
            )
            return

        # Check if interval is 0 (disabled)
        if "0x0" in backup.stdout:
            self.add_finding(
                result,
                description="System Restore session interval is set to 0 (disabled)",
                severity=Severity.MEDIUM,
                evidence=backup.stdout.strip()[:300],
                recommendation=(
                    "Set RPSessionInterval to a non-zero value to enable "
                    "automatic restore point creation"
                ),
            )

    def _check_vssadmin_accessible(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if vssadmin is accessible (used by ransomware to delete shadow copies)."""
        vssadmin = session.run_cmd("where vssadmin")
        if vssadmin and vssadmin.stdout.strip():
            self.add_finding(
                result,
                description="vssadmin.exe is accessible and can be used to delete shadow copies",
                severity=Severity.MEDIUM,
                evidence=f"vssadmin path: {vssadmin.stdout.strip()[:200]}",
                recommendation=(
                    "Consider restricting access to vssadmin.exe via "
                    "AppLocker or WDAC policies. Ransomware commonly uses "
                    "'vssadmin delete shadows /all /quiet' to remove backups."
                ),
                cwe="CWE-284",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        # List shadow copies
        shadows = session.run_cmd("vssadmin list shadows")
        if shadows:
            self.add_finding(
                result,
                description="Simulated: Listed existing volume shadow copies",
                severity=Severity.INFO,
                evidence=shadows.stdout.strip()[:500],
                recommendation="Monitor for vssadmin shadow copy enumeration and deletion",
            )

        # Check protected folders
        folders = session.run_powershell(
            "(Get-MpPreference).ControlledFolderAccessProtectedFolders"
        )
        if folders:
            self.add_finding(
                result,
                description="Simulated: Enumerated controlled folder access protected folders",
                severity=Severity.INFO,
                evidence=folders.stdout.strip()[:500],
                recommendation="Monitor for ransomware protection configuration queries",
            )

        # Check ransomware protection status
        status = session.run_powershell(
            "Get-MpComputerStatus | "
            "Select-Object RealTimeProtectionEnabled,IoavProtectionEnabled | "
            "ConvertTo-Json"
        )
        if status:
            self.add_finding(
                result,
                description="Simulated: Queried ransomware protection status",
                severity=Severity.INFO,
                evidence=status.stdout.strip()[:500],
                recommendation="Monitor for Defender protection status enumeration",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1053 — Data Backup: Maintain offline backups not accessible from the network",
            "M1049 — Antivirus/Antimalware: Enable Controlled Folder Access for ransomware protection",
            "M1038 — Execution Prevention: Use AppLocker/WDAC to restrict vssadmin.exe access",
            "M1047 — Audit: Monitor for shadow copy deletion and mass file modification events",
        ]
