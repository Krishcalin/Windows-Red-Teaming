"""T1490 — Inhibit System Recovery.

Ransomware and destructive actors delete shadow copies, disable Windows
Recovery Environment, and turn off automatic repair so victims cannot restore
without paying. This module is a ransomware-readiness audit: it passively
verifies that recovery capabilities are present and intact, and flags the
tampering patterns associated with this technique.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class InhibitRecoveryCheck(BaseModule):
    """Audit system-recovery posture against inhibition (T1490)."""

    TECHNIQUE_ID = "T1490"
    TECHNIQUE_NAME = "Inhibit System Recovery"
    TACTIC = "Impact"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [
        OSType.WIN10, OSType.WIN11,
        OSType.SERVER_2019, OSType.SERVER_2022,
    ]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_shadow_copies(session, result)
        self._check_vss_service(session, result)
        self._check_winre(session, result)
        self._check_boot_recovery(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_shadow_copies(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Volume Shadow Copies are the first thing ransomware deletes."""
        shadows = session.run_powershell(
            "Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue | "
            "Measure-Object | Select-Object -ExpandProperty Count"
        )
        count = shadows.stdout.strip() if shadows and shadows.stdout else ""
        if count.isdigit() and int(count) > 0:
            self.add_finding(
                result,
                description=f"Volume Shadow Copies present ({count}) — recovery snapshots available",
                severity=Severity.INFO,
                evidence=f"Win32_ShadowCopy count = {count}",
                recommendation="Ensure shadow copies are protected and backed up off-host.",
            )
        else:
            self.add_finding(
                result,
                description="No Volume Shadow Copies present — no local recovery snapshots (ransomware-inhibited state)",
                severity=Severity.HIGH,
                evidence="Win32_ShadowCopy count = 0",
                recommendation=(
                    "Enable and schedule shadow copies / System Protection, and "
                    "maintain off-host backups. Absent snapshots may also indicate "
                    "deletion via vssadmin/wmic."
                ),
                cwe="CWE-693",
            )

    def _check_vss_service(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """A disabled VSS service prevents new snapshots from ever being created."""
        vss = session.run_powershell(
            "Get-Service -Name VSS -ErrorAction SilentlyContinue | "
            "Select-Object Status, StartType | ConvertTo-Json -Compress"
        )
        out = vss.stdout if vss and vss.stdout else ""
        if out and '"StartType":"Disabled"' in out.replace(" ", ""):
            self.add_finding(
                result,
                description="Volume Shadow Copy service (VSS) start type is Disabled — snapshots cannot be created",
                severity=Severity.HIGH,
                evidence=out[:300],
                recommendation="Set the VSS service to Manual (default) so shadow copies can be created.",
                cwe="CWE-693",
            )
        elif out:
            self.add_finding(
                result,
                description="Volume Shadow Copy service (VSS) is configured normally",
                severity=Severity.INFO,
                evidence=out[:300],
                recommendation="No action required.",
            )

    def _check_winre(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Windows Recovery Environment enables offline repair/restore."""
        winre = session.run_powershell("reagentc /info 2>$null")
        out = winre.stdout if winre and winre.stdout else ""
        if out and "Disabled" in out and "Windows RE" in out:
            self.add_finding(
                result,
                description="Windows Recovery Environment (WinRE) is disabled — offline recovery unavailable",
                severity=Severity.MEDIUM,
                evidence=out[:400],
                recommendation="Re-enable WinRE with 'reagentc /enable'.",
                cwe="CWE-693",
            )
        elif out and "Enabled" in out:
            self.add_finding(
                result,
                description="Windows Recovery Environment (WinRE) is enabled",
                severity=Severity.INFO,
                evidence=out[:400],
                recommendation="No action required.",
            )

    def _check_boot_recovery(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Ransomware runs bcdedit to ignore failures and disable recovery."""
        bcd = session.run_powershell("bcdedit /enum '{default}' 2>$null")
        out = bcd.stdout if bcd and bcd.stdout else ""
        lowered = out.lower()
        if "ignoreallfailures" in lowered:
            self.add_finding(
                result,
                description="Boot status policy set to ignoreallfailures — automatic recovery suppressed (T1490 tampering)",
                severity=Severity.HIGH,
                evidence=out[:500],
                recommendation=(
                    "Restore default boot recovery: "
                    "'bcdedit /set {default} bootstatuspolicy DisplayAllFailures' and "
                    "'bcdedit /set {default} recoveryenabled Yes'."
                ),
                cwe="CWE-693",
            )
        elif "recoveryenabled" in lowered and "no" in lowered:
            self.add_finding(
                result,
                description="Boot recovery is disabled (recoveryenabled No) — possible recovery inhibition",
                severity=Severity.MEDIUM,
                evidence=out[:500],
                recommendation="Re-enable with 'bcdedit /set {default} recoveryenabled Yes'.",
                cwe="CWE-693",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        enum = session.run_powershell(
            "Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | "
            "Select-Object -First 3 ID, InstallDate | ConvertTo-Json -Compress"
        )
        self.add_finding(
            result,
            description="Simulated: enumerated shadow copies and recovery configuration (read-only, nothing deleted)",
            severity=Severity.INFO,
            evidence=(enum.stdout[:400] if enum and enum.stdout else "read-only enumeration"),
            recommendation=(
                "Alert on vssadmin/wmic shadowcopy delete, wbadmin delete, and "
                "bcdedit recovery changes (Event IDs 524, 4688)."
            ),
        )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1053 — Data Backup: Maintain tested, off-host (immutable) backups outside the reach of attackers",
            "M1028 — Operating System Configuration: Keep VSS, System Protection, and WinRE enabled",
            "M1018 — User Account Management: Restrict admin rights needed to delete shadow copies",
            "M1040 — Behavior Prevention on Endpoint: Block/alert on vssadmin and wbadmin deletion behavior",
            "M1047 — Audit: Monitor for shadow copy deletion and bcdedit recovery tampering",
        ]
