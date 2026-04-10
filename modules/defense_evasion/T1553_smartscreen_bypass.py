"""CVE-2026-21510 — Windows Shell SmartScreen Bypass.

Checks for the Windows Shell vulnerability (CVE-2026-21510, CVSS 8.8) that
bypasses SmartScreen and Shell security prompts. Actively exploited and
publicly disclosed.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class SmartScreenBypassCheck(BaseModule):
    """CVE-2026-21510 — SmartScreen bypass audit.

    Evaluates Windows SmartScreen and Defender Application Guard
    settings for the actively exploited Shell security prompt bypass.
    """

    TECHNIQUE_ID = "T1553.005"
    TECHNIQUE_NAME = "Subvert Trust Controls: Mark-of-the-Web Bypass (CVE-2026-21510)"
    TACTIC = "Defense Evasion"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_patch_installed(session, result)
        self._check_smartscreen_enabled(session, result)
        self._check_smartscreen_level(session, result)
        self._check_shell_smartscreen(session, result)
        self._check_attachment_manager(session, result)
        self._check_exploit_guard(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_patch_installed(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if the February 2026 security update is installed."""
        patches = session.run_powershell(
            "Get-HotFix -ErrorAction SilentlyContinue | "
            "Where-Object { $_.InstalledOn -ge '2026-02-01' } | "
            "Select-Object HotFixID, InstalledOn | "
            "ConvertTo-Json -Compress"
        )
        if not patches or not patches.stdout.strip() or patches.stdout.strip() in ("", "null"):
            self.add_finding(
                result,
                description="No February 2026+ patches found — likely vulnerable to CVE-2026-21510 (SmartScreen bypass)",
                severity=Severity.CRITICAL,
                evidence="No hotfixes installed after 2026-02-01",
                recommendation=(
                    "Apply the February 2026 Patch Tuesday update immediately. "
                    "CVE-2026-21510 bypasses SmartScreen and Shell security prompts."
                ),
                cwe="CWE-693",
            )
        else:
            self.add_finding(
                result,
                description="February 2026+ security updates detected",
                severity=Severity.INFO,
                evidence=patches.stdout[:500],
                recommendation="Verify the installed update covers CVE-2026-21510.",
            )

    def _check_smartscreen_enabled(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if SmartScreen is enabled system-wide."""
        ss = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "SmartScreenEnabled",
        )
        if ss is not None:
            val = str(ss).lower()
            if val in ("off", "0", ""):
                self.add_finding(
                    result,
                    description="Windows SmartScreen is disabled system-wide",
                    severity=Severity.HIGH,
                    evidence=f"SmartScreenEnabled = {ss}",
                    recommendation=(
                        "Enable SmartScreen via GPO: Computer Configuration > "
                        "Admin Templates > Windows Components > File Explorer > "
                        "Configure Windows Defender SmartScreen."
                    ),
                    cwe="CWE-693",
                )
            elif val == "warn":
                self.add_finding(
                    result,
                    description="SmartScreen is set to Warn — users can bypass the warning",
                    severity=Severity.MEDIUM,
                    evidence=f"SmartScreenEnabled = {ss}",
                    recommendation=(
                        "Set SmartScreen to Block mode to prevent users from "
                        "overriding SmartScreen warnings."
                    ),
                )

    def _check_smartscreen_level(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check SmartScreen enforcement level via Defender policy."""
        level = session.read_registry(
            "HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen",
            "ConfigureAppInstallControlEnabled",
        )
        if level is None or str(level) != "1":
            self.add_finding(
                result,
                description="SmartScreen app install control is not enforced via policy",
                severity=Severity.MEDIUM,
                evidence=f"ConfigureAppInstallControlEnabled = {level}",
                recommendation=(
                    "Enable app install control via GPO to restrict installations "
                    "to Microsoft Store only or warn on non-Store apps."
                ),
            )

    def _check_shell_smartscreen(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check the Shell-level SmartScreen prompt configuration."""
        prompt = session.read_registry(
            "HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            "EnableSmartScreen",
        )
        if prompt is not None and str(prompt) == "0":
            self.add_finding(
                result,
                description="Shell SmartScreen prompts are disabled via Group Policy",
                severity=Severity.HIGH,
                evidence=f"EnableSmartScreen = {prompt}",
                recommendation=(
                    "Enable Shell SmartScreen: Set EnableSmartScreen to 1 or 2 "
                    "under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System."
                ),
                cwe="CWE-693",
            )

    def _check_attachment_manager(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Attachment Manager settings that control MOTW prompts."""
        # HideZoneInfoOnProperties: 1 = hide zone info (reduces security)
        hide_zone = session.read_registry(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments",
            "HideZoneInfoOnProperties",
        )
        if hide_zone is not None and str(hide_zone) == "1":
            self.add_finding(
                result,
                description="Zone information is hidden on file properties — weakens MOTW protection",
                severity=Severity.MEDIUM,
                evidence=f"HideZoneInfoOnProperties = {hide_zone}",
                recommendation=(
                    "Show zone information on file properties so users can see "
                    "the origin of downloaded files."
                ),
            )

    def _check_exploit_guard(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Windows Defender Exploit Guard ASR rules relevant to SmartScreen bypass."""
        asr = session.run_powershell(
            "try { "
            "  Get-MpPreference -ErrorAction SilentlyContinue | "
            "  Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids "
            "} catch { }"
        )
        if not asr or not asr.stdout.strip():
            self.add_finding(
                result,
                description="No Attack Surface Reduction (ASR) rules detected — defense gap for SmartScreen bypass",
                severity=Severity.MEDIUM,
                evidence="AttackSurfaceReductionRules_Ids is empty or not configured",
                recommendation=(
                    "Enable ASR rules via Defender for Endpoint or GPO. "
                    "Key rules: Block execution of potentially obfuscated scripts, "
                    "Block Office applications from creating executable content."
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_powershell(
            "[PSCustomObject]@{ "
            "  SmartScreen = (Get-ItemProperty "
            "    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' "
            "    -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled; "
            "  ExploitGuard = (Get-MpPreference -ErrorAction SilentlyContinue).EnableNetworkProtection; "
            "  MOTW = (Get-ItemProperty "
            "    'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments' "
            "    -Name SaveZoneInformation -ErrorAction SilentlyContinue).SaveZoneInformation "
            "} | ConvertTo-Json -Compress"
        )
        if out:
            self.add_finding(
                result,
                description="Simulated: SmartScreen and trust controls enumeration",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Monitor for SmartScreen bypass attempts via event logs",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1051 — Update Software: Apply February 2026 Patch Tuesday update (CVE-2026-21510)",
            "M1054 — Software Configuration: Set SmartScreen to Block mode (not Warn)",
            "M1038 — Execution Prevention: Enable ASR rules to block untrusted content execution",
            "M1040 — Behavior Prevention on Endpoint: Enable Defender Exploit Guard",
            "M1028 — Operating System Configuration: Enable and enforce Mark of the Web via GPO",
        ]
