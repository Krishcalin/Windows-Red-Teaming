"""T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC.

Checks User Account Control (UAC) configuration for weaknesses
that allow privilege escalation without a UAC prompt.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class UacBypassCheck(BaseModule):
    """T1548.002 — UAC Bypass vulnerability audit.

    Evaluates UAC configuration for weaknesses including
    disabled prompts, auto-elevation, and weak consent levels.
    """

    TECHNIQUE_ID = "T1548.002"
    TECHNIQUE_NAME = "Abuse Elevation Control Mechanism: Bypass UAC"
    TACTIC = "Privilege Escalation"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    _UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_uac_enabled(session, result)
        self._check_consent_prompt(session, result)
        self._check_admin_auto_elevate(session, result)
        self._check_secure_desktop(session, result)
        self._check_installer_detection(session, result)
        self._check_uac_virtualization(session, result)
        self._check_auto_elevate_binaries(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_uac_enabled(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if UAC is enabled (EnableLUA)."""
        lua = session.read_registry("HKLM", self._UAC_KEY, "EnableLUA")
        if lua is not None and str(lua) != "1":
            self.add_finding(
                result,
                description="User Account Control (UAC) is disabled",
                severity=Severity.CRITICAL,
                evidence=f"EnableLUA = {lua}",
                recommendation=(
                    "Enable UAC: Set HKLM\\...\\Policies\\System\\EnableLUA to 1. "
                    "CIS Benchmark 2.3.17.6"
                ),
                cwe="CWE-250",
            )

    def _check_consent_prompt(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check consent prompt behavior for administrators."""
        # ConsentPromptBehaviorAdmin:
        # 0 = Elevate without prompting (MOST DANGEROUS)
        # 1 = Prompt for credentials on secure desktop
        # 2 = Prompt for consent on secure desktop
        # 3 = Prompt for credentials
        # 4 = Prompt for consent
        # 5 = Prompt for consent for non-Windows binaries (default)
        val = session.read_registry(
            "HKLM", self._UAC_KEY, "ConsentPromptBehaviorAdmin"
        )
        if val is not None:
            v = str(val)
            if v == "0":
                self.add_finding(
                    result,
                    description="UAC admin consent: Elevate without prompting (no UAC prompt at all)",
                    severity=Severity.CRITICAL,
                    evidence=f"ConsentPromptBehaviorAdmin = {v}",
                    recommendation=(
                        "Set ConsentPromptBehaviorAdmin to 1 or 2 (prompt for "
                        "credentials/consent on secure desktop). CIS Benchmark 2.3.17.1"
                    ),
                    cwe="CWE-250",
                )
            elif v in ("4", "5"):
                self.add_finding(
                    result,
                    description=f"UAC admin consent prompts for consent only, not credentials (level={v})",
                    severity=Severity.MEDIUM,
                    evidence=f"ConsentPromptBehaviorAdmin = {v}",
                    recommendation=(
                        "Set to 1 (prompt for credentials on secure desktop) "
                        "for maximum protection against UAC bypass"
                    ),
                )

        # ConsentPromptBehaviorUser for standard users
        user_val = session.read_registry(
            "HKLM", self._UAC_KEY, "ConsentPromptBehaviorUser"
        )
        if user_val is not None and str(user_val) == "0":
            self.add_finding(
                result,
                description="UAC standard user behavior: Auto-deny elevation (silent fail)",
                severity=Severity.LOW,
                evidence=f"ConsentPromptBehaviorUser = {user_val}",
                recommendation=(
                    "Set ConsentPromptBehaviorUser to 1 (prompt for credentials) "
                    "or 3 (prompt for credentials on secure desktop)"
                ),
            )

    def _check_admin_auto_elevate(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if admin approval mode is enabled."""
        # FilterAdministratorToken: if 0, the built-in admin runs everything elevated
        fat = session.read_registry(
            "HKLM", self._UAC_KEY, "FilterAdministratorToken"
        )
        if fat is None or str(fat) != "1":
            self.add_finding(
                result,
                description="Built-in Administrator account runs with full elevated token (no UAC filtering)",
                severity=Severity.HIGH,
                evidence=f"FilterAdministratorToken = {fat}",
                recommendation=(
                    "Set FilterAdministratorToken to 1 to enable UAC for the "
                    "built-in Administrator account. CIS Benchmark 2.3.17.2"
                ),
                cwe="CWE-250",
            )

    def _check_secure_desktop(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if UAC prompts run on the secure desktop."""
        sd = session.read_registry(
            "HKLM", self._UAC_KEY, "PromptOnSecureDesktop"
        )
        if sd is not None and str(sd) != "1":
            self.add_finding(
                result,
                description="UAC prompts do not use the secure desktop (vulnerable to UI spoofing)",
                severity=Severity.HIGH,
                evidence=f"PromptOnSecureDesktop = {sd}",
                recommendation=(
                    "Enable secure desktop for UAC prompts: Set PromptOnSecureDesktop "
                    "to 1. Prevents malware from spoofing UAC dialogs. CIS Benchmark 2.3.17.7"
                ),
                cwe="CWE-356",
            )

    def _check_installer_detection(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if installer detection is enabled."""
        detect = session.read_registry(
            "HKLM", self._UAC_KEY, "EnableInstallerDetection"
        )
        if detect is not None and str(detect) != "1":
            self.add_finding(
                result,
                description="UAC installer detection is disabled",
                severity=Severity.MEDIUM,
                evidence=f"EnableInstallerDetection = {detect}",
                recommendation=(
                    "Enable installer detection: Set EnableInstallerDetection to 1. "
                    "CIS Benchmark 2.3.17.3"
                ),
            )

    def _check_uac_virtualization(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if UAC file/registry virtualization is enabled."""
        virt = session.read_registry(
            "HKLM", self._UAC_KEY, "EnableVirtualization"
        )
        if virt is not None and str(virt) != "1":
            self.add_finding(
                result,
                description="UAC file and registry virtualization is disabled",
                severity=Severity.LOW,
                evidence=f"EnableVirtualization = {virt}",
                recommendation=(
                    "Enable virtualization: Set EnableVirtualization to 1. "
                    "CIS Benchmark 2.3.17.8"
                ),
            )

    def _check_auto_elevate_binaries(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for known auto-elevating binaries (UAC bypass vectors)."""
        # Check if common UAC bypass binaries exist and are accessible
        bypass_bins = [
            ("fodhelper.exe", "T1548.002 — eventvwr/fodhelper UAC bypass"),
            ("computerdefaults.exe", "T1548.002 — computerdefaults UAC bypass"),
            ("sdclt.exe", "T1548.002 — sdclt UAC bypass"),
        ]

        accessible: list[str] = []
        for binary, desc in bypass_bins:
            check = session.run_powershell(
                f"$path = \"$env:SystemRoot\\System32\\{binary}\"; "
                f"if (Test-Path $path) {{ "
                f"  $m = (Get-Item $path).VersionInfo.FileDescription; "
                f"  \"{binary}: $m\" "
                f"}}"
            )
            if check and check.stdout.strip():
                accessible.append(check.stdout.strip())

        if accessible:
            self.add_finding(
                result,
                description=f"Auto-elevating binaries accessible ({len(accessible)} known bypass vectors)",
                severity=Severity.INFO,
                evidence="\n".join(accessible),
                recommendation=(
                    "These binaries auto-elevate and can be abused for UAC bypass. "
                    "Set ConsentPromptBehaviorAdmin to 1 (prompt for credentials) "
                    "to mitigate auto-elevation attacks."
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate UAC configuration enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        out = session.run_cmd(
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        )
        if out:
            self.add_finding(
                result,
                description="Simulated: UAC registry configuration dump",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Monitor registry access to UAC policy keys",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1047 — Audit: Monitor Event ID 4688 for auto-elevated process creation",
            "M1026 — Privileged Account Management: Use separate admin accounts, never browse with admin",
            "M1051 — Update Software: Keep Windows patched to fix known UAC bypass vulnerabilities",
            "M1028 — Operating System Configuration: Set UAC to 'Always Notify' (highest level)",
        ]
