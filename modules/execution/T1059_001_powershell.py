"""T1059.001 — Command and Scripting Interpreter: PowerShell.

Checks PowerShell execution policy, logging configuration,
constrained language mode, and script block logging to evaluate
defenses against PowerShell-based attacks.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class PowerShellPolicyCheck(BaseModule):
    """T1059.001 — PowerShell security policy audit.

    Evaluates PowerShell hardening including execution policy,
    script block logging, transcription, AMSI, and CLM.
    """

    TECHNIQUE_ID = "T1059.001"
    TECHNIQUE_NAME = "Command and Scripting Interpreter: PowerShell"
    TACTIC = "Execution"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    _PS_POLICY_KEY = r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"
    _PS_LOGGING_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell"

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_execution_policy(session, result)
        self._check_script_block_logging(session, result)
        self._check_transcription(session, result)
        self._check_module_logging(session, result)
        self._check_constrained_language(session, result)
        self._check_powershell_v2(session, result)
        self._check_amsi(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_execution_policy(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check PowerShell execution policy."""
        policy = session.run_powershell("Get-ExecutionPolicy -List | Format-List")
        if not policy or not policy.stdout:
            return

        # Check machine-level policy
        machine_pol = session.read_registry(
            "HKLM", self._PS_POLICY_KEY, "ExecutionPolicy"
        )
        weak_policies = ("unrestricted", "bypass", "undefined")
        if machine_pol and machine_pol.lower() in weak_policies:
            self.add_finding(
                result,
                description=f"PowerShell execution policy is '{machine_pol}' (allows arbitrary script execution)",
                severity=Severity.HIGH,
                evidence=f"Machine ExecutionPolicy = {machine_pol}\n{policy.stdout[:300]}",
                recommendation=(
                    "Set execution policy to AllSigned or RemoteSigned via GPO: "
                    "Computer Configuration > Administrative Templates > "
                    "Windows Components > Windows PowerShell > Turn on Script Execution"
                ),
                cwe="CWE-94",
            )

    def _check_script_block_logging(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if PowerShell Script Block Logging is enabled."""
        sbl = session.read_registry(
            "HKLM",
            self._PS_LOGGING_KEY + r"\ScriptBlockLogging",
            "EnableScriptBlockLogging",
        )
        if sbl is None or str(sbl) != "1":
            self.add_finding(
                result,
                description="PowerShell Script Block Logging is not enabled",
                severity=Severity.HIGH,
                evidence=f"EnableScriptBlockLogging = {sbl}",
                recommendation=(
                    "Enable Script Block Logging via GPO: Administrative Templates > "
                    "Windows Components > Windows PowerShell > Turn on PowerShell "
                    "Script Block Logging. Logs Event ID 4104."
                ),
                cwe="CWE-778",
            )

        # Check invocation logging
        inv = session.read_registry(
            "HKLM",
            self._PS_LOGGING_KEY + r"\ScriptBlockLogging",
            "EnableScriptBlockInvocationLogging",
        )
        if inv is not None and str(inv) == "1":
            self.add_finding(
                result,
                description="PowerShell Script Block Invocation Logging is enabled (verbose, high volume)",
                severity=Severity.INFO,
                evidence=f"EnableScriptBlockInvocationLogging = {inv}",
                recommendation="Invocation logging generates high volume — ensure log capacity is sufficient",
            )

    def _check_transcription(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if PowerShell transcription is enabled."""
        trans = session.read_registry(
            "HKLM",
            self._PS_LOGGING_KEY + r"\Transcription",
            "EnableTranscripting",
        )
        if trans is None or str(trans) != "1":
            self.add_finding(
                result,
                description="PowerShell transcription is not enabled",
                severity=Severity.MEDIUM,
                evidence=f"EnableTranscripting = {trans}",
                recommendation=(
                    "Enable transcription via GPO to capture all PowerShell "
                    "input/output to text files. Useful for forensic analysis."
                ),
            )

    def _check_module_logging(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if PowerShell Module Logging is enabled."""
        mod_log = session.read_registry(
            "HKLM",
            self._PS_LOGGING_KEY + r"\ModuleLogging",
            "EnableModuleLogging",
        )
        if mod_log is None or str(mod_log) != "1":
            self.add_finding(
                result,
                description="PowerShell Module Logging is not enabled",
                severity=Severity.MEDIUM,
                evidence=f"EnableModuleLogging = {mod_log}",
                recommendation=(
                    "Enable Module Logging via GPO. Set module names to '*' "
                    "to log all modules. Logs Event ID 4103."
                ),
            )

    def _check_constrained_language(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Constrained Language Mode is enforced."""
        clm = session.run_powershell("$ExecutionContext.SessionState.LanguageMode")
        if clm and clm.stdout.strip():
            mode = clm.stdout.strip()
            if mode == "FullLanguage":
                self.add_finding(
                    result,
                    description="PowerShell runs in Full Language mode (no restrictions on .NET/COM)",
                    severity=Severity.MEDIUM,
                    evidence=f"LanguageMode = {mode}",
                    recommendation=(
                        "Deploy WDAC/AppLocker to enforce Constrained Language Mode "
                        "for non-admin users. CLM blocks .NET, COM, and type "
                        "manipulation used by attack tools."
                    ),
                )

    def _check_powershell_v2(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if PowerShell v2 engine is available (bypasses logging)."""
        v2 = session.run_powershell(
            "(Get-WindowsOptionalFeature -Online -FeatureName "
            "MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue).State"
        )
        if v2 and v2.stdout.strip().lower() == "enabled":
            self.add_finding(
                result,
                description="PowerShell v2 engine is enabled (bypasses all modern logging and AMSI)",
                severity=Severity.HIGH,
                evidence="MicrosoftWindowsPowerShellV2 = Enabled",
                recommendation=(
                    "Disable PowerShell v2: Disable-WindowsOptionalFeature "
                    "-Online -FeatureName MicrosoftWindowsPowerShellV2. "
                    "Attackers use 'powershell -version 2' to bypass logging."
                ),
                cwe="CWE-693",
            )

    def _check_amsi(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check AMSI (Antimalware Scan Interface) status."""
        amsi = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\AMSI",
            "Enable",
        )
        # AMSI is enabled by default; check if explicitly disabled
        if amsi is not None and str(amsi) == "0":
            self.add_finding(
                result,
                description="AMSI (Antimalware Scan Interface) is disabled via registry",
                severity=Severity.CRITICAL,
                evidence=f"HKLM\\SOFTWARE\\Microsoft\\AMSI\\Enable = {amsi}",
                recommendation=(
                    "Re-enable AMSI immediately. AMSI disabled via registry "
                    "indicates tampering. Investigate for compromise."
                ),
                cwe="CWE-693",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        commands = [
            ("powershell -Command \"Get-ExecutionPolicy -List\"",
             "Execution policy enumeration"),
            ("powershell -Command \"$PSVersionTable\"",
             "PowerShell version discovery"),
        ]
        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result, description=f"Simulated: {desc}",
                    severity=Severity.INFO, evidence=out.stdout[:500],
                    recommendation="Monitor PowerShell usage via Script Block Logging",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1045 — Code Signing: Set execution policy to AllSigned",
            "M1049 — Antivirus/Antimalware: Ensure AMSI is active for script scanning",
            "M1038 — Execution Prevention: Deploy WDAC/AppLocker for Constrained Language Mode",
            "M1047 — Audit: Enable Script Block Logging, Module Logging, and Transcription",
        ]
