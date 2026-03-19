"""T1059.003 — Command and Scripting Interpreter: Windows Command Shell.

Checks restrictions on cmd.exe usage, command-line auditing,
and controls to prevent abuse of the Windows Command Shell.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class CommandShellCheck(BaseModule):
    """T1059.003 — Windows Command Shell restrictions audit.

    Evaluates defenses against cmd.exe abuse including
    AppLocker/WDAC policies, command-line auditing, and
    DisableCMD registry settings.
    """

    TECHNIQUE_ID = "T1059.003"
    TECHNIQUE_NAME = "Command and Scripting Interpreter: Windows Command Shell"
    TACTIC = "Execution"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_cmd_disabled(session, result)
        self._check_command_line_audit(session, result)
        self._check_applocker_cmd(session, result)
        self._check_wscript_cscript(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_cmd_disabled(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if cmd.exe is restricted via Group Policy."""
        disable = session.read_registry(
            "HKCU",
            r"Software\Policies\Microsoft\Windows\System",
            "DisableCMD",
        )
        # DisableCMD: 0=not disabled, 1=disable cmd+scripts, 2=disable cmd only
        if disable is None or str(disable) == "0":
            self.add_finding(
                result,
                description="Windows Command Shell (cmd.exe) is not restricted for this user",
                severity=Severity.LOW,
                evidence=f"DisableCMD = {disable}",
                recommendation=(
                    "Consider disabling cmd.exe for standard users via GPO: "
                    "User Configuration > Administrative Templates > System > "
                    "Prevent access to the command prompt"
                ),
            )

    def _check_command_line_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if command-line process auditing is enabled."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Process Creation' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="Process creation auditing is not enabled — command execution is not logged",
                severity=Severity.HIGH,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Process Creation' (Success) via GPO. "
                    "CIS Benchmark 17.9.1"
                ),
                cwe="CWE-778",
            )

        # Check command-line inclusion in audit events
        cmdline = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled",
        )
        if cmdline is None or str(cmdline) != "1":
            self.add_finding(
                result,
                description="Command-line arguments are not included in process creation events",
                severity=Severity.HIGH,
                evidence=f"ProcessCreationIncludeCmdLine_Enabled = {cmdline}",
                recommendation=(
                    "Enable command-line logging via GPO: Administrative Templates > "
                    "System > Audit Process Creation > Include command line. "
                    "Essential for detecting cmd.exe and LOLBin abuse."
                ),
                cwe="CWE-778",
            )

    def _check_applocker_cmd(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if AppLocker or WDAC restricts cmd.exe execution."""
        applocker = session.run_powershell(
            "(Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue).Status"
        )
        if not applocker or applocker.stdout.strip().lower() != "running":
            self.add_finding(
                result,
                description="AppLocker service (AppIDSvc) is not running — no application whitelisting",
                severity=Severity.MEDIUM,
                evidence=f"AppIDSvc status: {applocker.stdout.strip() if applocker else 'not found'}",
                recommendation=(
                    "Deploy AppLocker or WDAC to restrict which executables "
                    "can run. At minimum, restrict cmd.exe and powershell.exe "
                    "for standard users."
                ),
            )

    def _check_wscript_cscript(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Windows Script Host (wscript/cscript) is enabled."""
        wsh = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows Script Host\Settings",
            "Enabled",
        )
        # Default is enabled (1 or not set)
        if wsh is None or str(wsh) != "0":
            self.add_finding(
                result,
                description="Windows Script Host (wscript/cscript) is enabled",
                severity=Severity.MEDIUM,
                evidence=f"WSH Enabled = {wsh}",
                recommendation=(
                    "Disable Windows Script Host if not needed: Set "
                    "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\"
                    "Enabled to 0. Prevents .vbs/.js script execution."
                ),
                cwe="CWE-94",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_cmd("cmd /c echo %COMSPEC% & ver")
        if out:
            self.add_finding(
                result, description="Simulated: Command shell access test",
                severity=Severity.INFO, evidence=out.stdout[:300],
                recommendation="Monitor cmd.exe invocations via process creation events",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1038 — Execution Prevention: Deploy AppLocker/WDAC to restrict cmd.exe",
            "M1047 — Audit: Enable process creation auditing with command-line logging",
            "M1042 — Disable or Remove Feature or Program: Disable Windows Script Host",
            "M1026 — Privileged Account Management: Restrict shell access for standard users",
        ]
