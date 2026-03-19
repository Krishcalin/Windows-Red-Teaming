"""T1546.001 — Event Triggered Execution: Change Default File Association.

Checks for tampered file associations that could redirect
common file types to execute malicious code.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# File extensions to check and their expected handlers
_EXPECTED_ASSOCIATIONS = {
    ".txt": "txtfile",
    ".bat": "batfile",
    ".cmd": "cmdfile",
    ".vbs": "VBSFile",
    ".js": "JSFile",
    ".ps1": "Microsoft.PowerShellScript.1",
    ".hta": "htafile",
    ".wsf": "WSFFile",
}


class FileAssociationCheck(BaseModule):
    """T1546.001 — File Association tampering audit.

    Checks common file type associations for evidence of
    hijacking that could execute malicious code.
    """

    TECHNIQUE_ID = "T1546.001"
    TECHNIQUE_NAME = "Event Triggered Execution: Change Default File Association"
    TACTIC = "Persistence"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_file_associations(session, result)
        self._check_progid_commands(session, result)
        self._check_user_choice_overrides(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_file_associations(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check file extension associations against expected defaults."""
        for ext, expected_type in _EXPECTED_ASSOCIATIONS.items():
            assoc = session.run_cmd(f"assoc {ext} 2>nul")
            if not assoc or not assoc.stdout.strip():
                continue

            current = assoc.stdout.strip()
            # assoc returns ".ext=FileType"
            if "=" in current:
                file_type = current.split("=", 1)[1].strip()
                if file_type.lower() != expected_type.lower():
                    self.add_finding(
                        result,
                        description=f"File association for '{ext}' has been changed: {file_type}",
                        severity=Severity.HIGH,
                        evidence=f"Expected: {expected_type}, Found: {file_type}",
                        recommendation=(
                            f"Restore the default file association for '{ext}'. "
                            f"Modified associations may redirect execution to malicious handlers."
                        ),
                        cwe="CWE-284",
                    )

    def _check_progid_commands(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check the actual command handlers for script file types."""
        script_types = {
            "htafile": ("mshta.exe", Severity.MEDIUM),
            "batfile": ("cmd.exe", Severity.MEDIUM),
            "VBSFile": ("wscript.exe", Severity.MEDIUM),
            "JSFile": ("wscript.exe", Severity.MEDIUM),
        }

        for prog_id, (expected_exe, severity) in script_types.items():
            handler = session.run_powershell(
                f"(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Classes\\{prog_id}"
                f"\\shell\\open\\command' -ErrorAction SilentlyContinue).'(Default)'"
            )
            if not handler or not handler.stdout.strip():
                continue

            cmd = handler.stdout.strip().lower()
            if expected_exe.lower() not in cmd:
                self.add_finding(
                    result,
                    description=f"Handler for '{prog_id}' has unexpected command: {handler.stdout.strip()[:100]}",
                    severity=Severity.HIGH,
                    evidence=f"ProgID: {prog_id}\nExpected: {expected_exe}\nFound: {cmd[:200]}",
                    recommendation=(
                        f"Investigate the modified handler for {prog_id}. "
                        f"Tampered handlers can execute arbitrary code when "
                        f"associated file types are opened."
                    ),
                    cwe="CWE-284",
                )

    def _check_user_choice_overrides(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for user-level file association overrides."""
        overrides = session.run_powershell(
            "Get-ChildItem -Path 'HKCU:\\Software\\Microsoft\\Windows\\"
            "CurrentVersion\\Explorer\\FileExts' -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "  $ext = $_.PSChildName; "
            "  $uc = Get-ItemProperty -Path \"$($_.PSPath)\\UserChoice\" "
            "    -ErrorAction SilentlyContinue; "
            "  if ($uc -and $uc.ProgId -and $ext -match '\\.(bat|cmd|vbs|js|ps1|hta|wsf)$') { "
            "    \"$ext=$($uc.ProgId)\" "
            "  } "
            "}"
        )
        if overrides and overrides.stdout.strip():
            self.add_finding(
                result,
                description="User-level file association overrides for script types detected",
                severity=Severity.MEDIUM,
                evidence=overrides.stdout[:500],
                recommendation=(
                    "Review user-level file association overrides. "
                    "These can redirect script execution to unexpected handlers."
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_cmd("assoc 2>nul")
        if out:
            self.add_finding(
                result, description="Simulated: File association enumeration",
                severity=Severity.INFO, evidence=out.stdout[:500],
                recommendation="Monitor for assoc/ftype command usage",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1024 — Restrict Registry Permissions: Protect file association registry keys",
            "M1042 — Disable or Remove Feature or Program: Disable script host for unneeded file types",
            "M1038 — Execution Prevention: Use AppLocker to block script interpreters",
            "M1047 — Audit: Monitor registry changes to HKCR and file association keys",
        ]
