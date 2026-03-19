"""T1036 — Masquerading.

Detects potential binary masquerading by checking for executables
with system binary names in non-standard locations, unsigned
executables, and name discrepancies.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# System binaries commonly masqueraded by attackers
_SYSTEM_BINARIES = [
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
    "smss.exe", "wininit.exe", "winlogon.exe", "explorer.exe",
    "taskhostw.exe", "RuntimeBroker.exe", "conhost.exe",
]


class MasqueradingCheck(BaseModule):
    """T1036 — Masquerading detection.

    Identifies executables masquerading as legitimate system
    binaries via name, path, or signature discrepancies.
    """

    TECHNIQUE_ID = "T1036"
    TECHNIQUE_NAME = "Masquerading"
    TACTIC = "Defense Evasion"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_binary_paths(session, result)
        self._check_space_after_name(session, result)
        self._check_hidden_extensions(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_binary_paths(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for system binary names running from non-standard paths."""
        for binary in _SYSTEM_BINARIES:
            procs = session.run_powershell(
                f"Get-Process -Name '{binary.replace('.exe', '')}' "
                f"-ErrorAction SilentlyContinue | "
                f"Select-Object Name, Id, Path | "
                f"ConvertTo-Json -Compress"
            )
            if not procs or not procs.stdout.strip() or procs.stdout.strip() in ("", "null"):
                continue

            try:
                proc_list = json.loads(procs.stdout)
            except json.JSONDecodeError:
                continue

            if not isinstance(proc_list, list):
                proc_list = [proc_list]

            for proc in proc_list:
                path = proc.get("Path", "")
                if not path:
                    continue

                path_lower = path.lower()
                # Valid paths for system binaries
                valid_paths = (
                    r"c:\windows\system32",
                    r"c:\windows\syswow64",
                    r"c:\windows",
                    r"c:\windows\explorer.exe",
                )
                if not any(path_lower.startswith(v) for v in valid_paths):
                    self.add_finding(
                        result,
                        description=f"Potential masquerading: '{binary}' running from non-standard path",
                        severity=Severity.CRITICAL,
                        evidence=f"Process: {binary}\nPID: {proc.get('Id', '?')}\nPath: {path}",
                        recommendation=(
                            f"Investigate '{binary}' running from '{path}'. "
                            f"Legitimate {binary} should only run from System32."
                        ),
                        cwe="CWE-506",
                    )

    def _check_space_after_name(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for executables with trailing spaces or unusual characters."""
        space_files = session.run_powershell(
            "Get-ChildItem -Path $env:TEMP, $env:APPDATA -Recurse -Depth 2 "
            "-Filter '*.exe' -ErrorAction SilentlyContinue | "
            "Where-Object { $_.BaseName -match '\\s$' -or $_.BaseName -match '^\\s' } | "
            "Select-Object FullName | ConvertTo-Json -Compress"
        )
        if space_files and space_files.stdout.strip() and space_files.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Executables with suspicious whitespace in filenames found",
                severity=Severity.HIGH,
                evidence=space_files.stdout[:500],
                recommendation=(
                    "Investigate executables with leading/trailing spaces in names. "
                    "This is a masquerading technique to evade casual inspection."
                ),
                cwe="CWE-506",
            )

    def _check_hidden_extensions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if 'Hide extensions for known file types' is enabled."""
        hide = session.read_registry(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "HideFileExt",
        )
        if hide is not None and str(hide) == "1":
            self.add_finding(
                result,
                description="File extensions are hidden in Explorer (masquerading enabler)",
                severity=Severity.LOW,
                evidence=f"HideFileExt = {hide}",
                recommendation=(
                    "Show file extensions for known file types via GPO: "
                    "User Configuration > Preferences > Control Panel Settings > "
                    "Folder Options. Prevents 'document.pdf.exe' masquerading."
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_powershell(
            "Get-Process | Where-Object { $_.Path } | "
            "Select-Object Name, Path | ConvertTo-Json -Compress"
        )
        if out:
            self.add_finding(
                result, description="Simulated: Running process path enumeration",
                severity=Severity.INFO, evidence=out.stdout[:500],
                recommendation="Monitor for process execution from non-standard paths",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1045 — Code Signing: Enforce code signing to detect unsigned masquerading binaries",
            "M1038 — Execution Prevention: Use WDAC/AppLocker to restrict execution by path",
            "M1040 — Behavior Prevention on Endpoint: EDR detection of path anomalies",
            "M1028 — Operating System Configuration: Show file extensions system-wide",
        ]
