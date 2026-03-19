"""T1574.002 — Hijack Execution Flow: DLL Side-Loading.

Checks for DLL side-loading vulnerabilities in installed
applications and services, focusing on unsigned DLLs,
writable application directories, and missing manifest entries.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Known application directories commonly targeted for side-loading
_SIDELOAD_TARGETS = [
    (r"C:\Program Files\*\*.dll", "Program Files"),
    (r"C:\Program Files (x86)\*\*.dll", "Program Files (x86)"),
]


class DllSideLoading(BaseModule):
    """T1574.002 — DLL Side-Loading audit.

    Identifies applications and services vulnerable to DLL
    side-loading through weak directory permissions, unsigned
    DLLs, and insecure application installations.
    """

    TECHNIQUE_ID = "T1574.002"
    TECHNIQUE_NAME = "Hijack Execution Flow: DLL Side-Loading"
    TACTIC = "Privilege Escalation"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_writable_program_dirs(session, result)
        self._check_unquoted_service_paths(session, result)
        self._check_appinit_dlls(session, result)
        self._check_code_signing_enforcement(session, result)
        self._check_sxs_dll_redirection(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_writable_program_dirs(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for writable application directories (side-load targets)."""
        check = session.run_powershell(
            "$dirs = @('C:\\Program Files', 'C:\\Program Files (x86)'); "
            "$dirs | ForEach-Object { "
            "  if (Test-Path $_ -ErrorAction SilentlyContinue) { "
            "    Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue | "
            "    ForEach-Object { "
            "      $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue; "
            "      $weak = $acl.Access | Where-Object { "
            "        $_.IdentityReference -match 'Everyone|Users|Authenticated Users' "
            "        -and $_.FileSystemRights -match 'Write|Modify|FullControl' "
            "        -and $_.AccessControlType -eq 'Allow' "
            "      }; "
            "      if ($weak) { "
            "        [PSCustomObject]@{ "
            "          Dir = $_.FullName; "
            "          Identity = ($weak.IdentityReference | Select-Object -First 1).ToString() "
            "        } "
            "      } "
            "    } "
            "  } "
            "} | Select-Object -First 10 | ConvertTo-Json -Compress"
        )
        if check and check.stdout.strip() and check.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Writable application directories found (DLL side-loading risk)",
                severity=Severity.HIGH,
                evidence=check.stdout[:500],
                recommendation=(
                    "Fix directory permissions under Program Files. Non-admin "
                    "users should not have write access to application directories."
                ),
                cwe="CWE-427",
            )

    def _check_unquoted_service_paths(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for unquoted service paths (binary planting)."""
        unquoted = session.run_powershell(
            "Get-CimInstance Win32_Service | Where-Object { "
            "  $_.PathName -and "
            "  $_.PathName -notmatch '^\".+\"' -and "
            "  $_.PathName -match '.+ .+\\.exe' -and "
            "  $_.PathName -notmatch '^C:\\\\Windows\\\\' "
            "} | Select-Object Name, PathName, StartMode, State | "
            "ConvertTo-Json -Compress"
        )
        if unquoted and unquoted.stdout.strip() and unquoted.stdout.strip() not in ("", "null"):
            try:
                services = json.loads(unquoted.stdout)
            except json.JSONDecodeError:
                return

            if not isinstance(services, list):
                services = [services]

            for svc in services:
                name = svc.get("Name", "")
                path = svc.get("PathName", "")
                self.add_finding(
                    result,
                    description=f"Unquoted service path: {name}",
                    severity=Severity.HIGH,
                    evidence=f"Service: {name}\nPath: {path}\nState: {svc.get('State', '')}",
                    recommendation=(
                        f"Quote the service path for '{name}'. Unquoted paths with "
                        f"spaces allow binary planting attacks. Use: "
                        f"sc config \"{name}\" binpath= \"\\\"{path}\\\"\""
                    ),
                    cwe="CWE-428",
                )

    def _check_appinit_dlls(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if AppInit_DLLs is configured (DLL injection vector)."""
        appinit = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs",
        )
        load_appinit = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "LoadAppInit_DLLs",
        )
        if load_appinit is not None and str(load_appinit) == "1":
            self.add_finding(
                result,
                description="AppInit_DLLs loading is enabled (global DLL injection)",
                severity=Severity.HIGH,
                evidence=f"LoadAppInit_DLLs = {load_appinit}, AppInit_DLLs = {appinit}",
                recommendation=(
                    "Disable AppInit_DLLs: Set LoadAppInit_DLLs to 0. "
                    "This mechanism loads specified DLLs into every process "
                    "that loads user32.dll, enabling persistence and injection."
                ),
                cwe="CWE-427",
            )

        if appinit and str(appinit).strip():
            self.add_finding(
                result,
                description=f"AppInit_DLLs has entries configured: {appinit}",
                severity=Severity.HIGH if str(load_appinit) == "1" else Severity.MEDIUM,
                evidence=f"AppInit_DLLs = {appinit}",
                recommendation="Remove AppInit_DLLs entries and disable the mechanism",
                cwe="CWE-427",
            )

    def _check_code_signing_enforcement(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if code signing is enforced for DLLs."""
        # Check WDAC / Device Guard Code Integrity
        ci = session.run_powershell(
            "(Get-CimInstance -ClassName Win32_DeviceGuard "
            "-Namespace root/Microsoft/Windows/DeviceGuard "
            "-ErrorAction SilentlyContinue).CodeIntegrityPolicyEnforcementStatus"
        )
        if ci and ci.stdout.strip():
            status = ci.stdout.strip()
            if status == "0":
                self.add_finding(
                    result,
                    description="WDAC/Code Integrity policy is not enforced — unsigned DLLs can load freely",
                    severity=Severity.MEDIUM,
                    evidence=f"CodeIntegrityPolicyEnforcementStatus = {status}",
                    recommendation=(
                        "Consider deploying Windows Defender Application Control (WDAC) "
                        "to enforce code signing for executables and DLLs"
                    ),
                )
        else:
            self.add_finding(
                result,
                description="WDAC/Code Integrity policy status unavailable",
                severity=Severity.LOW,
                evidence="DeviceGuard WMI class not available or policy not configured",
                recommendation="Evaluate WDAC deployment to prevent unsigned code execution",
            )

    def _check_sxs_dll_redirection(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for DotLocal DLL redirection (.local files)."""
        dotlocal = session.run_powershell(
            "Get-ChildItem -Path 'C:\\Windows\\System32\\*.local' "
            "-ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Name"
        )
        if dotlocal and dotlocal.stdout.strip():
            self.add_finding(
                result,
                description="DotLocal (.local) DLL redirection files found in System32",
                severity=Severity.HIGH,
                evidence=dotlocal.stdout.strip(),
                recommendation=(
                    "Remove .local files from System32. These enable SxS DLL "
                    "redirection which can be abused for side-loading."
                ),
                cwe="CWE-427",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate DLL side-loading reconnaissance."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        out = session.run_cmd(
            "wmic service get name,pathname /format:list 2>nul | findstr /i \"pathname\""
        )
        if out:
            self.add_finding(
                result,
                description="Simulated: Service path enumeration for side-loading targets",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Monitor for service path enumeration activity",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1044 — Restrict Library Loading: Deploy WDAC to enforce code signing on DLLs",
            "M1022 — Restrict File and Directory Permissions: Harden application directory ACLs",
            "M1024 — Restrict Registry Permissions: Disable AppInit_DLLs mechanism",
            "M1047 — Audit: Monitor DLL loads from non-standard paths (Sysmon Event ID 7)",
        ]
