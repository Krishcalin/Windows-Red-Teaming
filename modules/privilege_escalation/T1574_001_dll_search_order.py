"""T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking.

Checks for DLL search order hijacking vulnerabilities including
writable directories in search paths, missing DLLs loaded by
privileged services, and SafeDllSearchMode configuration.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class DllSearchOrderHijacking(BaseModule):
    """T1574.001 — DLL Search Order Hijacking audit.

    Identifies writable directories in DLL search paths and
    configuration weaknesses enabling DLL hijacking.
    """

    TECHNIQUE_ID = "T1574.001"
    TECHNIQUE_NAME = "Hijack Execution Flow: DLL Search Order Hijacking"
    TACTIC = "Privilege Escalation"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_safe_dll_search(session, result)
        self._check_path_writable(session, result)
        self._check_known_dlls(session, result)
        self._check_service_binary_permissions(session, result)
        self._check_cwdillegalindllsearch(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_safe_dll_search(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if SafeDllSearchMode is enabled."""
        safe = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "SafeDllSearchMode",
        )
        # Default is 1 (enabled) when not set, but explicit 0 = disabled
        if safe is not None and str(safe) == "0":
            self.add_finding(
                result,
                description="SafeDllSearchMode is disabled — CWD is searched before system directories",
                severity=Severity.HIGH,
                evidence=f"SafeDllSearchMode = {safe}",
                recommendation=(
                    "Enable SafeDllSearchMode: Set HKLM\\SYSTEM\\CurrentControlSet\\"
                    "Control\\Session Manager\\SafeDllSearchMode to 1 (DWORD). "
                    "This moves CWD later in the DLL search order."
                ),
                cwe="CWE-427",
            )

    def _check_path_writable(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for writable directories in the system PATH."""
        path_check = session.run_powershell(
            "$env:PATH -split ';' | ForEach-Object { "
            "  $p = $_.Trim(); "
            "  if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) { "
            "    $acl = Get-Acl $p -ErrorAction SilentlyContinue; "
            "    $weak = $acl.Access | Where-Object { "
            "      $_.IdentityReference -match 'Everyone|Users|Authenticated Users' "
            "      -and $_.FileSystemRights -match 'Write|Modify|FullControl' "
            "      -and $_.AccessControlType -eq 'Allow' "
            "    }; "
            "    if ($weak) { "
            "      [PSCustomObject]@{ "
            "        Path = $p; "
            "        Identity = ($weak.IdentityReference -join ', '); "
            "        Rights = ($weak.FileSystemRights -join ', ') "
            "      } "
            "    } "
            "  } "
            "} | ConvertTo-Json -Compress"
        )
        if path_check and path_check.stdout.strip() and path_check.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Writable directories found in system PATH — DLL hijacking possible",
                severity=Severity.HIGH,
                evidence=path_check.stdout[:500],
                recommendation=(
                    "Remove write permissions for non-admin users on all "
                    "PATH directories. An attacker can plant a malicious DLL "
                    "that gets loaded by a privileged process."
                ),
                cwe="CWE-427",
            )

    def _check_known_dlls(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check the KnownDLLs registry key for completeness."""
        known = session.run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\"
            "Control\\Session Manager\\KnownDLLs' -ErrorAction SilentlyContinue "
            "| Get-Member -MemberType NoteProperty | Where-Object { "
            "$_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' "
            "-and $_.Name -ne 'PSChildName' -and $_.Name -ne 'PSProvider' "
            "}).Count"
        )
        if known and known.stdout.strip().isdigit():
            count = int(known.stdout.strip())
            if count < 20:
                self.add_finding(
                    result,
                    description=f"KnownDLLs registry has only {count} entries (may be incomplete)",
                    severity=Severity.LOW,
                    evidence=f"KnownDLLs count: {count}",
                    recommendation=(
                        "Review KnownDLLs registry entries. DLLs in this list "
                        "are loaded from System32 only, preventing hijacking."
                    ),
                )

    def _check_service_binary_permissions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if service binary directories are writable."""
        svc_check = session.run_powershell(
            "Get-CimInstance Win32_Service | Where-Object { "
            "  $_.PathName -and $_.PathName -notmatch 'svchost|system32' "
            "} | ForEach-Object { "
            "  $path = $_.PathName -replace '\"', ''; "
            "  $dir = Split-Path $path -Parent -ErrorAction SilentlyContinue; "
            "  if ($dir -and (Test-Path $dir -ErrorAction SilentlyContinue)) { "
            "    $acl = Get-Acl $dir -ErrorAction SilentlyContinue; "
            "    $weak = $acl.Access | Where-Object { "
            "      $_.IdentityReference -match 'Everyone|Users|Authenticated Users' "
            "      -and $_.FileSystemRights -match 'Write|Modify|FullControl' "
            "    }; "
            "    if ($weak) { "
            "      [PSCustomObject]@{ "
            "        Service = $_.Name; "
            "        Path = $dir; "
            "        Identity = ($weak.IdentityReference -join ', ') "
            "      } "
            "    } "
            "  } "
            "} | ConvertTo-Json -Compress"
        )
        if svc_check and svc_check.stdout.strip() and svc_check.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Service binary directories with weak permissions found (DLL planting risk)",
                severity=Severity.CRITICAL,
                evidence=svc_check.stdout[:500],
                recommendation=(
                    "Fix permissions on service binary directories. Non-admin "
                    "users should not have write access to directories containing "
                    "service executables."
                ),
                cwe="CWE-427",
            )

    def _check_cwdillegalindllsearch(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check CWDIllegalInDllSearch mitigation."""
        cwd = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "CWDIllegalInDllSearch",
        )
        if cwd is None:
            self.add_finding(
                result,
                description="CWDIllegalInDllSearch is not configured (CWD used in DLL search)",
                severity=Severity.MEDIUM,
                evidence="CWDIllegalInDllSearch not set (defaults to allowing CWD)",
                recommendation=(
                    "Set CWDIllegalInDllSearch to 0xFFFFFFFF to remove CWD from "
                    "the DLL search order for all applications. KB2264107"
                ),
                cwe="CWE-427",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate DLL hijacking reconnaissance."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        out = session.run_cmd("echo %PATH%")
        if out:
            self.add_finding(
                result,
                description="Simulated: System PATH enumeration for DLL hijack targets",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Monitor for PATH enumeration and DLL planting activity",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1044 — Restrict Library Loading: Enable SafeDllSearchMode and CWDIllegalInDllSearch",
            "M1022 — Restrict File and Directory Permissions: Remove write access from PATH directories",
            "M1024 — Restrict Registry Permissions: Protect KnownDLLs and session manager keys",
            "M1047 — Audit: Monitor for DLL loads from non-standard directories (Sysmon Event ID 7)",
        ]
