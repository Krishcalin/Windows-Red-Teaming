"""T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys.

Audits common persistence registry keys including Run, RunOnce,
Winlogon, and other autostart locations for suspicious entries.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Registry autostart locations to audit
_AUTOSTART_KEYS = [
    # Machine-level Run keys
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", Severity.HIGH),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce", Severity.HIGH),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (WOW64)", Severity.HIGH),
    # User-level Run keys
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", Severity.MEDIUM),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce", Severity.MEDIUM),
    # Winlogon
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon", Severity.HIGH),
]

# Known legitimate Winlogon values
_SAFE_WINLOGON = {"explorer.exe", "userinit.exe", ""}


class RegistryRunKeysCheck(BaseModule):
    """T1547.001 — Registry Run Keys persistence audit.

    Scans autostart registry locations for suspicious entries
    and checks key permissions.
    """

    TECHNIQUE_ID = "T1547.001"
    TECHNIQUE_NAME = "Boot or Logon Autostart Execution: Registry Run Keys"
    TACTIC = "Persistence"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_run_keys(session, result)
        self._check_winlogon(session, result)
        self._check_run_key_permissions(session, result)
        self._check_startup_folder(session, result)
        self._check_registry_audit(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_run_keys(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Run and RunOnce registry keys for entries."""
        for hive, key, desc, severity in _AUTOSTART_KEYS:
            if "Winlogon" in key:
                continue  # Handled separately

            entries = session.run_powershell(
                f"Get-ItemProperty -Path '{hive}:\\{key}' "
                f"-ErrorAction SilentlyContinue | "
                f"Select-Object * -ExcludeProperty PS* | "
                f"ConvertTo-Json -Compress"
            )
            if not entries or not entries.stdout.strip() or entries.stdout.strip() in ("", "null", "{}"):
                continue

            # Parse and check each value
            values = session.run_powershell(
                f"(Get-Item -Path '{hive}:\\{key}' "
                f"-ErrorAction SilentlyContinue).Property"
            )
            if not values or not values.stdout.strip():
                continue

            for name in values.stdout.strip().splitlines():
                name = name.strip()
                if not name:
                    continue

                val = session.read_registry(hive, key, name)
                if not val:
                    continue

                val_lower = str(val).lower()
                # Flag entries with scripting engines or network paths
                suspicious = any(
                    s in val_lower
                    for s in ("powershell", "cmd /c", "wscript", "cscript",
                              "mshta", "regsvr32", "rundll32",
                              "http://", "https://", "\\\\")
                )

                if suspicious:
                    self.add_finding(
                        result,
                        description=f"Suspicious autostart entry in {desc}: {name}",
                        severity=severity,
                        evidence=f"Key: {hive}\\{key}\nValue: {name} = {val}",
                        recommendation=(
                            f"Investigate autostart entry '{name}'. Entries running "
                            f"scripting engines or referencing network paths may "
                            f"indicate persistence."
                        ),
                        cwe="CWE-284",
                    )

    def _check_winlogon(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Winlogon Shell and Userinit for tampering."""
        shell = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
        )
        if shell:
            shell_val = str(shell).strip().lower()
            if shell_val not in ("explorer.exe", ""):
                self.add_finding(
                    result,
                    description=f"Winlogon Shell has been modified: {shell}",
                    severity=Severity.CRITICAL,
                    evidence=f"Winlogon\\Shell = {shell}",
                    recommendation=(
                        "Winlogon Shell should be 'explorer.exe'. Any other "
                        "value indicates tampering or malicious persistence."
                    ),
                    cwe="CWE-284",
                )

        userinit = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Userinit",
        )
        if userinit:
            init_val = str(userinit).strip().lower().rstrip(",")
            expected = r"c:\windows\system32\userinit.exe"
            if init_val != expected:
                self.add_finding(
                    result,
                    description=f"Winlogon Userinit has been modified: {userinit}",
                    severity=Severity.CRITICAL,
                    evidence=f"Winlogon\\Userinit = {userinit}",
                    recommendation=(
                        "Userinit should be 'C:\\Windows\\system32\\userinit.exe,'. "
                        "Additional entries indicate persistence."
                    ),
                    cwe="CWE-284",
                )

    def _check_run_key_permissions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if HKLM Run key is writable by non-admins."""
        acl = session.run_powershell(
            "(Get-Acl 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' "
            "-ErrorAction SilentlyContinue).Access | "
            "Where-Object { "
            "  $_.IdentityReference -match 'Users|Everyone|Authenticated Users' "
            "  -and $_.RegistryRights -match 'SetValue|FullControl' "
            "} | Select-Object IdentityReference, RegistryRights | "
            "ConvertTo-Json -Compress"
        )
        if acl and acl.stdout.strip() and acl.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="HKLM Run key is writable by non-admin users (persistence risk)",
                severity=Severity.HIGH,
                evidence=acl.stdout[:500],
                recommendation=(
                    "Fix permissions on HKLM\\SOFTWARE\\Microsoft\\Windows\\"
                    "CurrentVersion\\Run. Only Administrators should have write access."
                ),
                cwe="CWE-732",
            )

    def _check_startup_folder(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for non-standard items in Startup folders."""
        startup_items = session.run_powershell(
            "$paths = @("
            "  [Environment]::GetFolderPath('Startup'), "
            "  [Environment]::GetFolderPath('CommonStartup') "
            "); "
            "$paths | ForEach-Object { "
            "  if ($_ -and (Test-Path $_)) { "
            "    Get-ChildItem $_ -File -ErrorAction SilentlyContinue | "
            "    Select-Object Name, FullName, Extension "
            "  } "
            "} | ConvertTo-Json -Compress"
        )
        if startup_items and startup_items.stdout.strip() and startup_items.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Items found in Startup folder(s)",
                severity=Severity.MEDIUM,
                evidence=startup_items.stdout[:500],
                recommendation=(
                    "Review Startup folder contents. Shortcuts and executables "
                    "here run at logon and are a common persistence mechanism."
                ),
            )

    def _check_registry_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if registry modification auditing is enabled."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Registry' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="Registry auditing is not enabled — Run key changes are not logged",
                severity=Severity.MEDIUM,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Registry' (Success) to detect Run key "
                    "modifications. Event ID 4657 logs registry value changes."
                ),
                cwe="CWE-778",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_cmd(
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run 2>nul"
        )
        if out:
            self.add_finding(
                result, description="Simulated: Run key enumeration",
                severity=Severity.INFO, evidence=out.stdout[:500],
                recommendation="Monitor registry autostart key modifications",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1024 — Restrict Registry Permissions: Lock down HKLM Run key ACLs",
            "M1047 — Audit: Enable Registry auditing (Event ID 4657)",
            "M1038 — Execution Prevention: Use AppLocker to restrict autostart execution",
            "M1022 — Restrict File and Directory Permissions: Protect Startup folders",
        ]
