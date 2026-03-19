"""T1083 — File and Directory Discovery.

Checks for sensitive files, insecure permissions on critical
directories, and exposed credentials or configuration data.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Paths where sensitive files are commonly found
_SENSITIVE_FILE_PATTERNS = [
    # Credential files
    (r"C:\Users\*\Desktop\*.txt", "Plaintext files on user desktops", Severity.LOW),
    (r"C:\Users\*\.ssh\*", "SSH keys in user profiles", Severity.HIGH),
    (r"C:\Users\*\.aws\credentials", "AWS credentials file", Severity.CRITICAL),
    (r"C:\Users\*\.azure\*", "Azure CLI credentials", Severity.HIGH),
    # Config files with potential secrets
    (r"C:\inetpub\wwwroot\web.config", "IIS web.config (may contain connection strings)", Severity.HIGH),
    (r"C:\Windows\Panther\unattend.xml", "Unattend.xml (may contain plaintext passwords)", Severity.CRITICAL),
    (r"C:\Windows\Panther\Unattend\unattend.xml", "Unattend.xml (alternate location)", Severity.CRITICAL),
    (r"C:\Windows\System32\sysprep\unattend.xml", "Sysprep unattend.xml", Severity.CRITICAL),
    # PowerShell history
    (r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
     "PowerShell command history (may contain credentials)", Severity.HIGH),
]


class FileDirectoryDiscovery(BaseModule):
    """T1083 — File and Directory Discovery.

    Identifies sensitive files, credential stores, and insecure
    directory permissions that an adversary could exploit.
    """

    TECHNIQUE_ID = "T1083"
    TECHNIQUE_NAME = "File and Directory Discovery"
    TACTIC = "Discovery"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Check for sensitive files ────────────────────────────
        self._check_sensitive_files(session, result)

        # ── Check directory permissions on critical paths ────────
        self._check_directory_permissions(session, result)

        # ── Check for world-writable directories in PATH ─────────
        self._check_path_permissions(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_sensitive_files(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Scan for known sensitive file locations."""
        for pattern, description, severity in _SENSITIVE_FILE_PATTERNS:
            check = session.run_powershell(
                f"Get-Item -Path '{pattern}' -ErrorAction SilentlyContinue | "
                f"Select-Object -ExpandProperty FullName"
            )
            if check and check.stdout.strip():
                files = check.stdout.strip()
                self.add_finding(
                    result,
                    description=f"{description} found",
                    severity=severity,
                    evidence=f"Files: {files}",
                    recommendation=(
                        "Remove or protect sensitive files. Encrypt credentials "
                        "at rest and restrict file ACLs."
                    ),
                    cwe="CWE-538",
                )

    def _check_directory_permissions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check permissions on critical system directories."""
        critical_dirs = [
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]

        for dir_path in critical_dirs:
            acl = session.run_powershell(
                f"(Get-Acl '{dir_path}' -ErrorAction SilentlyContinue).Access | "
                f"Where-Object {{ $_.IdentityReference -match 'Everyone|Users|Authenticated Users' "
                f"-and $_.FileSystemRights -match 'Write|Modify|FullControl' }} | "
                f"Select-Object IdentityReference, FileSystemRights | "
                f"ConvertTo-Json -Compress"
            )
            if acl and acl.stdout.strip() and acl.stdout.strip() != "":
                self.add_finding(
                    result,
                    description=f"Insecure write permissions on {dir_path}",
                    severity=Severity.HIGH,
                    evidence=acl.stdout[:500],
                    recommendation=(
                        f"Remove write/modify permissions for non-admin users on {dir_path}. "
                        f"This could allow DLL hijacking or binary planting."
                    ),
                    cwe="CWE-732",
                )

    def _check_path_permissions(
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
            "    }; "
            "    if ($weak) { $p } "
            "  } "
            "}"
        )
        if path_check and path_check.stdout.strip():
            dirs = path_check.stdout.strip()
            self.add_finding(
                result,
                description="Writable directories found in system PATH (DLL hijacking risk)",
                severity=Severity.HIGH,
                evidence=f"Writable PATH directories:\n{dirs}",
                recommendation=(
                    "Remove write permissions for non-admin users on all "
                    "directories in the system PATH. This prevents DLL "
                    "search order hijacking (T1574.001)."
                ),
                cwe="CWE-427",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary file/directory enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("dir /s /b C:\\Users\\*password* 2>nul",
             "Search for files containing 'password' in name"),
            ("dir /s /b C:\\Users\\*.kdbx 2>nul",
             "Search for KeePass database files"),
            ("where /R C:\\ *.config 2>nul",
             "Search for .config files"),
        ]

        for cmd, desc in commands:
            out = session.run_cmd(cmd, timeout=15)
            if out and out.stdout.strip():
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Encrypt sensitive files and restrict directory ACLs",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1022 — Restrict File and Directory Permissions: Enforce strict ACLs on sensitive directories",
            "M1057 — Data Loss Prevention: Monitor for bulk file enumeration activity",
            "M1047 — Audit: Enable file system auditing on sensitive directories",
            "M1041 — Encrypt Sensitive Information: Use DPAPI, BitLocker, or EFS for credentials at rest",
        ]
