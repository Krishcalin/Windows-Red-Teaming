"""T1552.001 — Unsecured Credentials: Credentials in Files.

Scans for credentials stored in plaintext files including
scripts, configuration files, XML deployment files, and
common credential storage locations.
"""

from __future__ import annotations

import re

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Credential patterns to search for in file contents
_CREDENTIAL_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?.{4,}', "Password in plaintext"),
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?.{8,}', "API key in plaintext"),
    (r'(?i)(secret|token)\s*[:=]\s*["\']?.{8,}', "Secret/token in plaintext"),
    (r'(?i)(connection[_-]?string)\s*[:=]\s*["\']?.{10,}', "Connection string"),
    (r'(?i)(aws_access_key_id)\s*[:=]\s*[A-Z0-9]{16,}', "AWS access key"),
    (r'(?i)(aws_secret_access_key)\s*[:=]\s*.{20,}', "AWS secret key"),
]

# File locations and extensions to scan
_SCAN_TARGETS = [
    # Unattend / sysprep files (often contain admin passwords)
    (r"C:\Windows\Panther\unattend.xml", "Sysprep unattend file", Severity.CRITICAL),
    (r"C:\Windows\Panther\Unattend\unattend.xml", "Sysprep unattend file", Severity.CRITICAL),
    (r"C:\Windows\System32\sysprep\unattend.xml", "Sysprep unattend file", Severity.CRITICAL),
    (r"C:\Windows\System32\sysprep\sysprep.xml", "Sysprep config", Severity.CRITICAL),
    # Group Policy preference files
    (r"C:\Windows\SYSVOL\*\Policies\*\Machine\Preferences\Groups\Groups.xml",
     "GPP Groups.xml (cPassword)", Severity.CRITICAL),
    (r"C:\Windows\SYSVOL\*\Policies\*\Machine\Preferences\Services\Services.xml",
     "GPP Services.xml (cPassword)", Severity.CRITICAL),
    (r"C:\Windows\SYSVOL\*\Policies\*\Machine\Preferences\Scheduledtasks\Scheduledtasks.xml",
     "GPP ScheduledTasks.xml (cPassword)", Severity.CRITICAL),
    # IIS config
    (r"C:\inetpub\wwwroot\web.config", "IIS web.config", Severity.HIGH),
    # PowerShell transcripts
    (r"C:\Users\*\Documents\PowerShell_transcript*",
     "PowerShell transcript file", Severity.MEDIUM),
]


class CredentialsInFilesCheck(BaseModule):
    """T1552.001 — Credentials in Files audit.

    Scans for credentials in common deployment files,
    scripts, and configuration locations.
    """

    TECHNIQUE_ID = "T1552.001"
    TECHNIQUE_NAME = "Unsecured Credentials: Credentials in Files"
    TACTIC = "Credential Access"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_known_credential_files(session, result)
        self._check_gpp_cpassword(session, result)
        self._check_powershell_history(session, result)
        self._check_credential_manager(session, result)
        self._check_wifi_passwords(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_known_credential_files(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check known locations for credential files."""
        for path, description, severity in _SCAN_TARGETS:
            found = session.run_powershell(
                f"Get-Item -Path '{path}' -ErrorAction SilentlyContinue | "
                f"Select-Object -ExpandProperty FullName"
            )
            if found and found.stdout.strip():
                files = found.stdout.strip()

                # For XML files, check for password patterns
                evidence = f"Files: {files}"
                if path.endswith(".xml"):
                    content = session.run_powershell(
                        f"Select-String -Path '{path}' -Pattern "
                        f"'password|cpassword|credential|connectionString' "
                        f"-ErrorAction SilentlyContinue | "
                        f"Select-Object -First 5 -ExpandProperty Line"
                    )
                    if content and content.stdout.strip():
                        evidence += f"\nMatching lines:\n{content.stdout.strip()}"
                        # Redact actual values
                        severity = Severity.CRITICAL

                self.add_finding(
                    result,
                    description=f"{description}: {files}",
                    severity=severity,
                    evidence=evidence[:500],
                    recommendation=(
                        "Remove credential files from disk. Use Windows Credential "
                        "Manager, Azure Key Vault, or DPAPI for secret storage."
                    ),
                    cwe="CWE-256",
                )

    def _check_gpp_cpassword(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for Group Policy Preferences cPassword (MS14-025)."""
        gpp = session.run_powershell(
            "Get-ChildItem -Path '\\\\$env:USERDNSDOMAIN\\SYSVOL' "
            "-Filter '*.xml' -Recurse -ErrorAction SilentlyContinue | "
            "Select-String -Pattern 'cpassword' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Path -Unique"
        )
        if gpp and gpp.stdout.strip():
            self.add_finding(
                result,
                description="Group Policy Preferences with cPassword found (MS14-025)",
                severity=Severity.CRITICAL,
                evidence=gpp.stdout.strip(),
                recommendation=(
                    "Remove GPP files containing cPassword immediately. The AES key "
                    "is published by Microsoft, making decryption trivial. "
                    "Apply MS14-025 and use LAPS for local admin passwords."
                ),
                cwe="CWE-256",
            )

    def _check_powershell_history(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if PowerShell history files contain credentials."""
        history = session.run_powershell(
            "Get-ChildItem -Path 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\"
            "Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt' "
            "-ErrorAction SilentlyContinue | ForEach-Object { "
            "  $matches = Select-String -Path $_.FullName "
            "    -Pattern 'password|secret|token|credential|apikey|ConvertTo-SecureString' "
            "    -ErrorAction SilentlyContinue; "
            "  if ($matches) { "
            "    [PSCustomObject]@{ File=$_.FullName; Matches=$matches.Count } "
            "  } "
            "} | ConvertTo-Json -Compress"
        )
        if history and history.stdout.strip() and history.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="PowerShell history files contain potential credential references",
                severity=Severity.HIGH,
                evidence=history.stdout[:500],
                recommendation=(
                    "Clear sensitive entries from PowerShell history. Consider "
                    "setting $env:PSReadLineOption to not save sensitive commands: "
                    "Set-PSReadLineOption -AddToHistoryHandler { ... }"
                ),
                cwe="CWE-532",
            )

    def _check_credential_manager(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Windows Credential Manager for stored credentials."""
        creds = session.run_powershell(
            "cmdkey /list 2>$null"
        )
        if creds and creds.stdout.strip():
            lines = creds.stdout.strip().splitlines()
            target_count = sum(1 for l in lines if "Target:" in l)
            if target_count > 0:
                self.add_finding(
                    result,
                    description=f"Windows Credential Manager has {target_count} stored credential(s)",
                    severity=Severity.LOW,
                    evidence=creds.stdout[:500],
                    recommendation=(
                        "Review stored credentials in Credential Manager. "
                        "Adversaries can extract these with tools like Mimikatz "
                        "(sekurlsa::credman)."
                    ),
                )

    def _check_wifi_passwords(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Wi-Fi passwords are accessible."""
        wifi = session.run_cmd(
            "netsh wlan show profiles 2>nul"
        )
        if wifi and wifi.stdout.strip() and "All User Profile" in wifi.stdout:
            profiles = [
                l.split(":")[-1].strip()
                for l in wifi.stdout.splitlines()
                if "All User Profile" in l
            ]
            if profiles:
                self.add_finding(
                    result,
                    description=f"Wi-Fi profiles with stored passwords found ({len(profiles)} profiles)",
                    severity=Severity.LOW,
                    evidence=f"Wi-Fi profiles: {', '.join(profiles[:10])}",
                    recommendation=(
                        "Wi-Fi passwords can be extracted with "
                        "'netsh wlan show profile name=X key=clear'. "
                        "Use 802.1X/EAP instead of PSK for enterprise networks."
                    ),
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate credential file hunting."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("findstr /si password *.xml *.ini *.txt *.config 2>nul",
             "Credential keyword search in common file types"),
            ("cmdkey /list",
             "Credential Manager enumeration"),
        ]
        for cmd, desc in commands:
            out = session.run_cmd(cmd, timeout=15)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500] if out.stdout else "No output",
                    recommendation="Monitor for bulk file searches with credential keywords",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1027 — Password Policies: Remove plaintext passwords from files and scripts",
            "M1022 — Restrict File and Directory Permissions: Lock down SYSVOL and deployment shares",
            "M1047 — Audit: Monitor file access to known credential locations",
            "M1041 — Encrypt Sensitive Information: Use DPAPI, Key Vault, or secrets managers",
        ]
