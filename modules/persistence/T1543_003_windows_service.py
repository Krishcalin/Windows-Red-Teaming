"""T1543.003 — Create or Modify System Process: Windows Service.

Adversaries install or modify Windows services for persistence and privilege
escalation, frequently as SYSTEM. This module passively audits service
configurations for the weaknesses attackers exploit: unquoted service paths,
service binaries in user-writable locations, and auto-start services running
from suspicious directories.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Directories any standard user can typically write to.
_USER_WRITABLE = (
    "\\users\\", "\\appdata\\", "\\temp\\", "\\tmp\\",
    "\\programdata\\", "\\public\\", "\\downloads\\",
)


class WindowsServiceCheck(BaseModule):
    """Audit Windows service configurations for persistence weaknesses (T1543.003)."""

    TECHNIQUE_ID = "T1543.003"
    TECHNIQUE_NAME = "Create or Modify System Process: Windows Service"
    TACTIC = "Persistence"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [
        OSType.WIN10, OSType.WIN11,
        OSType.SERVER_2019, OSType.SERVER_2022,
    ]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_unquoted_paths(session, result)
        self._check_user_writable_binaries(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_unquoted_paths(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Unquoted ImagePaths containing spaces enable binary-planting hijacks."""
        services = session.run_powershell(
            "Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | "
            "Where-Object { $_.PathName -and $_.PathName -notmatch '^\\\"' "
            "-and $_.PathName -match ' ' -and $_.PathName -notmatch '^[A-Za-z]:\\\\Windows' } | "
            "Select-Object Name, PathName, StartMode, StartName | "
            "ConvertTo-Json -Compress"
        )
        out = services.stdout.strip() if services and services.stdout else ""
        if out and out not in ("", "null", "[]"):
            self.add_finding(
                result,
                description="Unquoted service path(s) with spaces detected — vulnerable to binary planting",
                severity=Severity.HIGH,
                evidence=out[:1200],
                recommendation=(
                    "Quote the ImagePath for each affected service "
                    "(e.g. \"C:\\Program Files\\App\\svc.exe\")."
                ),
                cwe="CWE-428",
            )
        else:
            self.add_finding(
                result,
                description="No unquoted service paths with spaces detected",
                severity=Severity.INFO,
                evidence="All non-Windows service paths are quoted or space-free",
                recommendation="No action required.",
            )

    def _check_user_writable_binaries(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Service binaries under user-writable dirs can be replaced for persistence."""
        services = session.run_powershell(
            "Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | "
            "Select-Object Name, PathName, StartMode, StartName | "
            "ConvertTo-Json -Compress"
        )
        out = services.stdout if services and services.stdout else ""
        lowered = out.lower()
        hits = [d for d in _USER_WRITABLE if d in lowered]
        if hits:
            self.add_finding(
                result,
                description="Service binary path(s) located in user-writable directories — persistence/escalation risk",
                severity=Severity.HIGH,
                evidence=f"Matched directories: {', '.join(sorted(set(hits)))}\n{out[:1000]}",
                recommendation=(
                    "Relocate service binaries to protected paths (e.g. Program Files) "
                    "and restrict directory write permissions."
                ),
                cwe="CWE-732",
            )
        else:
            self.add_finding(
                result,
                description="No service binaries found in user-writable directories",
                severity=Severity.INFO,
                evidence="Service ImagePaths reside in protected locations",
                recommendation="No action required.",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        enum = session.run_powershell(
            "Get-Service -ErrorAction SilentlyContinue | "
            "Where-Object { $_.StartType -eq 'Automatic' } | "
            "Measure-Object | Select-Object -ExpandProperty Count"
        )
        self.add_finding(
            result,
            description="Simulated: enumerated auto-start services (no service created or modified)",
            severity=Severity.INFO,
            evidence=(
                f"Automatic-start services: {enum.stdout.strip()}"
                if enum and enum.stdout else "read-only enumeration"
            ),
            recommendation="Monitor Event ID 7045 for new service installations.",
        )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1018 — User Account Management: Restrict who can create or modify services",
            "M1038 — Execution Prevention: Use WDAC/AppLocker to control service binaries",
            "M1024 — Restrict Registry Permissions: Lock down service keys under HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "M1047 — Audit: Monitor Event ID 7045 (new service) and 7040 (start-type change)",
            "M1022 — Restrict File and Directory Permissions: Quote service paths and protect binary directories",
        ]
