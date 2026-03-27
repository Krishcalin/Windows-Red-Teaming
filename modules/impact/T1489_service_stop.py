"""T1489 — Service Stop.

Checks whether critical Windows services can be stopped by
attackers, evaluating service protection levels, permissions,
and recovery configurations.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class ServiceStopCheck(BaseModule):
    """T1489 — Service Stop audit.

    Evaluates whether critical services are protected against
    being stopped by attackers, including PPL configuration,
    service permissions, and recovery options.
    """

    TECHNIQUE_ID = "T1489"
    TECHNIQUE_NAME = "Service Stop"
    TACTIC = "Impact"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_critical_services(session, result)
        self._check_service_permissions(session, result)
        self._check_service_recovery(session, result)
        self._check_ppl_protection(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_critical_services(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check critical service status and start type."""
        svc = session.run_powershell(
            "Get-Service -Name WinDefend,EventLog,WSearch,MSSQLSERVER,wuauserv "
            "-ErrorAction SilentlyContinue | "
            "Select-Object Name,Status,StartType | ConvertTo-Json"
        )
        if not svc or not svc.stdout.strip():
            return

        try:
            services = json.loads(svc.stdout)
        except json.JSONDecodeError:
            return

        # Normalize to list for single-service results
        if isinstance(services, dict):
            services = [services]

        for service in services:
            name = service.get("Name", "unknown")
            status = str(service.get("Status", ""))
            start_type = str(service.get("StartType", ""))

            if status != "4":  # 4 = Running in JSON enum
                # Check string representation as well
                if "running" not in status.lower() and "4" not in status:
                    self.add_finding(
                        result,
                        description=f"Critical service '{name}' is not running",
                        severity=Severity.HIGH,
                        evidence=f"Service: {name}, Status: {status}, StartType: {start_type}",
                        recommendation=(
                            f"Ensure the '{name}' service is running and set to "
                            "Automatic start type"
                        ),
                        cwe="CWE-693",
                    )

    def _check_service_permissions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if services can be stopped by non-admins."""
        sd = session.run_cmd("sc.exe sdshow WinDefend")
        if not sd or not sd.stdout.strip():
            return

        sddl = sd.stdout.strip()
        # Check for broad permissions granted to Everyone (WD), Authenticated Users (AU),
        # or Users (BU) with RP (service stop) rights
        if any(group in sddl for group in (";;WD)", ";;AU)", ";;BU)")):
            if "RP" in sddl:
                self.add_finding(
                    result,
                    description="WinDefend service has weak permissions allowing non-admin stop",
                    severity=Severity.HIGH,
                    evidence=f"SDDL: {sddl[:300]}",
                    recommendation=(
                        "Restrict service permissions so only SYSTEM and "
                        "Administrators can stop critical services"
                    ),
                    cwe="CWE-732",
                )

    def _check_service_recovery(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check service recovery options for critical services."""
        recovery = session.run_powershell(
            "Get-CimInstance Win32_Service | "
            "Where-Object {$_.Name -in @('WinDefend','EventLog','wuauserv')} | "
            "Select-Object Name,StartMode | ConvertTo-Json"
        )
        if not recovery or not recovery.stdout.strip():
            return

        try:
            services = json.loads(recovery.stdout)
        except json.JSONDecodeError:
            return

        if isinstance(services, dict):
            services = [services]

        for service in services:
            name = service.get("Name", "unknown")
            start_mode = str(service.get("StartMode", ""))

            if start_mode.lower() not in ("auto", "automatic"):
                self.add_finding(
                    result,
                    description=f"Critical service '{name}' is not set to Automatic start",
                    severity=Severity.MEDIUM,
                    evidence=f"Service: {name}, StartMode: {start_mode}",
                    recommendation=(
                        f"Set '{name}' to Automatic start mode to ensure it "
                        "restarts after reboot"
                    ),
                )

    def _check_ppl_protection(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if PPL (Protected Process Light) is configured for critical services."""
        ppl = session.run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" '
            "/v LaunchProtected"
        )
        if not ppl or "LaunchProtected" not in ppl.stdout:
            self.add_finding(
                result,
                description="WinDefend does not have PPL (Protected Process Light) configured",
                severity=Severity.HIGH,
                evidence="LaunchProtected registry value not found for WinDefend",
                recommendation=(
                    "Enable Protected Process Light for Windows Defender to "
                    "prevent attackers from stopping or tampering with the service"
                ),
                cwe="CWE-693",
            )
            return

        # Check if value is 0 (not protected)
        if "0x0" in ppl.stdout:
            self.add_finding(
                result,
                description="WinDefend PPL protection is disabled (LaunchProtected = 0)",
                severity=Severity.HIGH,
                evidence=ppl.stdout.strip()[:300],
                recommendation=(
                    "Set LaunchProtected to a non-zero value to enable "
                    "Protected Process Light for Windows Defender"
                ),
                cwe="CWE-693",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        # Enumerate all running services
        count = session.run_powershell(
            "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
            "Measure-Object | Select-Object Count"
        )
        if count:
            self.add_finding(
                result,
                description="Simulated: Enumerated running services count",
                severity=Severity.INFO,
                evidence=count.stdout.strip()[:300],
                recommendation="Monitor for bulk service enumeration activity",
            )

        # Check service dependencies
        deps = session.run_powershell(
            "Get-Service WinDefend -DependentServices "
            "-ErrorAction SilentlyContinue | "
            "Select-Object Name,Status | ConvertTo-Json"
        )
        if deps:
            self.add_finding(
                result,
                description="Simulated: Enumerated WinDefend dependent services",
                severity=Severity.INFO,
                evidence=deps.stdout.strip()[:300],
                recommendation="Monitor for service dependency enumeration",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1030 — Network Segmentation: Restrict remote service management access",
            "M1022 — Restrict File and Directory Permissions: Limit service control permissions",
            "M1024 — Restrict Registry Permissions: Protect service registry keys",
            "M1047 — Audit: Monitor for service stop events (Event ID 7036)",
        ]
