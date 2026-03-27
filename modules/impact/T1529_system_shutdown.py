"""T1529 — System Shutdown/Reboot.

Checks whether the system is vulnerable to unauthorized shutdown
or reboot by evaluating shutdown privileges, policies, and
event tracking configuration.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class SystemShutdownCheck(BaseModule):
    """T1529 — System Shutdown/Reboot audit.

    Evaluates shutdown and reboot controls including privilege
    assignments, logon requirements, and shutdown event tracking.
    """

    TECHNIQUE_ID = "T1529"
    TECHNIQUE_NAME = "System Shutdown/Reboot"
    TACTIC = "Impact"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_shutdown_privilege(session, result)
        self._check_shutdown_policy(session, result)
        self._check_power_settings(session, result)
        self._check_shutdown_tracking(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_shutdown_privilege(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if shutdown privilege is assigned to current user."""
        priv = session.run_powershell(
            'whoami /priv | Select-String "SeShutdownPrivilege"'
        )
        if priv and "SeShutdownPrivilege" in priv.stdout:
            enabled = "Enabled" in priv.stdout
            self.add_finding(
                result,
                description=(
                    "Current user has SeShutdownPrivilege"
                    f" ({'enabled' if enabled else 'disabled'})"
                ),
                severity=Severity.MEDIUM if enabled else Severity.LOW,
                evidence=priv.stdout.strip()[:300],
                recommendation=(
                    "Review shutdown privilege assignments. On servers, "
                    "restrict SeShutdownPrivilege to Administrators only."
                ),
                cwe="CWE-269",
            )

    def _check_shutdown_policy(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if shutdown without logon is allowed."""
        policy = session.run_cmd(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows'
            '\\CurrentVersion\\Policies\\System" '
            "/v ShutdownWithoutLogon"
        )
        if not policy or "ShutdownWithoutLogon" not in policy.stdout:
            return

        if "0x1" in policy.stdout:
            self.add_finding(
                result,
                description="Shutdown without logon is allowed",
                severity=Severity.MEDIUM,
                evidence=policy.stdout.strip()[:300],
                recommendation=(
                    "Disable 'Shutdown: Allow system to be shut down "
                    "without having to log on' policy on servers to prevent "
                    "unauthorized physical shutdown."
                ),
                cwe="CWE-284",
            )

    def _check_power_settings(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check UPS/battery and power settings."""
        battery = session.run_powershell(
            "Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | "
            "Select-Object BatteryStatus | ConvertTo-Json"
        )
        if battery and battery.stdout.strip() and battery.stdout.strip() not in ("", "null"):
            try:
                data = json.loads(battery.stdout)
            except json.JSONDecodeError:
                return

            status = data.get("BatteryStatus")
            if status:
                self.add_finding(
                    result,
                    description=f"System has battery/UPS (BatteryStatus: {status})",
                    severity=Severity.INFO,
                    evidence=f"BatteryStatus: {status}",
                    recommendation=(
                        "Ensure UPS is configured with appropriate shutdown "
                        "thresholds and alerts for power loss events"
                    ),
                )

    def _check_shutdown_tracking(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if shutdown event tracking is enabled."""
        tracking = session.run_cmd(
            'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft'
            '\\Windows NT\\Reliability" /v ShutdownReasonOn'
        )
        if not tracking or "ShutdownReasonOn" not in tracking.stdout:
            self.add_finding(
                result,
                description="Shutdown Event Tracker is not configured",
                severity=Severity.MEDIUM,
                evidence="ShutdownReasonOn registry value not found",
                recommendation=(
                    "Enable Shutdown Event Tracker via Group Policy to "
                    "require a reason for each shutdown/reboot. This aids "
                    "in forensic investigation of unexpected shutdowns."
                ),
                cwe="CWE-778",
            )
            return

        if "0x0" in tracking.stdout:
            self.add_finding(
                result,
                description="Shutdown Event Tracker is disabled (ShutdownReasonOn = 0)",
                severity=Severity.MEDIUM,
                evidence=tracking.stdout.strip()[:300],
                recommendation=(
                    "Enable Shutdown Event Tracker by setting "
                    "ShutdownReasonOn to 1 in Group Policy"
                ),
                cwe="CWE-778",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        # Check last boot time
        boot_time = session.run_powershell(
            "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"
        )
        if boot_time:
            self.add_finding(
                result,
                description="Simulated: Retrieved system last boot time",
                severity=Severity.INFO,
                evidence=f"LastBootUpTime: {boot_time.stdout.strip()[:200]}",
                recommendation="Monitor for unexpected reboot patterns",
            )

        # Check pending reboots
        pending = session.run_powershell(
            'Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows'
            '\\CurrentVersion\\Component Based Servicing\\RebootPending"'
        )
        if pending:
            self.add_finding(
                result,
                description=f"Simulated: Reboot pending = {pending.stdout.strip()}",
                severity=Severity.INFO,
                evidence=f"RebootPending: {pending.stdout.strip()[:200]}",
                recommendation="Monitor for pending reboot manipulation",
            )

        # List shutdown history
        history = session.run_powershell(
            "Get-WinEvent -FilterHashtable @{LogName='System';ID=1074} "
            "-MaxEvents 5 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated,Message | ConvertTo-Json"
        )
        if history and history.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Retrieved recent shutdown/reboot history",
                severity=Severity.INFO,
                evidence=history.stdout.strip()[:500],
                recommendation="Monitor for unusual shutdown patterns and frequencies",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1030 — Network Segmentation: Restrict remote shutdown access via firewall rules",
            "M1026 — Privileged Account Management: Limit SeShutdownPrivilege to administrators",
            "M1018 — User Account Management: Disable shutdown without logon on servers",
            "M1047 — Audit: Enable Shutdown Event Tracker and monitor Event ID 1074",
        ]
