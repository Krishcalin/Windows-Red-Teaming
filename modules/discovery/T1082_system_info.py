"""T1082 — System Information Discovery.

Checks what system information is exposed and whether security
controls like Credential Guard, Secure Boot, BitLocker, and
Virtualization-Based Security (VBS) are properly configured.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class SystemInfoDiscovery(BaseModule):
    """T1082 — System Information Discovery.

    Enumerates system information that an adversary could gather
    to fingerprint the target and plan further attacks.
    """

    TECHNIQUE_ID = "T1082"
    TECHNIQUE_NAME = "System Information Discovery"
    TACTIC = "Discovery"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Gather baseline OS info ──────────────────────────────
        os_info = session.run_powershell(
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption, Version, BuildNumber, OSArchitecture, "
            "LastBootUpTime | Format-List"
        )
        if os_info:
            result.target_host = session.target.host
            self._log.info("os_info_collected", output=os_info.stdout[:200])

        # ── Check Credential Guard ───────────────────────────────
        cg = session.run_powershell(
            "(Get-CimInstance -ClassName Win32_DeviceGuard "
            "-Namespace root/Microsoft/Windows/DeviceGuard "
            "-ErrorAction SilentlyContinue).SecurityServicesRunning"
        )
        if cg and cg.stdout.strip():
            services = cg.stdout.strip()
            if "1" not in services:
                self.add_finding(
                    result,
                    description="Credential Guard is not running",
                    severity=Severity.HIGH,
                    evidence=f"SecurityServicesRunning = {services}",
                    recommendation=(
                        "Enable Credential Guard via Group Policy: "
                        "Computer Configuration > Administrative Templates > "
                        "System > Device Guard > Turn On Virtualization Based Security"
                    ),
                    cwe="CWE-522",
                )
        else:
            self.add_finding(
                result,
                description="Credential Guard status could not be determined (DeviceGuard WMI unavailable)",
                severity=Severity.MEDIUM,
                evidence=cg.stderr if cg else "No output",
                recommendation="Verify Credential Guard support and enable if possible",
            )

        # ── Check Secure Boot ────────────────────────────────────
        sb = session.run_powershell(
            "try { Confirm-SecureBootUEFI } catch { 'unsupported' }"
        )
        if sb:
            val = sb.stdout.strip().lower()
            if val == "false":
                self.add_finding(
                    result,
                    description="Secure Boot is disabled",
                    severity=Severity.HIGH,
                    evidence="Confirm-SecureBootUEFI returned False",
                    recommendation="Enable Secure Boot in UEFI/BIOS firmware settings",
                    cwe="CWE-693",
                )
            elif val == "unsupported":
                self.add_finding(
                    result,
                    description="Secure Boot is not supported on this system",
                    severity=Severity.MEDIUM,
                    evidence="Confirm-SecureBootUEFI threw unsupported exception",
                    recommendation="Consider hardware that supports UEFI Secure Boot",
                )

        # ── Check Virtualization-Based Security (VBS) ────────────
        vbs = session.run_powershell(
            "(Get-CimInstance -ClassName Win32_DeviceGuard "
            "-Namespace root/Microsoft/Windows/DeviceGuard "
            "-ErrorAction SilentlyContinue).VirtualizationBasedSecurityStatus"
        )
        if vbs and vbs.stdout.strip():
            status = vbs.stdout.strip()
            if status != "2":
                self.add_finding(
                    result,
                    description=f"Virtualization-Based Security is not running (status={status})",
                    severity=Severity.MEDIUM,
                    evidence=f"VirtualizationBasedSecurityStatus = {status}",
                    recommendation=(
                        "Enable VBS via Group Policy or DISM. "
                        "Status 0=disabled, 1=enabled-not-running, 2=running"
                    ),
                )

        # ── Check BitLocker on OS drive ──────────────────────────
        bl = session.run_powershell(
            "(Get-BitLockerVolume -MountPoint $env:SystemDrive "
            "-ErrorAction SilentlyContinue).ProtectionStatus"
        )
        if bl and bl.stdout.strip():
            if bl.stdout.strip() != "On":
                self.add_finding(
                    result,
                    description="BitLocker is not enabled on the OS drive",
                    severity=Severity.MEDIUM,
                    evidence=f"ProtectionStatus = {bl.stdout.strip()}",
                    recommendation="Enable BitLocker full-disk encryption on the OS drive",
                    cwe="CWE-311",
                )
        else:
            self.add_finding(
                result,
                description="BitLocker status could not be determined",
                severity=Severity.LOW,
                evidence=bl.stderr if bl else "No output",
                recommendation="Verify BitLocker is available and properly configured",
            )

        # ── Check if last boot was recent (reboot hygiene) ───────
        uptime = session.run_powershell(
            "((Get-Date) - (Get-CimInstance Win32_OperatingSystem)"
            ".LastBootUpTime).Days"
        )
        if uptime and uptime.stdout.strip().isdigit():
            days = int(uptime.stdout.strip())
            if days > 90:
                self.add_finding(
                    result,
                    description=f"System has not been rebooted in {days} days",
                    severity=Severity.LOW,
                    evidence=f"Uptime: {days} days",
                    recommendation=(
                        "Regular reboots ensure pending security patches are applied. "
                        "Consider a monthly reboot schedule."
                    ),
                )

        # ── Check OS version / build for EOL ─────────────────────
        build = session.run_powershell(
            "(Get-CimInstance Win32_OperatingSystem).BuildNumber"
        )
        if build and build.stdout.strip():
            build_num = build.stdout.strip()
            # Windows 10 builds below 19044 (21H2) are EOL
            if build_num.isdigit() and int(build_num) < 19044:
                self.add_finding(
                    result,
                    description=f"OS build {build_num} may be end-of-life and no longer receiving security updates",
                    severity=Severity.HIGH,
                    evidence=f"BuildNumber = {build_num}",
                    recommendation="Upgrade to a supported Windows version that receives security updates",
                    cwe="CWE-1104",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary system enumeration commands."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        recon_commands = [
            ("systeminfo", "Full system information dump"),
            ("hostname", "Hostname discovery"),
            ("wmic os get Caption,Version,BuildNumber /format:list",
             "OS version via WMI"),
            ("wmic bios get SerialNumber,Manufacturer /format:list",
             "BIOS/hardware fingerprint"),
        ]

        for cmd, desc in recon_commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Restrict WMI access and limit local user privileges",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass  # Read-only checks — nothing to revert

    def get_mitigations(self) -> list[str]:
        return [
            "M1028 — Operating System Configuration: Enable Credential Guard, VBS, and Secure Boot",
            "M1057 — Data Loss Prevention: Enable BitLocker full-disk encryption",
            "M1026 — Privileged Account Management: Limit access to system information commands",
            "M1018 — User Account Management: Restrict WMI namespace access to administrators",
        ]
