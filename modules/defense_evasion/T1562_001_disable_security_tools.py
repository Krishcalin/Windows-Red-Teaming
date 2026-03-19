"""T1562.001 — Impair Defenses: Disable or Modify Tools.

Checks the status and configuration of security tools
including Windows Defender, EDR agents, firewall, and
tamper protection.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class DisableSecurityToolsCheck(BaseModule):
    """T1562.001 — Security tools status and tampering audit.

    Evaluates whether security tools are running, properly
    configured, and protected against tampering.
    """

    TECHNIQUE_ID = "T1562.001"
    TECHNIQUE_NAME = "Impair Defenses: Disable or Modify Tools"
    TACTIC = "Defense Evasion"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_defender_status(session, result)
        self._check_tamper_protection(session, result)
        self._check_defender_exclusions(session, result)
        self._check_realtime_protection(session, result)
        self._check_firewall_status(session, result)
        self._check_defender_asr(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_defender_status(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Windows Defender antimalware service is running."""
        svc = session.run_powershell(
            "(Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status"
        )
        if not svc or svc.stdout.strip().lower() != "running":
            self.add_finding(
                result,
                description="Windows Defender service (WinDefend) is not running",
                severity=Severity.CRITICAL,
                evidence=f"WinDefend status: {svc.stdout.strip() if svc else 'not found'}",
                recommendation=(
                    "Ensure Windows Defender is running. If a third-party AV "
                    "is deployed, verify it is active and up-to-date."
                ),
                cwe="CWE-693",
            )

        # Check if Defender is disabled via GPO
        disabled = session.read_registry(
            "HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            "DisableAntiSpyware",
        )
        if disabled is not None and str(disabled) == "1":
            self.add_finding(
                result,
                description="Windows Defender is disabled via Group Policy (DisableAntiSpyware)",
                severity=Severity.CRITICAL,
                evidence=f"DisableAntiSpyware = {disabled}",
                recommendation=(
                    "Remove DisableAntiSpyware GPO setting. This is commonly "
                    "set by malware to disable Defender."
                ),
                cwe="CWE-693",
            )

    def _check_tamper_protection(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Defender Tamper Protection is enabled."""
        tamper = session.run_powershell(
            "(Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected"
        )
        if tamper and tamper.stdout.strip().lower() == "false":
            self.add_finding(
                result,
                description="Windows Defender Tamper Protection is disabled",
                severity=Severity.HIGH,
                evidence="IsTamperProtected = False",
                recommendation=(
                    "Enable Tamper Protection in Windows Security settings "
                    "or via Microsoft Intune. Tamper Protection prevents "
                    "malware from disabling Defender."
                ),
            )

    def _check_defender_exclusions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for suspicious Defender exclusions."""
        exclusions = session.run_powershell(
            "$pref = Get-MpPreference -ErrorAction SilentlyContinue; "
            "@{ "
            "  Paths = $pref.ExclusionPath; "
            "  Extensions = $pref.ExclusionExtension; "
            "  Processes = $pref.ExclusionProcess "
            "} | ConvertTo-Json -Compress"
        )
        if not exclusions or not exclusions.stdout.strip():
            return

        try:
            excl = json.loads(exclusions.stdout)
        except json.JSONDecodeError:
            return

        paths = excl.get("Paths") or []
        extensions = excl.get("Extensions") or []
        processes = excl.get("Processes") or []

        # Dangerous exclusions
        dangerous_paths = [
            p for p in paths
            if any(d in str(p).lower() for d in
                   ("c:\\", "c:\\windows", "c:\\users", "temp", "appdata"))
        ]
        dangerous_ext = [
            e for e in extensions
            if str(e).lower() in (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs")
        ]

        if dangerous_paths:
            self.add_finding(
                result,
                description=f"Broad Defender path exclusions configured ({len(dangerous_paths)})",
                severity=Severity.HIGH,
                evidence=f"Excluded paths: {dangerous_paths}",
                recommendation=(
                    "Review and narrow Defender exclusions. Broad exclusions "
                    "allow malware to hide in excluded directories."
                ),
                cwe="CWE-693",
            )

        if dangerous_ext:
            self.add_finding(
                result,
                description=f"Dangerous Defender extension exclusions: {dangerous_ext}",
                severity=Severity.CRITICAL,
                evidence=f"Excluded extensions: {dangerous_ext}",
                recommendation="Remove executable extension exclusions (.exe, .dll, .ps1, etc.)",
                cwe="CWE-693",
            )

        if processes:
            self.add_finding(
                result,
                description=f"Defender process exclusions configured: {len(processes)} process(es)",
                severity=Severity.MEDIUM,
                evidence=f"Excluded processes: {processes}",
                recommendation="Review process exclusions for necessity",
            )

    def _check_realtime_protection(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Defender real-time protection and cloud delivery."""
        status = session.run_powershell(
            "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
            "@{ "
            "  RealTimeEnabled = $s.RealTimeProtectionEnabled; "
            "  BehaviorMonitor = $s.BehaviorMonitorEnabled; "
            "  IoavProtection = $s.IoavProtectionEnabled; "
            "  NISEnabled = $s.NISEnabled; "
            "  AntispywareEnabled = $s.AntispywareEnabled "
            "} | ConvertTo-Json -Compress"
        )
        if not status or not status.stdout.strip():
            return

        try:
            cfg = json.loads(status.stdout)
        except json.JSONDecodeError:
            return

        checks = [
            ("RealTimeEnabled", "Real-time protection", Severity.CRITICAL),
            ("BehaviorMonitor", "Behavior monitoring", Severity.HIGH),
            ("IoavProtection", "Download scanning (IOAV)", Severity.HIGH),
        ]

        for key, name, severity in checks:
            if str(cfg.get(key, "")).lower() == "false":
                self.add_finding(
                    result,
                    description=f"Defender {name} is disabled",
                    severity=severity,
                    evidence=f"{key} = {cfg.get(key)}",
                    recommendation=f"Enable Defender {name} immediately",
                    cwe="CWE-693",
                )

    def _check_firewall_status(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if any firewall profile is disabled."""
        fw = session.run_powershell(
            "Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | "
            "Select-Object Name | ConvertTo-Json -Compress"
        )
        if fw and fw.stdout.strip() and fw.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Windows Firewall has disabled profile(s)",
                severity=Severity.HIGH,
                evidence=fw.stdout[:300],
                recommendation="Enable Windows Firewall on all profiles (Domain, Private, Public)",
                cwe="CWE-284",
            )

    def _check_defender_asr(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Attack Surface Reduction rules are configured."""
        asr = session.run_powershell(
            "$ids = (Get-MpPreference -ErrorAction SilentlyContinue)"
            ".AttackSurfaceReductionRules_Ids; "
            "if ($ids) { $ids.Count } else { '0' }"
        )
        if asr:
            count = asr.stdout.strip()
            if count == "0":
                self.add_finding(
                    result,
                    description="No Attack Surface Reduction (ASR) rules are configured",
                    severity=Severity.MEDIUM,
                    evidence="ASR rules count: 0",
                    recommendation=(
                        "Deploy ASR rules via Intune or GPO to block common "
                        "attack vectors (Office macros, script obfuscation, "
                        "credential theft, etc.)"
                    ),
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_powershell(
            "Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List"
        )
        if out:
            self.add_finding(
                result, description="Simulated: Defender status enumeration",
                severity=Severity.INFO, evidence=out.stdout[:500],
                recommendation="Monitor for Defender status queries and configuration changes",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1049 — Antivirus/Antimalware: Ensure Defender is active with real-time protection",
            "M1040 — Behavior Prevention on Endpoint: Enable Tamper Protection",
            "M1038 — Execution Prevention: Deploy ASR rules for defense-in-depth",
            "M1047 — Audit: Monitor for Defender service stop events and configuration changes",
        ]
