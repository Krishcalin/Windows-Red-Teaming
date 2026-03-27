"""T1041 — Exfiltration Over C2 Channel.

Checks for data exfiltration capabilities over existing
command and control channels, including DLP status, clipboard
restrictions, available transfer tools, and firewall logging.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class C2ChannelExfilCheck(BaseModule):
    """T1041 — Exfiltration over C2 channel audit.

    Evaluates DLP solution presence, clipboard redirection
    policies, available data transfer tools, and firewall
    logging configuration.
    """

    TECHNIQUE_ID = "T1041"
    TECHNIQUE_NAME = "Exfiltration Over C2 Channel"
    TACTIC = "Exfiltration"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_dlp_solutions(session, result)
        self._check_clipboard_redirection(session, result)
        self._check_transfer_tools(session, result)
        self._check_firewall_logging(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_dlp_solutions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for running DLP (Data Loss Prevention) solutions."""
        dlp = session.run_powershell(
            "Get-Process | Where-Object "
            "{$_.ProcessName -match 'dlp|endpoint|symantec|mcafee|forcepoint'} | "
            "Select-Object ProcessName | ConvertTo-Json"
        )
        if not dlp or not dlp.stdout.strip() or dlp.stdout.strip() in ("", "null"):
            self.add_finding(
                result,
                description="No DLP (Data Loss Prevention) solution detected running",
                severity=Severity.HIGH,
                evidence="No processes matching DLP vendor patterns found",
                recommendation=(
                    "Deploy a DLP solution to monitor and prevent unauthorized "
                    "data transfers. Solutions such as Microsoft Purview, Symantec "
                    "DLP, or Forcepoint can detect exfiltration attempts."
                ),
                cwe="CWE-200",
            )
        else:
            try:
                procs = json.loads(dlp.stdout)
                if isinstance(procs, dict):
                    procs = [procs]
                names = [p.get("ProcessName", "") for p in procs]
                self.add_finding(
                    result,
                    description=f"DLP solution processes detected: {', '.join(names)}",
                    severity=Severity.INFO,
                    evidence=dlp.stdout[:500],
                    recommendation="Verify DLP policies are properly configured and enforced",
                )
            except json.JSONDecodeError:
                pass

    def _check_clipboard_redirection(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if clipboard redirection is disabled for RDP sessions."""
        clip = session.run_cmd(
            'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT'
            '\\Terminal Services" /v fDisableClip'
        )
        if not clip or not clip.stdout or "ERROR" in clip.stdout:
            self.add_finding(
                result,
                description="RDP clipboard redirection is not restricted",
                severity=Severity.MEDIUM,
                evidence="Registry value fDisableClip not configured",
                recommendation=(
                    "Disable clipboard redirection for RDP sessions via GPO: "
                    "Computer Configuration > Administrative Templates > "
                    "Windows Components > Remote Desktop Services > "
                    "Device and Resource Redirection > Do not allow clipboard redirection."
                ),
                cwe="CWE-200",
            )
        else:
            if "0x0" in clip.stdout:
                self.add_finding(
                    result,
                    description="RDP clipboard redirection is explicitly allowed (fDisableClip=0)",
                    severity=Severity.MEDIUM,
                    evidence=clip.stdout.strip()[:300],
                    recommendation=(
                        "Set fDisableClip to 1 to prevent data exfiltration "
                        "via RDP clipboard redirection."
                    ),
                    cwe="CWE-200",
                )

    def _check_transfer_tools(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for available outbound data transfer tools."""
        tools = session.run_powershell(
            "Get-Command curl,wget,certutil,bitsadmin "
            "-ErrorAction SilentlyContinue | "
            "Select-Object Name,Source | ConvertTo-Json"
        )
        if tools and tools.stdout.strip() and tools.stdout.strip() not in ("", "null"):
            try:
                tool_list = json.loads(tools.stdout)
                if isinstance(tool_list, dict):
                    tool_list = [tool_list]
            except json.JSONDecodeError:
                tool_list = []

            if tool_list:
                names = [t.get("Name", "") for t in tool_list]
                self.add_finding(
                    result,
                    description=f"Data transfer tools available: {', '.join(names)}",
                    severity=Severity.MEDIUM,
                    evidence=tools.stdout[:500],
                    recommendation=(
                        "Restrict access to data transfer utilities via AppLocker "
                        "or WDAC policies. Tools like certutil and bitsadmin are "
                        "commonly used for exfiltration over C2 channels."
                    ),
                    cwe="CWE-284",
                )

    def _check_firewall_logging(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Windows Firewall logging is enabled."""
        fw_log = session.run_powershell(
            "Get-NetFirewallProfile | "
            "Select-Object Name,LogAllowed,LogBlocked,LogFileName | "
            "ConvertTo-Json"
        )
        if not fw_log or not fw_log.stdout.strip():
            return

        try:
            profiles = json.loads(fw_log.stdout)
            if isinstance(profiles, dict):
                profiles = [profiles]
        except json.JSONDecodeError:
            return

        unlogged = []
        for profile in profiles:
            name = profile.get("Name", "Unknown")
            log_allowed = str(profile.get("LogAllowed", "")).lower()
            log_blocked = str(profile.get("LogBlocked", "")).lower()
            if log_allowed in ("false", "0") and log_blocked in ("false", "0"):
                unlogged.append(name)

        if unlogged:
            self.add_finding(
                result,
                description=f"Firewall logging disabled on profile(s): {', '.join(unlogged)}",
                severity=Severity.MEDIUM,
                evidence=fw_log.stdout[:500],
                recommendation=(
                    "Enable firewall logging for both allowed and blocked "
                    "connections on all profiles. Logs are essential for "
                    "detecting exfiltration attempts."
                ),
                cwe="CWE-778",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate C2 channel exfiltration enumeration."""
        result = self.create_result(target_host=session.target.host, simulated=True)

        # Enumerate available transfer tools with their paths
        tools = session.run_powershell(
            "Get-Command curl,wget,certutil,bitsadmin,Invoke-WebRequest,"
            "Invoke-RestMethod,Start-BitsTransfer "
            "-ErrorAction SilentlyContinue | "
            "Select-Object Name,Source,CommandType | ConvertTo-Json"
        )
        if tools and tools.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Enumerated available data transfer tools",
                severity=Severity.INFO,
                evidence=tools.stdout[:500],
                recommendation="Monitor usage of data transfer tools for anomalous activity",
            )

        # Check firewall log existence
        log_exists = session.run_powershell(
            "Test-Path (Get-NetFirewallProfile -Name Domain).LogFileName"
        )
        if log_exists and log_exists.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Firewall log file existence check",
                severity=Severity.INFO,
                evidence=f"Domain firewall log exists: {log_exists.stdout.strip()}",
                recommendation=(
                    "Ensure firewall logs are collected and forwarded to a "
                    "SIEM for analysis"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1057 — Data Loss Prevention: Deploy DLP to detect and block data exfiltration",
            "M1031 — Network Intrusion Prevention: Monitor for large or anomalous outbound transfers",
            "M1037 — Filter Network Traffic: Restrict outbound traffic to approved destinations",
            "M1038 — Execution Prevention: Use AppLocker/WDAC to restrict data transfer tools",
        ]
