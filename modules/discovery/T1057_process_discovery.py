"""T1057 — Process Discovery.

Checks for exposed process information, identifies security
tool processes (AV/EDR), and detects potentially malicious
or anomalous processes.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule

# Known security tool process names (AV/EDR/SIEM)
_SECURITY_PROCESSES = {
    "MsMpEng.exe": "Windows Defender Antimalware",
    "MsSense.exe": "Microsoft Defender for Endpoint (EDR)",
    "SenseIR.exe": "Microsoft Defender for Endpoint (IR)",
    "SenseCncProxy.exe": "Microsoft Defender for Endpoint (CNC)",
    "csfalconservice.exe": "CrowdStrike Falcon",
    "CSFalconContainer.exe": "CrowdStrike Falcon Container",
    "cb.exe": "Carbon Black",
    "CbDefense.exe": "Carbon Black Defense",
    "CylanceSvc.exe": "Cylance",
    "SentinelAgent.exe": "SentinelOne",
    "SentinelServiceHost.exe": "SentinelOne",
    "fortiedr.exe": "FortiEDR",
    "coreServiceShell.exe": "Trend Micro Apex One",
    "PccNTMon.exe": "Trend Micro",
    "savservice.exe": "Sophos AV",
    "SophosFileScanner.exe": "Sophos",
    "bdagent.exe": "Bitdefender",
    "kavfswp.exe": "Kaspersky",
    "avp.exe": "Kaspersky",
    "WRSA.exe": "Webroot",
    "ossec-agent.exe": "OSSEC/Wazuh Agent",
    "winlogbeat.exe": "Elastic Winlogbeat",
    "splunkd.exe": "Splunk Forwarder",
    "nxlog.exe": "NXLog",
}

# Processes commonly abused by attackers (LOLBins etc.)
_SUSPICIOUS_PARENTS = {
    "mshta.exe": "HTML Application Host (T1218.005)",
    "regsvr32.exe": "Regsvr32 proxy execution (T1218.010)",
    "rundll32.exe": "Rundll32 proxy execution (T1218.011)",
    "certutil.exe": "Certutil download (T1105)",
    "bitsadmin.exe": "BITS download (T1197)",
    "wscript.exe": "Windows Script Host (T1059.005)",
    "cscript.exe": "Console Script Host (T1059.005)",
}


class ProcessDiscovery(BaseModule):
    """T1057 — Process Discovery.

    Enumerates running processes, identifies security tools,
    and detects potentially suspicious process activity.
    """

    TECHNIQUE_ID = "T1057"
    TECHNIQUE_NAME = "Process Discovery"
    TACTIC = "Discovery"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Identify running security tools ──────────────────────
        self._check_security_tools(session, result)

        # ── Check for suspicious LOLBin processes ────────────────
        self._check_suspicious_processes(session, result)

        # ── Check process creation audit policy ──────────────────
        self._check_process_audit(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_security_tools(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Identify which security tools are running."""
        procs = session.run_powershell(
            "Get-Process | Select-Object -ExpandProperty Name -Unique"
        )
        if not procs or not procs.stdout.strip():
            return

        running = {p.strip().lower() for p in procs.stdout.splitlines() if p.strip()}
        found_tools: list[str] = []
        missing_tools: list[str] = []

        for proc_name, tool_name in _SECURITY_PROCESSES.items():
            base = proc_name.lower().replace(".exe", "")
            if base in running:
                found_tools.append(f"{tool_name} ({proc_name})")
            # Track key defenders
            elif proc_name in ("MsMpEng.exe", "MsSense.exe"):
                missing_tools.append(f"{tool_name} ({proc_name})")

        if found_tools:
            self.add_finding(
                result,
                description=f"Security tools detected: {len(found_tools)} running",
                severity=Severity.INFO,
                evidence="\n".join(found_tools),
                recommendation="Ensure security tools are up-to-date and properly configured",
            )

        if missing_tools:
            self.add_finding(
                result,
                description="Key security tools are not running",
                severity=Severity.HIGH,
                evidence=f"Not detected: {', '.join(missing_tools)}",
                recommendation=(
                    "Ensure Windows Defender Antimalware (MsMpEng.exe) and "
                    "Defender for Endpoint (MsSense.exe) are running. "
                    "Investigate if they were disabled or tampered with."
                ),
                cwe="CWE-693",
            )

    def _check_suspicious_processes(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for commonly abused LOLBin processes running."""
        procs = session.run_powershell(
            "Get-Process | Select-Object Name, Id, Path | "
            "ConvertTo-Json -Compress"
        )
        if not procs or not procs.stdout.strip():
            return

        try:
            proc_list = json.loads(procs.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(proc_list, list):
            proc_list = [proc_list]

        for proc in proc_list:
            name = proc.get("Name", "")
            exe = f"{name}.exe".lower()
            if exe in _SUSPICIOUS_PARENTS:
                desc = _SUSPICIOUS_PARENTS[exe]
                self.add_finding(
                    result,
                    description=f"Potentially suspicious process running: {name} — {desc}",
                    severity=Severity.LOW,
                    evidence=f"PID={proc.get('Id', '?')}, Path={proc.get('Path', 'N/A')}",
                    recommendation=(
                        f"Investigate {name}.exe execution context. "
                        f"This is a known LOLBin used for proxy execution."
                    ),
                )

    def _check_process_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if process creation auditing is enabled."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Process Creation' 2>$null"
        )
        if audit and audit.stdout:
            if "No Auditing" in audit.stdout:
                self.add_finding(
                    result,
                    description="Process creation auditing is not enabled",
                    severity=Severity.HIGH,
                    evidence=audit.stdout.strip(),
                    recommendation=(
                        "Enable 'Audit Process Creation' (Success) via Group Policy. "
                        "Also enable 'Include command line in process creation events' "
                        "for full visibility. CIS Benchmark 17.9.1"
                    ),
                    cwe="CWE-778",
                )
            elif "Success" not in audit.stdout:
                self.add_finding(
                    result,
                    description="Process creation auditing may not include success events",
                    severity=Severity.MEDIUM,
                    evidence=audit.stdout.strip(),
                    recommendation=(
                        "Enable success auditing for process creation events"
                    ),
                )

        # Check if command-line logging is enabled
        cmd_line = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled",
        )
        if cmd_line is None or str(cmd_line) != "1":
            self.add_finding(
                result,
                description="Command-line logging for process creation is not enabled",
                severity=Severity.MEDIUM,
                evidence=f"ProcessCreationIncludeCmdLine_Enabled = {cmd_line}",
                recommendation=(
                    "Enable command-line process auditing via Group Policy: "
                    "Administrative Templates > System > Audit Process Creation > "
                    "Include command line in process creation events"
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary process enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("tasklist /svc", "Process and service enumeration"),
            ("wmic process get Name,ProcessId,CommandLine /format:list",
             "WMI process enumeration with command lines"),
        ]

        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Enable process creation auditing and command-line logging",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1047 — Audit: Enable process creation auditing with command-line logging",
            "M1040 — Behavior Prevention on Endpoint: Deploy EDR with process telemetry",
            "M1026 — Privileged Account Management: Restrict access to process information",
            "M1038 — Execution Prevention: Block or monitor known LOLBin abuse patterns",
        ]
