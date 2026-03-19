"""T1003.001 — OS Credential Dumping: LSASS Memory.

Checks protections around LSASS (Local Security Authority Subsystem
Service) memory, including Credential Guard, RunAsPPL, and attack
surface reduction rules.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class LsassMemoryCheck(BaseModule):
    """T1003.001 — LSASS Memory protection audit.

    Evaluates defenses against LSASS memory dumping techniques
    such as Mimikatz, procdump, comsvcs.dll MiniDump, etc.
    """

    TECHNIQUE_ID = "T1003.001"
    TECHNIQUE_NAME = "OS Credential Dumping: LSASS Memory"
    TACTIC = "Credential Access"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_lsass_ppl(session, result)
        self._check_credential_guard(session, result)
        self._check_wdigest(session, result)
        self._check_asr_lsass(session, result)
        self._check_lsass_audit_mode(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_lsass_ppl(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if LSASS runs as Protected Process Light (PPL)."""
        ppl = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
        )
        if ppl is None or str(ppl) != "1":
            self.add_finding(
                result,
                description="LSASS is not configured to run as Protected Process Light (RunAsPPL)",
                severity=Severity.CRITICAL,
                evidence=f"RunAsPPL = {ppl}",
                recommendation=(
                    "Enable LSASS PPL protection: Set HKLM\\SYSTEM\\CurrentControlSet\\"
                    "Control\\Lsa\\RunAsPPL to 1 (DWORD). This prevents usermode "
                    "processes from reading LSASS memory. CIS Benchmark 18.4.7"
                ),
                cwe="CWE-522",
            )

    def _check_credential_guard(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Credential Guard is protecting LSASS secrets."""
        cg = session.run_powershell(
            "(Get-CimInstance -ClassName Win32_DeviceGuard "
            "-Namespace root/Microsoft/Windows/DeviceGuard "
            "-ErrorAction SilentlyContinue).SecurityServicesRunning"
        )
        if not cg or not cg.stdout.strip():
            self.add_finding(
                result,
                description="Credential Guard status could not be determined",
                severity=Severity.HIGH,
                evidence=cg.stderr if cg else "DeviceGuard WMI class unavailable",
                recommendation="Enable Credential Guard to isolate LSASS secrets in a virtual container",
            )
            return

        services = cg.stdout.strip()
        # SecurityServicesRunning: 1 = Credential Guard
        if "1" not in services:
            self.add_finding(
                result,
                description="Credential Guard is not running — NTLM hashes and Kerberos TGTs are in LSASS memory",
                severity=Severity.HIGH,
                evidence=f"SecurityServicesRunning = {services}",
                recommendation=(
                    "Enable Credential Guard via Group Policy to isolate "
                    "credentials in a virtualization-based container"
                ),
                cwe="CWE-522",
            )

    def _check_wdigest(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if WDigest cleartext password caching is disabled."""
        wdigest = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential",
        )
        if wdigest is not None and str(wdigest) == "1":
            self.add_finding(
                result,
                description="WDigest authentication stores cleartext passwords in LSASS memory",
                severity=Severity.CRITICAL,
                evidence=f"UseLogonCredential = {wdigest}",
                recommendation=(
                    "Disable WDigest cleartext credential caching: Set "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\"
                    "WDigest\\UseLogonCredential to 0. KB2871997"
                ),
                cwe="CWE-256",
            )

    def _check_asr_lsass(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if ASR rule blocks credential stealing from LSASS."""
        # ASR GUID for "Block credential stealing from LSASS"
        asr_guid = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
        asr = session.run_powershell(
            f"(Get-MpPreference -ErrorAction SilentlyContinue)"
            f".AttackSurfaceReductionRules_Ids -contains '{asr_guid}'"
        )
        if not asr or asr.stdout.strip().lower() != "true":
            self.add_finding(
                result,
                description="ASR rule 'Block credential stealing from LSASS' is not enabled",
                severity=Severity.HIGH,
                evidence=f"ASR rule {asr_guid} not found in active rules",
                recommendation=(
                    "Enable the Defender ASR rule to block credential stealing from LSASS: "
                    "Add-MpPreference -AttackSurfaceReductionRules_Ids "
                    f"'{asr_guid}' -AttackSurfaceReductionRules_Actions Enabled"
                ),
            )

    def _check_lsass_audit_mode(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if LSASS audit mode is enabled for monitoring."""
        audit = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
            "AuditLevel",
        )
        if audit is None or str(audit) != "8":
            self.add_finding(
                result,
                description="LSASS audit mode is not enabled — LSASS access attempts are not logged",
                severity=Severity.MEDIUM,
                evidence=f"AuditLevel = {audit}",
                recommendation=(
                    "Enable LSASS audit mode: Set HKLM\\SOFTWARE\\Microsoft\\"
                    "Windows NT\\CurrentVersion\\Image File Execution Options\\"
                    "LSASS.exe\\AuditLevel to 8 (DWORD)"
                ),
                cwe="CWE-778",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate LSASS protection enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        commands = [
            ("tasklist /fi \"imagename eq lsass.exe\" /v",
             "LSASS process information"),
            ("wmic process where \"name='lsass.exe'\" get ProcessId,CommandLine /format:list",
             "LSASS WMI enumeration"),
        ]
        for cmd, desc in commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Monitor for LSASS enumeration and access attempts",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1043 — Credential Access Protection: Enable LSASS RunAsPPL and Credential Guard",
            "M1025 — Privileged Process Integrity: Configure LSASS as PPL to block usermode access",
            "M1040 — Behavior Prevention on Endpoint: Enable ASR rule for LSASS credential theft",
            "M1028 — Operating System Configuration: Disable WDigest cleartext credential caching",
        ]
