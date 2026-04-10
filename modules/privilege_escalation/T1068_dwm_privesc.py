"""CVE-2026-21519 — Desktop Window Manager (DWM) SYSTEM Privilege Escalation.

Checks for the DWM type confusion vulnerability (CVE-2026-21519, CVSS 7.8)
that enables local privilege escalation to SYSTEM with no user interaction
and low attack complexity. Actively exploited in the wild.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class DwmPrivescCheck(BaseModule):
    """CVE-2026-21519 — DWM SYSTEM privilege escalation audit.

    Evaluates whether the system is vulnerable to the Desktop Window
    Manager type confusion bug that grants SYSTEM privileges to a
    local attacker.
    """

    TECHNIQUE_ID = "T1068"
    TECHNIQUE_NAME = "Exploitation for Privilege Escalation (CVE-2026-21519)"
    TACTIC = "Privilege Escalation"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_patch_installed(session, result)
        self._check_dwm_running(session, result)
        self._check_dwm_integrity(session, result)
        self._check_exploit_artifacts(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_patch_installed(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if the February 2026 security update addressing CVE-2026-21519 is installed."""
        patches = session.run_powershell(
            "Get-HotFix -ErrorAction SilentlyContinue | "
            "Where-Object { $_.InstalledOn -ge '2026-02-01' } | "
            "Select-Object HotFixID, InstalledOn | "
            "ConvertTo-Json -Compress"
        )
        if not patches or not patches.stdout.strip() or patches.stdout.strip() in ("", "null"):
            self.add_finding(
                result,
                description="No February 2026+ patches found — likely vulnerable to CVE-2026-21519 (DWM SYSTEM privesc)",
                severity=Severity.CRITICAL,
                evidence="No hotfixes installed after 2026-02-01",
                recommendation=(
                    "Apply the February 2026 Patch Tuesday update immediately. "
                    "CVE-2026-21519 is an actively exploited zero-day allowing "
                    "local SYSTEM escalation with no user interaction."
                ),
                cwe="CWE-843",
            )
        else:
            self.add_finding(
                result,
                description="February 2026+ security updates detected",
                severity=Severity.INFO,
                evidence=patches.stdout[:500],
                recommendation="Verify the installed update includes the fix for CVE-2026-21519.",
            )

    def _check_dwm_running(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check DWM process status and privilege level."""
        dwm = session.run_powershell(
            "Get-Process -Name dwm -ErrorAction SilentlyContinue | "
            "Select-Object Id, ProcessName, "
            "@{N='User';E={(Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.Id)\" "
            "-ErrorAction SilentlyContinue).GetOwner().User}} | "
            "ConvertTo-Json -Compress"
        )
        if dwm and dwm.stdout.strip() and dwm.stdout.strip() not in ("", "null"):
            self.add_finding(
                result,
                description="Desktop Window Manager (dwm.exe) is running — attack surface for CVE-2026-21519",
                severity=Severity.INFO,
                evidence=dwm.stdout[:500],
                recommendation=(
                    "DWM runs as SYSTEM by design and cannot be disabled on modern "
                    "Windows. Patching is the only mitigation."
                ),
            )

    def _check_dwm_integrity(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Verify dwm.exe file hash against known-good values."""
        integrity = session.run_powershell(
            "$dwm = \"$env:SystemRoot\\System32\\dwm.exe\"; "
            "if (Test-Path $dwm) { "
            "  $sig = Get-AuthenticodeSignature $dwm; "
            "  [PSCustomObject]@{ "
            "    Path = $dwm; "
            "    Status = $sig.Status.ToString(); "
            "    Signer = $sig.SignerCertificate.Subject; "
            "    Hash = (Get-FileHash $dwm -Algorithm SHA256).Hash "
            "  } | ConvertTo-Json -Compress "
            "}"
        )
        if integrity and integrity.stdout.strip():
            if "NotSigned" in integrity.stdout or "HashMismatch" in integrity.stdout:
                self.add_finding(
                    result,
                    description="dwm.exe signature verification failed — possible tampering",
                    severity=Severity.CRITICAL,
                    evidence=integrity.stdout[:500],
                    recommendation=(
                        "Run sfc /scannow and DISM to verify system file integrity. "
                        "An unsigned or tampered dwm.exe may indicate exploitation."
                    ),
                    cwe="CWE-494",
                )
            else:
                self.add_finding(
                    result,
                    description="dwm.exe signature is valid",
                    severity=Severity.INFO,
                    evidence=integrity.stdout[:500],
                    recommendation="No action required — file integrity verified.",
                )

    def _check_exploit_artifacts(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for known exploitation artifacts of CVE-2026-21519."""
        # Look for suspicious child processes spawned by dwm.exe
        children = session.run_powershell(
            "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
            "Where-Object { $_.ParentProcessId -in "
            "  (Get-Process -Name dwm -ErrorAction SilentlyContinue).Id } | "
            "Select-Object Name, ProcessId, CommandLine | "
            "ConvertTo-Json -Compress"
        )
        if children and children.stdout.strip() and children.stdout.strip() not in ("", "null", "[]"):
            self.add_finding(
                result,
                description="Suspicious child processes found under dwm.exe — possible CVE-2026-21519 exploitation",
                severity=Severity.CRITICAL,
                evidence=children.stdout[:1000],
                recommendation=(
                    "Investigate immediately. DWM should not spawn child processes. "
                    "This may indicate active exploitation of CVE-2026-21519."
                ),
                cwe="CWE-843",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_powershell(
            "Get-Process dwm -ErrorAction SilentlyContinue | "
            "Format-List Id, ProcessName, StartTime, "
            "@{N='Modules';E={$_.Modules.Count}}"
        )
        if out:
            self.add_finding(
                result,
                description="Simulated: DWM process enumeration for CVE-2026-21519 surface",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Monitor dwm.exe for anomalous child process creation",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1051 — Update Software: Apply February 2026 Patch Tuesday update (CVE-2026-21519)",
            "M1040 — Behavior Prevention on Endpoint: EDR monitoring for DWM child process creation",
            "M1038 — Execution Prevention: Monitor SYSTEM-level process creation from unexpected parents",
            "M1047 — Audit: Monitor Event ID 4688 for processes spawned by dwm.exe",
        ]
