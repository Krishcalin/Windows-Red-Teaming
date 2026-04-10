"""CVE-2026-21513 — MSHTML Security Feature Bypass.

Checks for the MSHTML platform vulnerability (CVE-2026-21513, CVSS 8.8)
that bypasses security warnings and allows remote code execution. Actively
exploited in the wild across Windows 10, 11, and Server.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class MshtmlBypassCheck(BaseModule):
    """CVE-2026-21513 — MSHTML security feature bypass audit.

    Checks whether the system is patched against the MSHTML flaw
    that allows attackers to execute code without security warnings,
    and evaluates mitigating controls.
    """

    TECHNIQUE_ID = "T1218"
    TECHNIQUE_NAME = "System Binary Proxy Execution — MSHTML Bypass (CVE-2026-21513)"
    TACTIC = "Defense Evasion"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_patch_installed(session, result)
        self._check_mshtml_dll_version(session, result)
        self._check_ie_security_zones(session, result)
        self._check_mark_of_web(session, result)
        self._check_office_ole_config(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_patch_installed(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if the February 2026 security update is installed."""
        patches = session.run_powershell(
            "Get-HotFix -ErrorAction SilentlyContinue | "
            "Where-Object { $_.InstalledOn -ge '2026-02-01' } | "
            "Select-Object HotFixID, InstalledOn | "
            "ConvertTo-Json -Compress"
        )
        if not patches or not patches.stdout.strip() or patches.stdout.strip() in ("", "null"):
            self.add_finding(
                result,
                description="No February 2026+ patches found — likely vulnerable to CVE-2026-21513 (MSHTML bypass)",
                severity=Severity.CRITICAL,
                evidence="No hotfixes installed after 2026-02-01",
                recommendation=(
                    "Apply the February 2026 Patch Tuesday update immediately. "
                    "CVE-2026-21513 allows remote code execution without security "
                    "warnings via the MSHTML platform."
                ),
                cwe="CWE-863",
            )
        else:
            self.add_finding(
                result,
                description="February 2026+ security updates detected",
                severity=Severity.INFO,
                evidence=patches.stdout[:500],
                recommendation="Verify the installed update covers CVE-2026-21513.",
            )

    def _check_mshtml_dll_version(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check mshtml.dll version to detect unpatched builds."""
        ver = session.run_powershell(
            "$dll = \"$env:SystemRoot\\System32\\mshtml.dll\"; "
            "if (Test-Path $dll) { "
            "  (Get-Item $dll).VersionInfo | "
            "  Select-Object FileVersion, ProductVersion | "
            "  ConvertTo-Json -Compress "
            "}"
        )
        if ver and ver.stdout.strip():
            self.add_finding(
                result,
                description="MSHTML DLL version information",
                severity=Severity.INFO,
                evidence=ver.stdout[:500],
                recommendation=(
                    "Compare mshtml.dll version against the patched version "
                    "from the February 2026 update."
                ),
            )

    def _check_ie_security_zones(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Internet Explorer / MSHTML security zone settings."""
        # Zone 3 = Internet zone; setting 1201 = ActiveX controls
        activex = session.read_registry(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3",
            "1201",
        )
        if activex is not None and str(activex) == "0":
            self.add_finding(
                result,
                description="ActiveX controls are enabled in the Internet zone (MSHTML attack surface)",
                severity=Severity.HIGH,
                evidence=f"Zone 3, setting 1201 (ActiveX) = {activex} (enabled)",
                recommendation=(
                    "Disable ActiveX controls in the Internet zone via GPO. "
                    "This reduces the MSHTML attack surface for CVE-2026-21513."
                ),
                cwe="CWE-863",
            )

        # Check if MSHTML scripting is disabled
        scripting = session.read_registry(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3",
            "1400",
        )
        if scripting is not None and str(scripting) == "0":
            self.add_finding(
                result,
                description="Active scripting is enabled in the Internet zone",
                severity=Severity.MEDIUM,
                evidence=f"Zone 3, setting 1400 (scripting) = {scripting}",
                recommendation="Restrict active scripting in the Internet zone via GPO.",
            )

    def _check_mark_of_web(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Mark of the Web (MOTW) processing is configured."""
        # SaveZoneInformation: 1 = MOTW disabled, 2 = enabled
        motw = session.read_registry(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments",
            "SaveZoneInformation",
        )
        if motw is not None and str(motw) == "1":
            self.add_finding(
                result,
                description="Mark of the Web (MOTW) zone information is disabled — "
                            "security bypass enabler for CVE-2026-21513",
                severity=Severity.HIGH,
                evidence=f"SaveZoneInformation = {motw}",
                recommendation=(
                    "Enable MOTW: Set SaveZoneInformation to 2. "
                    "MOTW provides a defense layer against downloaded content "
                    "exploiting MSHTML vulnerabilities."
                ),
                cwe="CWE-863",
            )

    def _check_office_ole_config(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Office OLE embedding controls (related to CVE-2026-21514 vector)."""
        # PackagerPrompt: 0=no prompt, 1=prompt on execution, 2=no prompt, no execution
        ole = session.read_registry(
            "HKCU",
            r"Software\Microsoft\Office\16.0\Common\Security",
            "PackagerPrompt",
        )
        if ole is not None and str(ole) == "0":
            self.add_finding(
                result,
                description="Office OLE packager prompt is disabled — enables silent execution of embedded objects",
                severity=Severity.HIGH,
                evidence=f"PackagerPrompt = {ole}",
                recommendation=(
                    "Set PackagerPrompt to 2 (block) or 1 (prompt) to prevent "
                    "silent OLE object execution in Office documents."
                ),
                cwe="CWE-863",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_powershell(
            "$dll = \"$env:SystemRoot\\System32\\mshtml.dll\"; "
            "if (Test-Path $dll) { "
            "  $sig = Get-AuthenticodeSignature $dll; "
            "  [PSCustomObject]@{ "
            "    Version = (Get-Item $dll).VersionInfo.FileVersion; "
            "    Signed = $sig.Status.ToString(); "
            "    Signer = $sig.SignerCertificate.Subject "
            "  } | ConvertTo-Json -Compress "
            "}"
        )
        if out:
            self.add_finding(
                result,
                description="Simulated: MSHTML component enumeration",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Monitor for MSHTML/mshta.exe usage in unusual contexts",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1051 — Update Software: Apply February 2026 Patch Tuesday update (CVE-2026-21513)",
            "M1021 — Restrict Web-Based Content: Block MSHTML/ActiveX via GPO security zones",
            "M1038 — Execution Prevention: Block mshta.exe execution via WDAC/AppLocker",
            "M1040 — Behavior Prevention on Endpoint: EDR detection of MSHTML-based execution",
            "M1054 — Software Configuration: Enable Mark of the Web and macro security policies",
        ]
