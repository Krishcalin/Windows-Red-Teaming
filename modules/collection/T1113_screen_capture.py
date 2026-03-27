"""T1113 — Screen Capture.

Checks whether screen capture tools are available and whether
any restrictions are in place to prevent unauthorized screenshots.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class ScreenCaptureCheck(BaseModule):
    """T1113 — Screen Capture.

    Evaluates the availability of screen capture utilities and
    whether policies exist to restrict screenshot capabilities
    that an adversary could abuse for data collection.
    """

    TECHNIQUE_ID = "T1113"
    TECHNIQUE_NAME = "Screen Capture"
    TACTIC = "Collection"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # -- Check if screenshot tools are available ----------------
        snip_tools = session.run_powershell(
            "Get-Command snippingtool,SnippingTool.exe "
            "-ErrorAction SilentlyContinue | Select Name | ConvertTo-Json"
        )
        if snip_tools and snip_tools.stdout.strip():
            self.add_finding(
                result,
                description="Built-in screen capture tools are available (Snipping Tool)",
                severity=Severity.MEDIUM,
                evidence=snip_tools.stdout.strip()[:500],
                recommendation=(
                    "Consider restricting access to Snipping Tool via "
                    "AppLocker or WDAC policies on sensitive systems"
                ),
            )

        # -- Check PrintScreen key policy ---------------------------
        prtscn = session.run_cmd(
            'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" '
            "/v ScreenShotIndex"
        )
        if prtscn and prtscn.return_code == 0:
            self.add_finding(
                result,
                description="PrintScreen key is enabled — screenshots can be taken via keyboard",
                severity=Severity.LOW,
                evidence=prtscn.stdout.strip()[:300],
                recommendation=(
                    "Disable the PrintScreen key via Group Policy or "
                    "registry on high-security workstations"
                ),
            )

        # -- Check if graphics APIs accessible (GDI+) ---------------
        gdi = session.run_powershell(
            "Add-Type -AssemblyName System.Drawing; "
            "[System.Drawing.Graphics] | Out-Null; 'accessible'"
        )
        if gdi and "accessible" in gdi.stdout:
            self.add_finding(
                result,
                description="GDI+ graphics API is accessible — programmatic screen capture is possible",
                severity=Severity.MEDIUM,
                evidence="System.Drawing.Graphics loaded successfully",
                recommendation=(
                    "Monitor for processes loading System.Drawing or "
                    "calling BitBlt/GDI+ screen capture APIs"
                ),
                cwe="CWE-200",
            )

        # -- Check third-party screen capture software ---------------
        third_party = session.run_powershell(
            "Get-Process | Where-Object {"
            "$_.ProcessName -match 'obs|sharex|greenshot|lightshot|gyazo'"
            "} | Select ProcessName | ConvertTo-Json"
        )
        if third_party and third_party.stdout.strip() and third_party.stdout.strip() != "":
            self.add_finding(
                result,
                description="Third-party screen capture software is running",
                severity=Severity.MEDIUM,
                evidence=third_party.stdout.strip()[:500],
                recommendation=(
                    "Audit third-party screen capture tools; remove or "
                    "restrict unauthorized software via application whitelisting"
                ),
            )

        if not result.findings:
            self.add_finding(
                result,
                description="Screen capture tools are available with no restrictions in place",
                severity=Severity.MEDIUM,
                evidence="No screenshot restrictions detected",
                recommendation=(
                    "Implement application control policies to restrict "
                    "screen capture utilities on sensitive systems"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary screen capture reconnaissance."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        # -- Enumerate display adapters -----------------------------
        displays = session.run_powershell(
            "Get-CimInstance Win32_VideoController | "
            "Select Name,CurrentHorizontalResolution,"
            "CurrentVerticalResolution | ConvertTo-Json"
        )
        if displays and displays.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Enumerated display adapters and screen resolutions",
                severity=Severity.INFO,
                evidence=displays.stdout.strip()[:500],
                recommendation="Monitor WMI queries to Win32_VideoController",
            )

        # -- List windows that could be captured --------------------
        windows = session.run_powershell(
            "Get-Process | Where-Object {$_.MainWindowTitle} | "
            "Select ProcessName,MainWindowTitle | ConvertTo-Json"
        )
        if windows and windows.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: Listed visible windows that could be captured",
                severity=Severity.INFO,
                evidence=windows.stdout.strip()[:500],
                recommendation=(
                    "Restrict process enumeration and monitor for "
                    "suspicious window enumeration activity"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass  # Read-only checks — nothing to revert

    def get_mitigations(self) -> list[str]:
        return [
            "M1042 — Disable or Remove Feature or Program: Remove unnecessary screen capture tools",
            "M1038 — Execution Prevention: Use AppLocker/WDAC to block unauthorized capture utilities",
            "M1057 — Data Loss Prevention: Monitor for screen capture API calls and clipboard exfiltration",
            "M1018 — User Account Management: Restrict user ability to install third-party capture software",
        ]
