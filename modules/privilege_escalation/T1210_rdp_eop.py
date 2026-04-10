"""CVE-2026-21533 — Remote Desktop Services Elevation of Privilege.

Checks for the RDP EoP vulnerability (CVE-2026-21533, CVSS 7.8) that
allows attackers to add users to the Administrators group via
Remote Desktop Services. Actively exploited since December 2025
targeting US and Canadian entities.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class RdpEopCheck(BaseModule):
    """CVE-2026-21533 — RDP Elevation of Privilege audit.

    Evaluates Remote Desktop Services configuration for the actively
    exploited vulnerability allowing local privilege escalation to
    the Administrators group.
    """

    TECHNIQUE_ID = "T1210"
    TECHNIQUE_NAME = "Exploitation of Remote Services (CVE-2026-21533)"
    TACTIC = "Privilege Escalation"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_rdp_enabled(session, result)
        self._check_patch_installed(session, result)
        self._check_nla_enforced(session, result)
        self._check_rdp_restricted_admin(session, result)
        self._check_recent_admin_additions(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_rdp_enabled(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Remote Desktop is enabled."""
        deny = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
        if deny is not None and str(deny) == "0":
            self.add_finding(
                result,
                description="Remote Desktop is enabled — attack surface for CVE-2026-21533",
                severity=Severity.MEDIUM,
                evidence=f"fDenyTSConnections = {deny}",
                recommendation=(
                    "If RDP is not required, disable it. If required, ensure "
                    "the February 2026 patch (KB5034763) is installed and NLA is enforced."
                ),
            )

    def _check_patch_installed(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if the February 2026 security update is installed."""
        # Check for the specific KB that patches CVE-2026-21533
        patches = session.run_powershell(
            "Get-HotFix -ErrorAction SilentlyContinue | "
            "Where-Object { $_.InstalledOn -ge '2026-02-01' } | "
            "Select-Object HotFixID, InstalledOn, Description | "
            "ConvertTo-Json -Compress"
        )
        if not patches or not patches.stdout.strip() or patches.stdout.strip() in ("", "null"):
            self.add_finding(
                result,
                description="No security updates from February 2026 or later found — likely vulnerable to CVE-2026-21533",
                severity=Severity.CRITICAL,
                evidence="No hotfixes installed after 2026-02-01",
                recommendation=(
                    "Apply the February 2026 Patch Tuesday update immediately. "
                    "CVE-2026-21533 is actively exploited in the wild since December 2025."
                ),
                cwe="CWE-269",
            )
        else:
            self.add_finding(
                result,
                description="February 2026+ security updates detected",
                severity=Severity.INFO,
                evidence=patches.stdout[:500],
                recommendation="Verify the installed patch covers CVE-2026-21533.",
            )

    def _check_nla_enforced(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Network Level Authentication is enforced for RDP."""
        nla = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication",
        )
        if nla is None or str(nla) != "1":
            self.add_finding(
                result,
                description="Network Level Authentication (NLA) is not enforced for RDP",
                severity=Severity.HIGH,
                evidence=f"UserAuthentication = {nla}",
                recommendation=(
                    "Enable NLA: Set UserAuthentication to 1 under "
                    "RDP-Tcp WinStation config. NLA limits pre-auth attack surface "
                    "and partially mitigates CVE-2026-21533."
                ),
                cwe="CWE-287",
            )

    def _check_rdp_restricted_admin(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check Restricted Admin mode for RDP."""
        restricted = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "DisableRestrictedAdmin",
        )
        if restricted is not None and str(restricted) == "0":
            self.add_finding(
                result,
                description="RDP Restricted Admin mode is enabled (pass-the-hash vector but limits credential exposure)",
                severity=Severity.INFO,
                evidence=f"DisableRestrictedAdmin = {restricted}",
                recommendation=(
                    "Restricted Admin mode reduces credential theft risk on the "
                    "remote host but enables pass-the-hash. Evaluate tradeoff."
                ),
            )

    def _check_recent_admin_additions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check for recent additions to the Administrators group (IoC for CVE-2026-21533)."""
        events = session.run_powershell(
            "try { "
            "  Get-WinEvent -FilterHashtable @{ "
            "    LogName='Security'; Id=4732; "
            "    StartTime=(Get-Date).AddDays(-30) "
            "  } -MaxEvents 20 -ErrorAction SilentlyContinue | "
            "  Where-Object { $_.Message -match 'Administrators' } | "
            "  Select-Object TimeCreated, Message | "
            "  ConvertTo-Json -Compress "
            "} catch { }"
        )
        if events and events.stdout.strip() and events.stdout.strip() not in ("", "null"):
            try:
                data = json.loads(events.stdout)
                if not isinstance(data, list):
                    data = [data]
                count = len(data)
            except json.JSONDecodeError:
                count = 0

            if count > 0:
                self.add_finding(
                    result,
                    description=f"Detected {count} recent addition(s) to the Administrators group (past 30 days)",
                    severity=Severity.HIGH,
                    evidence=events.stdout[:1000],
                    recommendation=(
                        "Investigate all recent Administrators group changes — "
                        "CVE-2026-21533 exploitation adds rogue accounts to this group. "
                        "Check Event ID 4732 entries for unauthorized additions."
                    ),
                    cwe="CWE-269",
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        out = session.run_powershell(
            "net localgroup Administrators | Select-String -Pattern '\\\\'"
        )
        if out:
            self.add_finding(
                result,
                description="Simulated: Enumerated Administrators group membership",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Monitor Event ID 4732 for unauthorized group modifications",
            )

        rdp_users = session.run_powershell(
            "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections -ErrorAction SilentlyContinue"
        )
        if rdp_users:
            self.add_finding(
                result,
                description="Simulated: RDP configuration enumeration",
                severity=Severity.INFO,
                evidence=rdp_users.stdout[:500],
                recommendation="Restrict RDP access via GPO and firewall rules",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1051 — Update Software: Apply February 2026 Patch Tuesday update (CVE-2026-21533)",
            "M1042 — Disable or Remove Feature: Disable RDP if not required",
            "M1035 — Limit Access to Resource Over Network: Restrict RDP via firewall to trusted IPs",
            "M1032 — Multi-factor Authentication: Enforce MFA for all RDP sessions",
            "M1026 — Privileged Account Management: Monitor Administrators group for unauthorized additions",
        ]
