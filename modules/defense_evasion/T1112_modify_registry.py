"""T1112 — Modify Registry.

Adversaries modify the registry to hide configuration, disable defenses, or
establish stealthy footholds. This module passively audits whether registry
changes would be visible (auditing/logging) and looks for evasion-oriented
modifications that indicate tampering.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class ModifyRegistryCheck(BaseModule):
    """Audit registry-modification visibility and evasion artifacts (T1112)."""

    TECHNIQUE_ID = "T1112"
    TECHNIQUE_NAME = "Modify Registry"
    TACTIC = "Defense Evasion"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [
        OSType.WIN10, OSType.WIN11,
        OSType.SERVER_2019, OSType.SERVER_2022,
    ]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_registry_auditing(session, result)
        self._check_registry_tools_disabled(session, result)
        self._check_ifeo_debuggers(session, result)
        self._check_defender_tamper_keys(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_registry_auditing(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Registry subcategory auditing surfaces Event ID 4657 on changes."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Registry' 2>$null"
        )
        out = audit.stdout if audit and audit.stdout else ""
        if out and "No Auditing" in out:
            self.add_finding(
                result,
                description="Registry change auditing is disabled — modifications go unlogged (Event 4657)",
                severity=Severity.MEDIUM,
                evidence=out[:300],
                recommendation=(
                    "Enable Success/Failure auditing for the 'Registry' subcategory "
                    "and apply SACLs to sensitive keys."
                ),
                cwe="CWE-778",
            )
        elif out and ("Success" in out or "Failure" in out):
            self.add_finding(
                result,
                description="Registry change auditing is enabled",
                severity=Severity.INFO,
                evidence=out[:300],
                recommendation="No action required.",
            )

    def _check_registry_tools_disabled(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """DisableRegistryTools=1 blocks regedit — a common anti-analysis move."""
        for hive in ("HKCU", "HKLM"):
            reg = session.run_powershell(
                f"(Get-ItemProperty -Path "
                f"'{hive}:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                f"-Name 'DisableRegistryTools' -ErrorAction SilentlyContinue)"
                f".DisableRegistryTools"
            )
            value = reg.stdout.strip() if reg and reg.stdout else ""
            if value in ("1", "2"):
                self.add_finding(
                    result,
                    description=f"Registry editing tools are disabled via {hive} policy (DisableRegistryTools={value})",
                    severity=Severity.MEDIUM,
                    evidence=f"{hive} DisableRegistryTools = {value}",
                    recommendation=(
                        "Investigate why regedit is disabled; attackers set this to "
                        "hinder analysis. Remove the policy if unexpected."
                    ),
                    cwe="CWE-284",
                )

    def _check_ifeo_debuggers(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Image File Execution Options Debugger values hijack/disable binaries."""
        ifeo = session.run_powershell(
            "Get-ChildItem -Path "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' "
            "-ErrorAction SilentlyContinue | ForEach-Object { "
            "  $d = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger; "
            "  if ($d) { [PSCustomObject]@{ Image = $_.PSChildName; Debugger = $d } } "
            "} | ConvertTo-Json -Compress"
        )
        out = ifeo.stdout.strip() if ifeo and ifeo.stdout else ""
        if out and out not in ("", "null", "[]"):
            self.add_finding(
                result,
                description="Image File Execution Options 'Debugger' entries found — possible binary hijack/evasion",
                severity=Severity.HIGH,
                evidence=out[:1000],
                recommendation=(
                    "Review each IFEO Debugger value. Legitimate use is rare; "
                    "attackers use it to hijack or disable security tools."
                ),
                cwe="CWE-94",
            )

    def _check_defender_tamper_keys(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Policy keys that disable Microsoft Defender via the registry."""
        defender = session.run_powershell(
            "(Get-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' "
            "-Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue)"
            ".DisableAntiSpyware"
        )
        value = defender.stdout.strip() if defender and defender.stdout else ""
        if value == "1":
            self.add_finding(
                result,
                description="Microsoft Defender disabled via registry policy (DisableAntiSpyware=1)",
                severity=Severity.CRITICAL,
                evidence="DisableAntiSpyware = 1",
                recommendation=(
                    "Remove the DisableAntiSpyware policy value; this registry "
                    "modification is a hallmark of defense-evasion tampering."
                ),
                cwe="CWE-284",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        enum = session.run_powershell(
            "(Get-Item 'HKCU:\\Software' -ErrorAction SilentlyContinue) "
            "| Out-Null; 'Registry write surface enumerated (read-only)'"
        )
        self.add_finding(
            result,
            description="Simulated: enumerated registry write surface (no keys modified)",
            severity=Severity.INFO,
            evidence=(enum.stdout[:300] if enum and enum.stdout else "read-only enumeration"),
            recommendation="Monitor Event ID 4657 for unexpected registry value changes.",
        )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1047 — Audit: Enable registry-change auditing (Event 4657) and SACLs on sensitive keys",
            "M1024 — Restrict Registry Permissions: Limit write access to security-relevant keys",
            "M1038 — Execution Prevention: Block unauthorized tools from editing the registry",
            "M1018 — User Account Management: Restrict local admin rights that permit HKLM changes",
        ]
