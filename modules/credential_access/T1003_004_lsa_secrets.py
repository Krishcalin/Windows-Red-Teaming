"""T1003.004 — OS Credential Dumping: LSA Secrets.

LSA Secrets are stored encrypted under HKLM\\SECURITY\\Policy\\Secrets and can
be decrypted by an attacker with SYSTEM/administrator access (e.g. Mimikatz
`lsadump::secrets`, Impacket `secretsdump.py`). They commonly contain service
account passwords, auto-logon credentials, and cached domain secrets.

This module passively audits the protections that make LSA Secrets harder to
extract and looks for cleartext-credential exposure that ends up stored as an
LSA secret.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class LsaSecretsCheck(BaseModule):
    """Audit defenses against LSA Secrets dumping (T1003.004)."""

    TECHNIQUE_ID = "T1003.004"
    TECHNIQUE_NAME = "OS Credential Dumping: LSA Secrets"
    TACTIC = "Credential Access"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [
        OSType.WIN10, OSType.WIN11,
        OSType.SERVER_2019, OSType.SERVER_2022,
    ]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_lsa_protection(session, result)
        self._check_wdigest(session, result)
        self._check_autologon_secret(session, result)
        self._check_secret_auditing(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_lsa_protection(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """RunAsPPL hardens LSASS, the gateway to dumping LSA secrets."""
        ppl = session.run_powershell(
            "(Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "-Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL"
        )
        value = ppl.stdout.strip() if ppl and ppl.stdout else ""
        if value in ("1", "2"):
            self.add_finding(
                result,
                description="LSASS runs as a Protected Process Light (RunAsPPL enabled)",
                severity=Severity.INFO,
                evidence=f"RunAsPPL = {value}",
                recommendation="No action — LSA protection raises the bar for secret extraction.",
            )
        else:
            self.add_finding(
                result,
                description="LSA Protection (RunAsPPL) is not enabled — LSA secrets are easier to extract",
                severity=Severity.HIGH,
                evidence="RunAsPPL not set or = 0",
                recommendation=(
                    "Enable LSA protection: set RunAsPPL=1 under "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa."
                ),
                cwe="CWE-522",
            )

    def _check_wdigest(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """WDigest UseLogonCredential=1 caches cleartext creds reachable via LSA."""
        wdigest = session.run_powershell(
            "(Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
            "-Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential"
        )
        value = wdigest.stdout.strip() if wdigest and wdigest.stdout else ""
        if value == "1":
            self.add_finding(
                result,
                description="WDigest cleartext credential caching is enabled (UseLogonCredential=1)",
                severity=Severity.CRITICAL,
                evidence="UseLogonCredential = 1",
                recommendation=(
                    "Set UseLogonCredential=0 (or remove it) so plaintext "
                    "credentials are not stored where they can be dumped."
                ),
                cwe="CWE-312",
            )
        else:
            self.add_finding(
                result,
                description="WDigest cleartext caching is disabled",
                severity=Severity.INFO,
                evidence=f"UseLogonCredential = {value or 'not set'}",
                recommendation="No action required.",
            )

    def _check_autologon_secret(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """An auto-logon DefaultPassword is stored as the LSA secret DefaultPassword."""
        autologon = session.run_powershell(
            "$w = Get-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
            "-ErrorAction SilentlyContinue; "
            "[PSCustomObject]@{ "
            "AutoAdminLogon = $w.AutoAdminLogon; "
            "HasDefaultPassword = [bool]$w.DefaultPassword "
            "} | ConvertTo-Json -Compress"
        )
        out = autologon.stdout if autologon and autologon.stdout else ""
        if '"HasDefaultPassword":true' in out.replace(" ", "").lower() or \
                '"hasdefaultpassword":true' in out.replace(" ", "").lower():
            self.add_finding(
                result,
                description="Auto-logon password stored in registry — exposed as LSA secret 'DefaultPassword'",
                severity=Severity.HIGH,
                evidence=out[:500],
                recommendation=(
                    "Remove DefaultPassword from the Winlogon key and disable "
                    "AutoAdminLogon; use a managed credential instead."
                ),
                cwe="CWE-256",
            )
        elif '"autoadminlogon":"1"' in out.replace(" ", "").lower():
            self.add_finding(
                result,
                description="AutoAdminLogon is enabled (no stored DefaultPassword detected)",
                severity=Severity.MEDIUM,
                evidence=out[:500],
                recommendation="Confirm no credential is cached for auto-logon; prefer disabling auto-logon.",
            )

    def _check_secret_auditing(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Object-access auditing helps detect SECURITY hive / secret access."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Other Object Access Events' 2>$null"
        )
        out = audit.stdout if audit and audit.stdout else ""
        if out and "No Auditing" in out:
            self.add_finding(
                result,
                description="Object access auditing is disabled — LSA secret access would go unlogged",
                severity=Severity.MEDIUM,
                evidence=out[:300],
                recommendation=(
                    "Enable Success/Failure auditing for object access so attempts "
                    "to read protected secrets are recorded."
                ),
                cwe="CWE-778",
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host, simulated=True)

        enum = session.run_powershell(
            "Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services' -ErrorAction SilentlyContinue "
            "| Out-Null; 'LSA secret surface enumerated (read-only)'"
        )
        self.add_finding(
            result,
            description="Simulated: enumerated LSA secret protection surface (no secrets read)",
            severity=Severity.INFO,
            evidence=(enum.stdout[:300] if enum and enum.stdout else "read-only enumeration"),
            recommendation="Monitor for lsadump/secretsdump behavior accessing the SECURITY hive.",
        )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1043 — Credential Access Protection: Enable LSA protection (RunAsPPL) and Credential Guard",
            "M1028 — Operating System Configuration: Disable WDigest cleartext caching (UseLogonCredential=0)",
            "M1027 — Password Policies: Remove auto-logon DefaultPassword and rotate service account secrets",
            "M1026 — Privileged Account Management: Restrict local administrator rights that allow SYSTEM access",
            "M1047 — Audit: Enable object access auditing to detect SECURITY hive access",
        ]
