"""T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting.

Checks for service accounts vulnerable to Kerberoasting by
identifying SPNs on user accounts, weak encryption types,
and Kerberos audit configuration.
"""

from __future__ import annotations

import json

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class KerberoastingCheck(BaseModule):
    """T1558.003 — Kerberoasting vulnerability audit.

    Identifies service accounts with SPNs that can be targeted
    for offline password cracking via Kerberos TGS requests.
    """

    TECHNIQUE_ID = "T1558.003"
    TECHNIQUE_NAME = "Steal or Forge Kerberos Tickets: Kerberoasting"
    TACTIC = "Credential Access"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # Check if domain-joined
        domain = session.run_powershell(
            "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"
        )
        if not domain or domain.stdout.strip().lower() != "true":
            return self.skip_result(
                "System is not domain-joined — Kerberoasting checks not applicable",
                target_host=session.target.host,
            )

        self._check_spn_accounts(session, result)
        self._check_weak_kerberos_encryption(session, result)
        self._check_kerberos_audit(session, result)
        self._check_managed_service_accounts(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_spn_accounts(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Find user accounts with SPNs (Kerberoastable accounts)."""
        spn_query = session.run_powershell(
            "try { "
            "  $searcher = [adsisearcher]'(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'; "
            "  $searcher.PropertiesToLoad.AddRange(@('samaccountname','serviceprincipalname','memberof','pwdlastset')); "
            "  $results = $searcher.FindAll(); "
            "  $results | ForEach-Object { "
            "    @{ "
            "      Name = [string]$_.Properties['samaccountname']; "
            "      SPN = [string]($_.Properties['serviceprincipalname'] -join ', '); "
            "      Groups = [string]($_.Properties['memberof'] -join ', '); "
            "      PwdLastSet = [string]$_.Properties['pwdlastset'] "
            "    } "
            "  } | ConvertTo-Json -Compress "
            "} catch { 'query_failed' }"
        )
        if not spn_query or "query_failed" in spn_query.stdout:
            return

        stdout = spn_query.stdout.strip()
        if not stdout or stdout in ("", "null"):
            return

        try:
            accounts = json.loads(stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(accounts, list):
            accounts = [accounts]

        for acct in accounts:
            name = acct.get("Name", "")
            spn = acct.get("SPN", "")
            groups = acct.get("Groups", "")

            # Higher severity if account is in privileged groups
            is_privileged = any(
                g in groups.lower()
                for g in ("domain admins", "enterprise admins", "administrators")
            )
            sev = Severity.CRITICAL if is_privileged else Severity.HIGH

            self.add_finding(
                result,
                description=f"Kerberoastable account: {name} (SPN: {spn[:80]})",
                severity=sev,
                evidence=f"Account: {name}\nSPN: {spn}\nGroups: {groups[:200]}",
                recommendation=(
                    f"Use a Group Managed Service Account (gMSA) instead of "
                    f"'{name}'. If a standard account is required, set a "
                    f"25+ character random password and rotate regularly."
                ),
                cwe="CWE-521",
            )

        if accounts:
            self.add_finding(
                result,
                description=f"Total Kerberoastable accounts found: {len(accounts)}",
                severity=Severity.MEDIUM,
                evidence=f"Accounts with SPNs: {', '.join(a.get('Name', '') for a in accounts)}",
                recommendation="Migrate service accounts to gMSAs or use AES-only Kerberos encryption",
            )

    def _check_weak_kerberos_encryption(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if weak Kerberos encryption types (RC4/DES) are allowed."""
        # Check supported encryption types policy
        enc = session.read_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
            "SupportedEncryptionTypes",
        )
        if enc is not None:
            val = int(enc) if str(enc).isdigit() else 0
            # Bit 4 = RC4_HMAC_MD5, Bits 0-1 = DES
            uses_rc4 = bool(val & 0x4)
            uses_des = bool(val & 0x3)
            if uses_des:
                self.add_finding(
                    result,
                    description="DES Kerberos encryption is enabled (extremely weak)",
                    severity=Severity.CRITICAL,
                    evidence=f"SupportedEncryptionTypes = {val} (DES bits set)",
                    recommendation="Disable DES encryption types for Kerberos immediately",
                    cwe="CWE-327",
                )
            if uses_rc4:
                self.add_finding(
                    result,
                    description="RC4 Kerberos encryption is enabled (vulnerable to offline cracking)",
                    severity=Severity.HIGH,
                    evidence=f"SupportedEncryptionTypes = {val} (RC4 bit set)",
                    recommendation=(
                        "Disable RC4_HMAC_MD5 and enforce AES256 for Kerberos. "
                        "RC4 tickets can be cracked much faster than AES."
                    ),
                    cwe="CWE-327",
                )

    def _check_kerberos_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if Kerberos authentication auditing is enabled."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Kerberos Service Ticket Operations' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="Kerberos Service Ticket Operations auditing is not enabled",
                severity=Severity.MEDIUM,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Kerberos Service Ticket Operations' "
                    "(Success, Failure) to detect Kerberoasting. "
                    "Event ID 4769 with RC4 encryption (0x17) indicates attack."
                ),
                cwe="CWE-778",
            )

    def _check_managed_service_accounts(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if gMSA is deployed for service accounts."""
        gmsa = session.run_powershell(
            "try { "
            "  $searcher = [adsisearcher]'(objectClass=msDS-GroupManagedServiceAccount)'; "
            "  $searcher.FindAll().Count "
            "} catch { '0' }"
        )
        if gmsa:
            count = gmsa.stdout.strip()
            if count == "0":
                self.add_finding(
                    result,
                    description="No Group Managed Service Accounts (gMSA) found in the domain",
                    severity=Severity.LOW,
                    evidence="gMSA count: 0",
                    recommendation=(
                        "Deploy gMSAs for service accounts. gMSAs provide "
                        "automatic password rotation with 120-character random "
                        "passwords, making Kerberoasting infeasible."
                    ),
                )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate Kerberoasting reconnaissance."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        out = session.run_powershell(
            "setspn -Q */* 2>$null | Select-Object -First 30"
        )
        if out and out.stdout.strip():
            self.add_finding(
                result,
                description="Simulated: SPN enumeration via setspn",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Monitor for mass SPN enumeration (setspn, LDAP queries)",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1027 — Password Policies: Use 25+ character passwords for service accounts with SPNs",
            "M1026 — Privileged Account Management: Migrate to Group Managed Service Accounts (gMSA)",
            "M1041 — Encrypt Sensitive Information: Enforce AES-only Kerberos encryption, disable RC4/DES",
            "M1047 — Audit: Enable Kerberos Service Ticket Operations auditing (Event ID 4769)",
        ]
