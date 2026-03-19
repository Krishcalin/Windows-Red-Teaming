"""T1087 — Account Discovery (Local + Domain).

Checks local and domain account enumeration exposure, identifies
privileged accounts, stale accounts, and weak account policies.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class AccountDiscovery(BaseModule):
    """T1087 — Account Discovery.

    Enumerates local and domain accounts to identify security
    weaknesses in account management and access controls.
    """

    TECHNIQUE_ID = "T1087"
    TECHNIQUE_NAME = "Account Discovery"
    TACTIC = "Discovery"
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── T1087.001 Local Account Discovery ────────────────────
        self._check_local_accounts(session, result)

        # ── T1087.002 Domain Account Discovery ───────────────────
        self._check_domain_accounts(session, result)

        # ── Account lockout policy ───────────────────────────────
        self._check_lockout_policy(session, result)

        # ── Password policy ──────────────────────────────────────
        self._check_password_policy(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_local_accounts(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check local user accounts for security issues."""
        users = session.run_powershell(
            "Get-LocalUser | Select-Object Name, Enabled, "
            "PasswordRequired, PasswordLastSet, LastLogon | "
            "ConvertTo-Json -Compress"
        )
        if not users or not users.stdout.strip():
            return

        import json

        try:
            accounts = json.loads(users.stdout)
        except json.JSONDecodeError:
            return

        if not isinstance(accounts, list):
            accounts = [accounts]

        for acct in accounts:
            name = acct.get("Name", "")
            enabled = acct.get("Enabled", False)

            if not enabled:
                continue

            # Built-in Administrator account enabled
            if name.lower() == "administrator":
                self.add_finding(
                    result,
                    description="Built-in Administrator account is enabled",
                    severity=Severity.HIGH,
                    evidence=f"Account: {name}, Enabled: {enabled}",
                    recommendation=(
                        "Disable the built-in Administrator account and use "
                        "named admin accounts with least privilege. "
                        "CIS Benchmark 2.3.1.1"
                    ),
                    cwe="CWE-250",
                )

            # Guest account enabled
            if name.lower() == "guest":
                self.add_finding(
                    result,
                    description="Guest account is enabled",
                    severity=Severity.HIGH,
                    evidence=f"Account: {name}, Enabled: {enabled}",
                    recommendation=(
                        "Disable the Guest account. CIS Benchmark 2.3.10.1"
                    ),
                    cwe="CWE-284",
                )

            # Password not required
            if not acct.get("PasswordRequired", True):
                self.add_finding(
                    result,
                    description=f"Account '{name}' does not require a password",
                    severity=Severity.CRITICAL,
                    evidence=f"Account: {name}, PasswordRequired: False",
                    recommendation="Enforce password requirement on all enabled accounts",
                    cwe="CWE-521",
                )

        # Check for accounts that have never logged in (possible orphaned)
        stale = session.run_powershell(
            "Get-LocalUser | Where-Object { $_.Enabled -and "
            "$_.LastLogon -eq $null -and $_.Name -ne 'DefaultAccount' "
            "-and $_.Name -ne 'WDAGUtilityAccount' } | "
            "Select-Object -ExpandProperty Name"
        )
        if stale and stale.stdout.strip():
            names = stale.stdout.strip()
            self.add_finding(
                result,
                description="Enabled local accounts that have never logged in detected",
                severity=Severity.LOW,
                evidence=f"Accounts: {names}",
                recommendation="Review and disable or remove unused local accounts",
            )

    def _check_domain_accounts(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check domain account enumeration exposure (if domain-joined)."""
        domain = session.run_powershell(
            "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"
        )
        if not domain or domain.stdout.strip().lower() != "true":
            return

        # Check if anonymous enumeration of SAM accounts is restricted
        restrict_anon = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RestrictAnonymousSAM",
        )
        if restrict_anon is None or str(restrict_anon) != "1":
            self.add_finding(
                result,
                description="Anonymous enumeration of SAM accounts is not restricted",
                severity=Severity.HIGH,
                evidence=f"RestrictAnonymousSAM = {restrict_anon}",
                recommendation=(
                    "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\"
                    "RestrictAnonymousSAM to 1. CIS Benchmark 2.3.10.2"
                ),
                cwe="CWE-284",
            )

        # Check if anonymous enumeration of shares is restricted
        restrict_anon_shares = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RestrictAnonymous",
        )
        if restrict_anon_shares is None or str(restrict_anon_shares) == "0":
            self.add_finding(
                result,
                description="Anonymous enumeration of shares and accounts is not restricted",
                severity=Severity.MEDIUM,
                evidence=f"RestrictAnonymous = {restrict_anon_shares}",
                recommendation=(
                    "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\"
                    "RestrictAnonymous to 1. CIS Benchmark 2.3.10.3"
                ),
                cwe="CWE-284",
            )

    def _check_lockout_policy(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check account lockout policy configuration."""
        lockout = session.run_cmd("net accounts")
        if not lockout or not lockout.stdout:
            return

        lines = lockout.stdout.lower()

        # Parse lockout threshold
        for line in lines.splitlines():
            if "lockout threshold" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    val = parts[1].strip()
                    if val == "never" or val == "0":
                        self.add_finding(
                            result,
                            description="Account lockout threshold is not configured (unlimited attempts)",
                            severity=Severity.HIGH,
                            evidence=f"Lockout threshold: {val}",
                            recommendation=(
                                "Set account lockout threshold to 5 or fewer "
                                "invalid logon attempts. CIS Benchmark 1.2.1"
                            ),
                            cwe="CWE-307",
                        )
                    elif val.isdigit() and int(val) > 10:
                        self.add_finding(
                            result,
                            description=f"Account lockout threshold is too high ({val} attempts)",
                            severity=Severity.MEDIUM,
                            evidence=f"Lockout threshold: {val}",
                            recommendation="Set lockout threshold to 5 or fewer attempts",
                            cwe="CWE-307",
                        )

    def _check_password_policy(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check local password policy."""
        policy = session.run_cmd("net accounts")
        if not policy or not policy.stdout:
            return

        for line in policy.stdout.splitlines():
            low = line.lower()
            if "minimum password length" in low:
                parts = line.split(":")
                if len(parts) > 1:
                    val = parts[1].strip()
                    if val.isdigit() and int(val) < 14:
                        self.add_finding(
                            result,
                            description=f"Minimum password length is too short ({val} characters)",
                            severity=Severity.HIGH,
                            evidence=f"Minimum password length: {val}",
                            recommendation=(
                                "Set minimum password length to 14 or more characters. "
                                "CIS Benchmark 1.1.4"
                            ),
                            cwe="CWE-521",
                        )

            if "maximum password age" in low:
                parts = line.split(":")
                if len(parts) > 1:
                    val = parts[1].strip()
                    if val.lower() == "unlimited":
                        self.add_finding(
                            result,
                            description="Maximum password age is set to unlimited (passwords never expire)",
                            severity=Severity.MEDIUM,
                            evidence=f"Maximum password age: {val}",
                            recommendation=(
                                "Set maximum password age to 365 days or less. "
                                "CIS Benchmark 1.1.2"
                            ),
                            cwe="CWE-262",
                        )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary account enumeration commands."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        enum_commands = [
            ("net user", "Local user enumeration"),
            ("net localgroup Administrators", "Local admin group enumeration"),
            ("wmic useraccount get Name,SID,Status /format:list",
             "WMI user account enumeration"),
        ]

        for cmd, desc in enum_commands:
            out = session.run_cmd(cmd)
            if out:
                self.add_finding(
                    result,
                    description=f"Simulated: {desc}",
                    severity=Severity.INFO,
                    evidence=out.stdout[:500],
                    recommendation="Restrict local user enumeration via Group Policy",
                )

        # Domain enumeration (if domain-joined)
        domain_check = session.run_powershell(
            "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"
        )
        if domain_check and domain_check.stdout.strip().lower() == "true":
            domain_cmds = [
                ("net user /domain", "Domain user enumeration"),
                ("net group \"Domain Admins\" /domain",
                 "Domain Admins group enumeration"),
            ]
            for cmd, desc in domain_cmds:
                out = session.run_cmd(cmd)
                if out:
                    self.add_finding(
                        result,
                        description=f"Simulated: {desc}",
                        severity=Severity.INFO,
                        evidence=out.stdout[:500],
                        recommendation="Restrict domain enumeration and monitor for anomalous queries",
                    )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass  # Read-only — nothing to revert

    def get_mitigations(self) -> list[str]:
        return [
            "M1028 — Operating System Configuration: Restrict anonymous enumeration of SAM accounts and shares",
            "M1026 — Privileged Account Management: Disable built-in Administrator, enforce least privilege",
            "M1018 — User Account Management: Enforce strong password policy and account lockout",
            "M1030 — Network Segmentation: Limit network-level access to enumeration endpoints",
        ]
