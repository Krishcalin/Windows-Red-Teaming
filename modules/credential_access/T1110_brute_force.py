"""T1110 — Brute Force.

Checks defenses against brute force attacks by evaluating
account lockout policy, password policy, and related
security controls.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class BruteForceCheck(BaseModule):
    """T1110 — Brute Force policy audit.

    Evaluates account lockout, password complexity, and
    authentication rate-limiting controls.
    """

    TECHNIQUE_ID = "T1110"
    TECHNIQUE_NAME = "Brute Force"
    TACTIC = "Credential Access"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        self._check_lockout_policy(session, result)
        self._check_password_complexity(session, result)
        self._check_logon_audit(session, result)
        self._check_ntlm_restrictions(session, result)
        self._check_smart_card_requirement(session, result)

        result.complete(ModuleStatus.SUCCESS)
        return result

    def _check_lockout_policy(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check account lockout policy parameters."""
        policy = session.run_cmd("net accounts")
        if not policy or not policy.stdout:
            return

        threshold = None
        duration = None
        window = None

        for line in policy.stdout.splitlines():
            low = line.lower()
            parts = line.split(":")
            if len(parts) < 2:
                continue
            val = parts[1].strip()

            if "lockout threshold" in low:
                threshold = val
            elif "lockout duration" in low:
                duration = val
            elif "lockout observation" in low or "lockout window" in low:
                window = val

        # Lockout threshold
        if threshold in (None, "Never", "0"):
            self.add_finding(
                result,
                description="Account lockout threshold is not configured (unlimited login attempts)",
                severity=Severity.CRITICAL,
                evidence=f"Lockout threshold: {threshold}",
                recommendation=(
                    "Set account lockout threshold to 5 or fewer invalid attempts. "
                    "CIS Benchmark 1.2.1"
                ),
                cwe="CWE-307",
            )
        elif threshold and threshold.isdigit() and int(threshold) > 10:
            self.add_finding(
                result,
                description=f"Account lockout threshold is too high ({threshold} attempts)",
                severity=Severity.MEDIUM,
                evidence=f"Lockout threshold: {threshold}",
                recommendation="Set lockout threshold to 5 or fewer attempts. CIS Benchmark 1.2.1",
                cwe="CWE-307",
            )

        # Lockout duration
        if duration and duration.isdigit() and int(duration) < 15 and int(duration) > 0:
            self.add_finding(
                result,
                description=f"Account lockout duration is too short ({duration} minutes)",
                severity=Severity.MEDIUM,
                evidence=f"Lockout duration: {duration} minutes",
                recommendation=(
                    "Set lockout duration to 15 minutes or more. CIS Benchmark 1.2.2"
                ),
                cwe="CWE-307",
            )

        # Lockout observation window
        if window and window.isdigit() and int(window) < 15 and int(window) > 0:
            self.add_finding(
                result,
                description=f"Lockout observation window is too short ({window} minutes)",
                severity=Severity.MEDIUM,
                evidence=f"Lockout observation window: {window} minutes",
                recommendation=(
                    "Set lockout observation window to 15 minutes or more. CIS Benchmark 1.2.3"
                ),
            )

    def _check_password_complexity(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check password policy strength."""
        policy = session.run_cmd("net accounts")
        if not policy or not policy.stdout:
            return

        for line in policy.stdout.splitlines():
            low = line.lower()
            parts = line.split(":")
            if len(parts) < 2:
                continue
            val = parts[1].strip()

            if "minimum password length" in low:
                if val.isdigit() and int(val) < 14:
                    self.add_finding(
                        result,
                        description=f"Minimum password length is {val} (should be 14+)",
                        severity=Severity.HIGH,
                        evidence=f"Minimum password length: {val}",
                        recommendation=(
                            "Set minimum password length to 14+ characters. "
                            "CIS Benchmark 1.1.4"
                        ),
                        cwe="CWE-521",
                    )

            if "minimum password age" in low:
                if val == "0":
                    self.add_finding(
                        result,
                        description="Minimum password age is 0 (passwords can be changed immediately)",
                        severity=Severity.MEDIUM,
                        evidence=f"Minimum password age: {val} days",
                        recommendation=(
                            "Set minimum password age to 1+ days to prevent "
                            "password history cycling. CIS Benchmark 1.1.3"
                        ),
                    )

            if "password history" in low:
                if val.lower() == "none" or (val.isdigit() and int(val) < 24):
                    self.add_finding(
                        result,
                        description=f"Password history length is insufficient ({val})",
                        severity=Severity.MEDIUM,
                        evidence=f"Password history: {val}",
                        recommendation=(
                            "Enforce 24 passwords remembered. CIS Benchmark 1.1.1"
                        ),
                    )

        # Check password complexity via secpol export
        complexity = session.run_powershell(
            "secedit /export /cfg $env:TEMP\\secpol.cfg /quiet 2>$null; "
            "(Select-String -Path $env:TEMP\\secpol.cfg -Pattern "
            "'PasswordComplexity' -ErrorAction SilentlyContinue).Line; "
            "Remove-Item $env:TEMP\\secpol.cfg -ErrorAction SilentlyContinue"
        )
        if complexity and complexity.stdout.strip():
            if "= 0" in complexity.stdout:
                self.add_finding(
                    result,
                    description="Password complexity requirements are disabled",
                    severity=Severity.HIGH,
                    evidence=complexity.stdout.strip(),
                    recommendation=(
                        "Enable password complexity requirements. CIS Benchmark 1.1.5"
                    ),
                    cwe="CWE-521",
                )

    def _check_logon_audit(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if logon failure auditing is enabled."""
        audit = session.run_powershell(
            "auditpol /get /subcategory:'Logon' 2>$null"
        )
        if audit and "No Auditing" in audit.stdout:
            self.add_finding(
                result,
                description="Logon auditing is not enabled — brute force attempts are not logged",
                severity=Severity.HIGH,
                evidence=audit.stdout.strip(),
                recommendation=(
                    "Enable 'Audit Logon Events' (Success, Failure). "
                    "Event ID 4625 tracks failed logon attempts. CIS Benchmark 17.5.1"
                ),
                cwe="CWE-778",
            )
        elif audit and "Failure" not in audit.stdout:
            self.add_finding(
                result,
                description="Logon failure auditing is not enabled",
                severity=Severity.MEDIUM,
                evidence=audit.stdout.strip(),
                recommendation="Enable failure auditing for logon events to detect brute force",
            )

    def _check_ntlm_restrictions(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check NTLM authentication restrictions."""
        # Check if NTLMv1 is blocked
        lm_level = session.read_registry(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LmCompatibilityLevel",
        )
        if lm_level is None or (str(lm_level).isdigit() and int(lm_level) < 3):
            self.add_finding(
                result,
                description=f"LAN Manager authentication level allows weak NTLMv1 (level={lm_level})",
                severity=Severity.HIGH,
                evidence=f"LmCompatibilityLevel = {lm_level} (should be 5)",
                recommendation=(
                    "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, "
                    "refuse LM & NTLM). CIS Benchmark 2.3.11.7"
                ),
                cwe="CWE-327",
            )

    def _check_smart_card_requirement(
        self, session: BaseSession, result: ModuleResult
    ) -> None:
        """Check if smart card logon is available for privileged accounts."""
        # Just check if the smart card service is running
        sc = session.run_powershell(
            "(Get-Service -Name SCardSvr -ErrorAction SilentlyContinue).Status"
        )
        if sc and sc.stdout.strip().lower() == "stopped":
            self.add_finding(
                result,
                description="Smart Card service (SCardSvr) is stopped",
                severity=Severity.INFO,
                evidence="SCardSvr service status: Stopped",
                recommendation=(
                    "Consider enabling smart card authentication for "
                    "privileged accounts to eliminate password brute force risk"
                ),
            )

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate brute force policy enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        out = session.run_cmd("net accounts")
        if out:
            self.add_finding(
                result,
                description="Simulated: Account policy enumeration via net accounts",
                severity=Severity.INFO,
                evidence=out.stdout[:500],
                recommendation="Restrict access to account policy information",
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass

    def get_mitigations(self) -> list[str]:
        return [
            "M1032 — Multi-factor Authentication: Deploy MFA to prevent credential-based attacks",
            "M1036 — Account Use Policies: Configure account lockout (threshold, duration, window)",
            "M1027 — Password Policies: Enforce 14+ character minimum, complexity, and history",
            "M1047 — Audit: Enable logon failure auditing (Event ID 4625)",
        ]
