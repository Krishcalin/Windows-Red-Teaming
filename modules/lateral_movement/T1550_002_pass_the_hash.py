"""T1550.002 — Pass the Hash.

Checks whether the system is vulnerable to Pass the Hash attacks
by auditing Credential Guard, restricted admin mode, WDigest
credential caching, LM hash storage, and NTLM settings.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class PassTheHashCheck(BaseModule):
    """T1550.002 — Pass the Hash.

    Evaluates protections against Pass the Hash attacks including
    Credential Guard, WDigest, LM hash storage, and NTLM configuration.
    """

    TECHNIQUE_ID = "T1550.002"
    TECHNIQUE_NAME = "Pass the Hash"
    TACTIC = "Lateral Movement"
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── Check Credential Guard ────────────────────────────────
        cg = session.run_powershell(
            "(Get-CimInstance Win32_DeviceGuard "
            "-Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ErrorAction SilentlyContinue).SecurityServicesRunning"
        )
        if cg and cg.stdout.strip():
            services = cg.stdout.strip()
            if "1" not in services:
                self.add_finding(
                    result,
                    description="Credential Guard is not running — NTLM hashes stored in memory are vulnerable",
                    severity=Severity.CRITICAL,
                    evidence=f"SecurityServicesRunning = {services}",
                    recommendation=(
                        "Enable Credential Guard via Group Policy: "
                        "Computer Configuration > Administrative Templates > "
                        "System > Device Guard > Turn On Virtualization Based Security"
                    ),
                    cwe="CWE-522",
                )
        else:
            self.add_finding(
                result,
                description="Credential Guard status could not be determined (DeviceGuard WMI unavailable)",
                severity=Severity.HIGH,
                evidence=cg.stderr if cg else "No output",
                recommendation="Verify Credential Guard support and enable if possible",
                cwe="CWE-522",
            )

        # ── Check restricted admin mode ───────────────────────────
        restricted = session.run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" '
            "/v DisableRestrictedAdmin"
        )
        if restricted and restricted.stdout:
            if "0x0" in restricted.stdout:
                self.add_finding(
                    result,
                    description=(
                        "Restricted Admin mode is enabled (DisableRestrictedAdmin=0) — "
                        "allows Pass the Hash via RDP"
                    ),
                    severity=Severity.HIGH,
                    evidence=restricted.stdout[:500],
                    recommendation=(
                        "Disable Restricted Admin mode unless specifically required: "
                        "Set DisableRestrictedAdmin to 1 in "
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
                    ),
                    cwe="CWE-287",
                )
        else:
            # Key not present means restricted admin is disabled (default)
            self._log.info("restricted_admin_not_configured", note="Default — disabled")

        # ── Check WDigest credential caching ──────────────────────
        wdigest = session.run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" '
            "/v UseLogonCredential"
        )
        if wdigest and wdigest.stdout:
            if "0x1" in wdigest.stdout:
                self.add_finding(
                    result,
                    description="WDigest credential caching is enabled — plaintext passwords stored in memory",
                    severity=Severity.CRITICAL,
                    evidence=wdigest.stdout[:500],
                    recommendation=(
                        "Disable WDigest: Set UseLogonCredential to 0 in "
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
                    ),
                    cwe="CWE-256",
                )
        else:
            # Key not present on modern Windows means WDigest is disabled (default on Win 8.1+)
            self._log.info("wdigest_not_configured", note="Default — disabled on modern Windows")

        # ── Check LM hash storage ─────────────────────────────────
        lm_hash = session.run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" '
            "/v NoLMHash"
        )
        if lm_hash and lm_hash.stdout:
            if "0x0" in lm_hash.stdout:
                self.add_finding(
                    result,
                    description="LM hash storage is enabled (NoLMHash=0) — weak hashes stored",
                    severity=Severity.HIGH,
                    evidence=lm_hash.stdout[:500],
                    recommendation=(
                        "Disable LM hash storage: Set NoLMHash to 1 in "
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
                    ),
                    cwe="CWE-328",
                )
        elif lm_hash and "not find" in (lm_hash.stderr or "").lower():
            self.add_finding(
                result,
                description="NoLMHash registry value not found — verify LM hash storage is disabled",
                severity=Severity.MEDIUM,
                evidence=lm_hash.stderr[:500] if lm_hash.stderr else "Key not found",
                recommendation=(
                    "Explicitly set NoLMHash to 1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
                ),
            )

        # ── Check NTLM settings (LmCompatibilityLevel) ───────────
        ntlm = session.run_cmd(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" '
            "/v LmCompatibilityLevel"
        )
        if ntlm and ntlm.stdout:
            for token in ntlm.stdout.split():
                if token.startswith("0x"):
                    try:
                        level = int(token, 16)
                        if level < 3:
                            self.add_finding(
                                result,
                                description=(
                                    f"NTLM LmCompatibilityLevel is {level} — "
                                    "allows weak LM/NTLM authentication"
                                ),
                                severity=Severity.HIGH,
                                evidence=f"LmCompatibilityLevel = {level}",
                                recommendation=(
                                    "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, "
                                    "refuse LM & NTLM) via Group Policy: "
                                    "Computer Configuration > Windows Settings > Security Settings > "
                                    "Local Policies > Security Options > "
                                    "'Network security: LAN Manager authentication level'"
                                ),
                                cwe="CWE-327",
                            )
                    except ValueError:
                        pass
        else:
            self.add_finding(
                result,
                description="LmCompatibilityLevel not configured — default NTLM settings in use",
                severity=Severity.MEDIUM,
                evidence=ntlm.stderr[:500] if ntlm and ntlm.stderr else "Key not found",
                recommendation=(
                    "Explicitly set LmCompatibilityLevel to 5 to enforce NTLMv2 only"
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary credential and token reconnaissance."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        # ── Enumerate current token information ───────────────────
        whoami = session.run_cmd("whoami /all")
        if whoami and whoami.stdout:
            self.add_finding(
                result,
                description="Simulated: Enumerated token information via whoami /all",
                severity=Severity.INFO,
                evidence=whoami.stdout[:500],
                recommendation="Monitor for whoami usage — common in post-exploitation reconnaissance",
            )

        # ── Check local admin group membership ────────────────────
        admins = session.run_cmd("net localgroup administrators")
        if admins and admins.stdout:
            self.add_finding(
                result,
                description="Simulated: Enumerated local Administrators group membership",
                severity=Severity.INFO,
                evidence=admins.stdout[:500],
                recommendation=(
                    "Minimize local administrator accounts. Use LAPS for local admin "
                    "password management."
                ),
            )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        pass  # Read-only checks — nothing to revert

    def get_mitigations(self) -> list[str]:
        return [
            "M1043 — Credential Access Protection: Enable Credential Guard to protect NTLM hashes",
            "M1026 — Privileged Account Management: Use LAPS and minimize local admin accounts",
            "M1032 — Multi-factor Authentication: Require MFA for privileged access",
            "M1052 — User Account Control: Enforce token filtering for remote connections",
            "M1018 — User Account Management: Disable WDigest and enforce NTLMv2 only",
        ]
