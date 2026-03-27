"""T1021.002 — SMB/Windows Admin Shares.

Audits SMB configuration for insecure settings including exposed
administrative shares, SMBv1 protocol, and missing SMB signing
that could allow adversaries to move laterally.
"""

from __future__ import annotations

from core.models import ModuleResult, ModuleStatus, OSType, Severity
from core.session import BaseSession
from modules.base import BaseModule


class SMBSharesAudit(BaseModule):
    """T1021.002 — SMB/Windows Admin Shares.

    Checks whether administrative shares are exposed, SMBv1 is
    disabled, and SMB signing is enforced.
    """

    TECHNIQUE_ID = "T1021.002"
    TECHNIQUE_NAME = "SMB/Windows Admin Shares"
    TACTIC = "Lateral Movement"
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = True
    SAFE_MODE = True

    def check(self, session: BaseSession) -> ModuleResult:
        result = self.create_result(target_host=session.target.host)

        # ── List SMB shares ───────────────────────────────────────
        shares = session.run_powershell(
            "Get-SmbShare | Select-Object Name,Path,Description | ConvertTo-Json"
        )
        if shares and shares.stdout:
            self._log.info("smb_shares_collected", output=shares.stdout[:200])

        # ── Check admin shares (C$, ADMIN$, IPC$) ────────────────
        net_share = session.run_cmd("net share")
        if net_share and net_share.stdout:
            admin_shares = []
            for line in net_share.stdout.splitlines():
                stripped = line.strip()
                for share_name in ("C$", "ADMIN$", "IPC$"):
                    if stripped.startswith(share_name):
                        admin_shares.append(share_name)
            if admin_shares:
                self.add_finding(
                    result,
                    description=f"Administrative shares are exposed: {', '.join(admin_shares)}",
                    severity=Severity.HIGH,
                    evidence=net_share.stdout[:500],
                    recommendation=(
                        "Disable administrative shares if not required by setting "
                        "AutoShareServer/AutoShareWks to 0 in "
                        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
                    ),
                    cwe="CWE-732",
                )

        # ── Check SMBv1 enabled ───────────────────────────────────
        smbv1 = session.run_powershell(
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json"
        )
        if smbv1 and smbv1.stdout:
            output = smbv1.stdout.strip()
            if "true" in output.lower():
                self.add_finding(
                    result,
                    description="SMBv1 protocol is enabled — vulnerable to EternalBlue and other exploits",
                    severity=Severity.CRITICAL,
                    evidence=output[:500],
                    recommendation=(
                        "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false "
                        "or via Group Policy"
                    ),
                    cwe="CWE-327",
                )

        # ── Check SMB signing ────────────────────────────────────
        signing = session.run_powershell(
            "Get-SmbServerConfiguration | "
            "Select-Object RequireSecuritySignature,EnableSecuritySignature | ConvertTo-Json"
        )
        if signing and signing.stdout:
            output = signing.stdout.strip()
            if '"RequireSecuritySignature":  false' in output.lower() or \
               '"requiresecuritysignature": false' in output.lower():
                self.add_finding(
                    result,
                    description="SMB signing is not required — vulnerable to relay attacks",
                    severity=Severity.HIGH,
                    evidence=output[:500],
                    recommendation=(
                        "Enforce SMB signing: Set-SmbServerConfiguration "
                        "-RequireSecuritySignature $true or via Group Policy "
                        "'Microsoft network server: Digitally sign communications (always)'"
                    ),
                    cwe="CWE-345",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def simulate(self, session: BaseSession) -> ModuleResult:
        """Simulate adversary SMB share enumeration."""
        result = self.create_result(
            target_host=session.target.host, simulated=True
        )

        # ── Enumerate accessible shares via net use ───────────────
        net_use = session.run_cmd("net use")
        if net_use and net_use.stdout:
            self.add_finding(
                result,
                description="Simulated: Enumerated current SMB connections via net use",
                severity=Severity.INFO,
                evidence=net_use.stdout[:500],
                recommendation="Monitor for unauthorized net use commands and SMB enumeration",
            )

        # ── Check null session access ─────────────────────────────
        target_host = session.target.host
        null_session = session.run_cmd(
            f'net use \\\\{target_host}\\IPC$ "" /user:""'
        )
        if null_session:
            if null_session.return_code == 0:
                self.add_finding(
                    result,
                    description="Simulated: Null session connection to IPC$ succeeded",
                    severity=Severity.HIGH,
                    evidence=null_session.stdout[:500],
                    recommendation=(
                        "Disable null sessions: Set RestrictAnonymous to 1 or 2 in "
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
                    ),
                    cwe="CWE-287",
                )
                # Clean up the test connection
                session.run_cmd(f"net use \\\\{target_host}\\IPC$ /delete /y")
            else:
                self.add_finding(
                    result,
                    description="Simulated: Null session connection to IPC$ was denied",
                    severity=Severity.INFO,
                    evidence=null_session.stderr[:500] if null_session.stderr else "Connection denied",
                    recommendation="Null sessions are properly restricted",
                )

        result.complete(ModuleStatus.SUCCESS)
        return result

    def cleanup(self, session: BaseSession) -> None:
        # Clean up any test null session connection that may remain
        target_host = session.target.host
        session.run_cmd(f"net use \\\\{target_host}\\IPC$ /delete /y")

    def get_mitigations(self) -> list[str]:
        return [
            "M1037 — Filter Network Traffic: Restrict SMB traffic (TCP 445) to required hosts only",
            "M1035 — Limit Access to Resource Over Network: Disable administrative shares if not needed",
            "M1042 — Disable or Remove Feature: Disable SMBv1 protocol",
            "M1026 — Privileged Account Management: Limit accounts with remote share access",
            "M1031 — Network Intrusion Prevention: Enable SMB signing to prevent relay attacks",
        ]
