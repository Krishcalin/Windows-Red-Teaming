"""Compliance mapper for CIS Benchmark and NIST 800-53 controls.

Maps MITRE ATT&CK technique IDs used by this tool to their corresponding
CIS Benchmark v8 and NIST 800-53 Rev 5 controls, enabling compliance
reporting alongside red team findings.
"""

from __future__ import annotations

import json
import structlog
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import ScanResult, Finding, Severity

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# CIS Benchmark v8 control descriptions (for report readability)
# ---------------------------------------------------------------------------
CIS_CONTROL_DESCRIPTIONS: dict[str, str] = {
    "1.1": "Establish and Maintain Detailed Enterprise Asset Inventory",
    "1.2": "Address Unauthorized Assets",
    "2.1": "Establish and Maintain a Software Inventory",
    "2.2": "Ensure Authorized Software is Currently Supported",
    "2.5": "Allowlist Authorized Software",
    "2.6": "Allowlist Authorized Libraries",
    "2.7": "Allowlist Authorized Scripts",
    "3.1": "Establish and Maintain a Data Management Process",
    "3.3": "Configure Data Access Control Lists",
    "3.4": "Enforce Data Retention",
    "3.10": "Encrypt Sensitive Data in Transit",
    "3.11": "Encrypt Sensitive Data at Rest",
    "3.12": "Segment Data Processing and Storage Based on Sensitivity",
    "4.1": "Establish and Maintain a Secure Configuration Process",
    "4.2": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
    "4.3": "Configure Automatic Session Locking on Enterprise Assets",
    "4.4": "Implement and Manage a Firewall on Servers",
    "4.5": "Implement and Manage a Firewall on End-User Devices",
    "4.6": "Securely Manage Enterprise Assets and Software",
    "4.7": "Manage Default Accounts on Enterprise Assets and Software",
    "4.8": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
    "5.1": "Establish and Maintain an Inventory of Accounts",
    "5.2": "Use Unique Passwords",
    "5.3": "Disable Dormant Accounts",
    "5.4": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
    "5.5": "Establish and Maintain an Inventory of Service Accounts",
    "5.6": "Centralize Account Management",
    "6.1": "Establish an Access Granting Process",
    "6.2": "Establish an Access Revoking Process",
    "6.3": "Require MFA for Externally-Exposed Applications",
    "6.4": "Require MFA for Remote Network Access",
    "6.5": "Require MFA for Administrative Access",
    "6.7": "Centralize Access Control",
    "6.8": "Define and Maintain Role-Based Access Control",
    "7.1": "Establish and Maintain a Vulnerability Management Process",
    "7.2": "Establish and Maintain a Remediation Process",
    "7.6": "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets",
    "8.1": "Establish and Maintain an Audit Log Management Process",
    "8.2": "Collect Audit Logs",
    "8.3": "Ensure Adequate Audit Log Storage",
    "8.5": "Collect Detailed Audit Logs",
    "8.9": "Centralize Audit Logs",
    "8.11": "Conduct Audit Log Reviews",
    "9.1": "Ensure Use of Only Fully Supported Browsers and Email Clients",
    "9.2": "Use DNS Filtering Services",
    "9.3": "Maintain and Enforce Network-Based URL Filters",
    "10.1": "Deploy and Maintain Anti-Malware Software",
    "10.2": "Configure Automatic Anti-Malware Signature Updates",
    "10.5": "Enable Anti-Exploitation Features",
    "10.7": "Use Behavior-Based Anti-Malware Software",
    "11.1": "Establish and Maintain a Data Recovery Process",
    "11.2": "Perform Automated Backups",
    "11.3": "Protect Recovery Data",
    "11.4": "Establish and Maintain an Isolated Instance of Recovery Data",
    "12.1": "Ensure Network Infrastructure is Up-to-Date",
    "12.2": "Establish and Maintain a Secure Network Architecture",
    "12.6": "Use of Secure Network Management and Communication Protocols",
    "12.7": "Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise's AAA Infrastructure",
    "12.8": "Establish and Maintain Dedicated Computing Resources for All Administrative Work",
    "13.1": "Centralize Security Event Alerting",
    "13.3": "Deploy a Network Intrusion Detection Solution",
    "13.5": "Manage Access Control for Remote Assets",
    "13.6": "Collect Network Traffic Flow Logs",
    "13.7": "Deploy a Host-Based Intrusion Detection Solution",
    "13.8": "Deploy a Network Intrusion Prevention Solution",
    "16.1": "Establish and Maintain a Secure Application Development Process",
    "16.11": "Leverage Vetted Modules or Services for Application Security Components",
    "18.3": "Remediate Penetration Test Findings",
}


# ---------------------------------------------------------------------------
# NIST 800-53 Rev 5 control descriptions
# ---------------------------------------------------------------------------
NIST_CONTROL_DESCRIPTIONS: dict[str, str] = {
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-5": "Separation of Duties",
    "AC-6": "Least Privilege",
    "AC-7": "Unsuccessful Logon Attempts",
    "AC-12": "Session Termination",
    "AC-17": "Remote Access",
    "AC-18": "Wireless Access",
    "AU-2": "Event Logging",
    "AU-3": "Content of Audit Records",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "AU-9": "Protection of Audit Information",
    "AU-12": "Audit Record Generation",
    "CA-7": "Continuous Monitoring",
    "CA-8": "Penetration Testing",
    "CM-2": "Baseline Configuration",
    "CM-5": "Access Restrictions for Change",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CM-8": "System Component Inventory",
    "CM-10": "Software Usage Restrictions",
    "CM-11": "User-Installed Software",
    "CP-9": "System Backup",
    "CP-10": "System Recovery and Reconstitution",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-4": "Identifier Management",
    "IA-5": "Authenticator Management",
    "IR-4": "Incident Handling",
    "IR-5": "Incident Monitoring",
    "MA-4": "Nonlocal Maintenance",
    "MP-2": "Media Access",
    "PE-3": "Physical Access Control",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SA-11": "Developer Testing and Evaluation",
    "SC-4": "Information in Shared System Resources",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection",
    "SI-4": "System Monitoring",
    "SI-7": "Software, Firmware, and Information Integrity",
    "SI-16": "Memory Protection",
}


# ---------------------------------------------------------------------------
# ATT&CK technique → CIS Benchmark v8 mappings
# ---------------------------------------------------------------------------
TECHNIQUE_TO_CIS: dict[str, list[str]] = {
    # --- Discovery (TA0007) ---
    "T1082": ["1.1", "4.1"],                        # System Information Discovery
    "T1087": ["5.1", "5.3", "5.4"],                  # Account Discovery
    "T1069": ["5.4", "6.8"],                          # Permission Groups Discovery
    "T1046": ["4.4", "4.5", "12.2"],                  # Network Service Discovery
    "T1083": ["3.3", "4.1"],                          # File and Directory Discovery
    "T1057": ["2.1", "4.8"],                          # Process Discovery
    "T1049": ["12.2", "13.6"],                        # System Network Connections Discovery
    "T1016": ["1.1", "12.1"],                         # System Network Configuration Discovery
    "T1595": ["7.6", "12.2", "13.3"],                 # Active Scanning

    # --- Credential Access (TA0006) ---
    "T1003.001": ["6.1", "6.2", "6.5"],               # LSASS Memory
    "T1003.002": ["6.1", "6.2", "3.11"],              # SAM Database
    "T1003.003": ["6.1", "6.2", "3.11"],              # NTDS.dit
    "T1558.003": ["5.2", "6.3", "6.5"],               # Kerberoasting
    "T1552.001": ["3.1", "3.11", "16.11"],            # Credentials in Files
    "T1110": ["5.2", "6.3", "6.4"],                   # Brute Force

    # --- Privilege Escalation (TA0004) ---
    "T1548.002": ["4.1", "5.4", "6.8"],               # UAC Bypass
    "T1134": ["5.4", "6.1", "6.8"],                   # Access Token Manipulation
    "T1574.001": ["2.5", "2.6", "4.1"],               # DLL Search Order Hijacking
    "T1574.002": ["2.5", "2.6", "10.5"],              # DLL Side-Loading
    "T1210": ["7.1", "7.4", "18.3"],                  # Exploitation of Remote Services (CVE-2026-21533)
    "T1068": ["7.1", "7.4", "18.3"],                  # Exploitation for Privilege Escalation (CVE-2026-21519)

    # --- Execution (TA0002) ---
    "T1059.001": ["2.6", "2.7", "10.5"],              # PowerShell
    "T1059.003": ["2.7", "4.8", "10.5"],              # Windows Command Shell
    "T1047": ["4.1", "4.8", "5.4"],                   # WMI

    # --- Persistence (TA0003) ---
    "T1053.005": ["4.1", "5.4", "8.5"],               # Scheduled Task
    "T1547.001": ["4.1", "2.5", "10.5"],              # Registry Run Keys
    "T1546.001": ["2.5", "4.1", "10.5"],              # Change Default File Association

    # --- Defense Evasion (TA0005) ---
    "T1562.001": ["10.1", "10.2", "13.7"],            # Disable/Modify Security Tools
    "T1562.002": ["8.2", "8.5", "8.9"],               # Disable Windows Event Logging
    "T1036": ["2.1", "2.5", "10.7"],                  # Masquerading
    "T1070.001": ["8.2", "8.3", "8.9"],               # Clear Windows Event Logs
    "T1218": ["2.5", "2.6", "10.5"],                  # System Binary Proxy Execution (CVE-2026-21513)
    "T1553.005": ["2.5", "10.1", "10.5"],             # MOTW Bypass (CVE-2026-21510)

    # --- Lateral Movement (TA0008) ---
    "T1021.001": ["4.3", "6.4", "12.7"],              # RDP
    "T1021.002": ["4.4", "6.4", "12.8"],              # SMB/Admin Shares
    "T1021.006": ["4.1", "6.4", "12.8"],              # WinRM
    "T1550.002": ["6.3", "6.5", "13.5"],              # Pass the Hash

    # --- Command and Control (TA0011) ---
    "T1071.001": ["9.2", "9.3", "13.8"],              # Web Protocols

    # --- Exfiltration (TA0010) ---
    "T1048": ["3.10", "3.12", "13.6"],                # Exfiltration Over Alternative Protocol
    "T1041": ["3.10", "3.12", "13.6"],                # Exfiltration Over C2 Channel

    # --- Collection (TA0009) ---
    "T1113": ["3.3", "4.1", "6.1"],                   # Screen Capture
    "T1560": ["3.10", "3.11", "3.12"],                # Archive Collected Data
    "T1074": ["3.3", "3.12", "8.5"],                  # Data Staged

    # --- Impact (TA0040) ---
    "T1489": ["4.8", "11.1", "11.2"],                 # Service Stop
    "T1486": ["11.1", "11.2", "11.3", "11.4"],        # Data Encrypted for Impact (Ransomware)
    "T1529": ["4.1", "5.4", "11.1"],                  # System Shutdown/Reboot
}


# ---------------------------------------------------------------------------
# ATT&CK technique → NIST 800-53 Rev 5 mappings
# ---------------------------------------------------------------------------
TECHNIQUE_TO_NIST: dict[str, list[str]] = {
    # --- Discovery (TA0007) ---
    "T1082": ["CM-8", "RA-5", "SI-4"],                # System Information Discovery
    "T1087": ["AC-2", "IA-4", "CA-7"],                # Account Discovery
    "T1069": ["AC-2", "AC-5", "AC-6"],                # Permission Groups Discovery
    "T1046": ["SC-7", "CA-7", "RA-5"],                # Network Service Discovery
    "T1083": ["AC-3", "AC-6", "SI-4"],                # File and Directory Discovery
    "T1057": ["CM-7", "SI-4", "CA-7"],                # Process Discovery
    "T1049": ["SC-7", "SI-4", "CA-7"],                # System Network Connections Discovery
    "T1016": ["CM-8", "SC-7", "SI-4"],                # System Network Configuration Discovery
    "T1595": ["RA-5", "SC-7", "SI-4"],                # Active Scanning

    # --- Credential Access (TA0006) ---
    "T1003.001": ["AC-3", "IA-5", "SI-16"],           # LSASS Memory
    "T1003.002": ["AC-3", "IA-5", "SC-28"],           # SAM Database
    "T1003.003": ["AC-3", "IA-5", "SC-28"],           # NTDS.dit
    "T1558.003": ["IA-2", "IA-5", "SC-12"],           # Kerberoasting
    "T1552.001": ["IA-5", "SC-28", "CM-6"],           # Credentials in Files
    "T1110": ["AC-7", "IA-2", "IA-5"],                # Brute Force

    # --- Privilege Escalation (TA0004) ---
    "T1548.002": ["AC-6", "CM-6", "CM-7"],            # UAC Bypass
    "T1134": ["AC-3", "AC-5", "AC-6"],                # Access Token Manipulation
    "T1574.001": ["CM-6", "CM-7", "SI-7"],            # DLL Search Order Hijacking
    "T1574.002": ["CM-7", "SI-7", "CM-11"],           # DLL Side-Loading
    "T1210": ["SI-2", "SI-5", "RA-5"],                # Exploitation of Remote Services (CVE-2026-21533)
    "T1068": ["SI-2", "SI-7", "RA-5"],                # Exploitation for Privilege Escalation (CVE-2026-21519)

    # --- Execution (TA0002) ---
    "T1059.001": ["CM-7", "SI-7", "SI-16"],           # PowerShell
    "T1059.003": ["CM-7", "SI-7", "CM-11"],           # Windows Command Shell
    "T1047": ["AC-3", "CM-7", "SC-4"],                # WMI

    # --- Persistence (TA0003) ---
    "T1053.005": ["AC-3", "CM-6", "AU-2"],            # Scheduled Task
    "T1547.001": ["CM-6", "CM-7", "SI-7"],            # Registry Run Keys
    "T1546.001": ["CM-6", "CM-7", "SI-7"],            # Change Default File Association

    # --- Defense Evasion (TA0005) ---
    "T1562.001": ["SI-3", "SI-4", "CM-6"],            # Disable/Modify Security Tools
    "T1562.002": ["AU-2", "AU-9", "AU-12"],           # Disable Windows Event Logging
    "T1036": ["CM-7", "SI-3", "SI-7"],                # Masquerading
    "T1070.001": ["AU-9", "AU-3", "AU-6"],            # Clear Windows Event Logs
    "T1218": ["CM-7", "SI-7", "CM-11"],               # System Binary Proxy Execution (CVE-2026-21513)
    "T1553.005": ["CM-6", "SI-3", "SI-7"],            # MOTW Bypass (CVE-2026-21510)

    # --- Lateral Movement (TA0008) ---
    "T1021.001": ["AC-17", "CM-6", "SC-8"],           # RDP
    "T1021.002": ["AC-3", "AC-17", "SC-7"],           # SMB/Admin Shares
    "T1021.006": ["AC-17", "CM-6", "IA-2"],           # WinRM
    "T1550.002": ["IA-2", "IA-5", "SI-4"],            # Pass the Hash

    # --- Command and Control (TA0011) ---
    "T1071.001": ["SC-7", "SI-4", "SC-8"],            # Web Protocols

    # --- Exfiltration (TA0010) ---
    "T1048": ["AC-4", "SC-7", "SI-4"],                # Exfiltration Over Alternative Protocol
    "T1041": ["AC-4", "SC-7", "SI-4"],                # Exfiltration Over C2 Channel

    # --- Collection (TA0009) ---
    "T1113": ["AC-3", "SC-4", "SI-4"],                # Screen Capture
    "T1560": ["SC-13", "SC-28", "SI-4"],              # Archive Collected Data
    "T1074": ["AC-3", "SC-28", "SI-4"],               # Data Staged

    # --- Impact (TA0040) ---
    "T1489": ["CM-6", "CP-9", "IR-4"],                # Service Stop
    "T1486": ["CP-9", "CP-10", "SC-28"],              # Data Encrypted for Impact (Ransomware)
    "T1529": ["AC-6", "CM-6", "CP-9"],                # System Shutdown/Reboot
}


class ComplianceMapper:
    """Maps ATT&CK technique findings to CIS Benchmark v8 and NIST 800-53 Rev 5 controls.

    Provides methods to enrich scan results with compliance framework
    mappings and generate standalone compliance reports.
    """

    def __init__(self) -> None:
        self.technique_to_cis = TECHNIQUE_TO_CIS
        self.technique_to_nist = TECHNIQUE_TO_NIST
        self.cis_descriptions = CIS_CONTROL_DESCRIPTIONS
        self.nist_descriptions = NIST_CONTROL_DESCRIPTIONS

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_cis_controls(self, technique_id: str) -> list[str]:
        """Return CIS Benchmark v8 controls mapped to a technique ID.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g. ``T1003.001``).

        Returns:
            List of CIS control identifiers, or empty list if unmapped.
        """
        return list(self.technique_to_cis.get(technique_id, []))

    def get_nist_controls(self, technique_id: str) -> list[str]:
        """Return NIST 800-53 Rev 5 controls mapped to a technique ID.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g. ``T1003.001``).

        Returns:
            List of NIST control identifiers, or empty list if unmapped.
        """
        return list(self.technique_to_nist.get(technique_id, []))

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------

    def _enrich_finding(self, finding: Finding) -> dict[str, Any]:
        """Build a compliance-enriched dict for a single finding."""
        tid = finding.technique_id
        cis_ids = self.get_cis_controls(tid)
        nist_ids = self.get_nist_controls(tid)

        return {
            "finding_id": finding.finding_id,
            "technique_id": tid,
            "technique_name": finding.technique_name,
            "tactic": finding.tactic,
            "severity": finding.severity.value,
            "description": finding.description,
            "cis_controls": [
                {
                    "id": cid,
                    "description": self.cis_descriptions.get(cid, ""),
                }
                for cid in cis_ids
            ],
            "nist_controls": [
                {
                    "id": nid,
                    "description": self.nist_descriptions.get(nid, ""),
                }
                for nid in nist_ids
            ],
        }

    def map_findings(self, scan_result: ScanResult) -> dict[str, Any]:
        """Map all findings in a scan result to CIS and NIST controls.

        Args:
            scan_result: A completed :class:`ScanResult`.

        Returns:
            A dict containing:
            - ``scan_id``: the original scan identifier
            - ``target``: target host info
            - ``generated_at``: ISO-8601 timestamp
            - ``summary``: counts of unique CIS/NIST controls implicated
            - ``findings``: list of enriched finding dicts
        """
        enriched_findings: list[dict[str, Any]] = []
        unique_cis: set[str] = set()
        unique_nist: set[str] = set()

        for finding in scan_result.all_findings:
            enriched = self._enrich_finding(finding)
            enriched_findings.append(enriched)
            unique_cis.update(c["id"] for c in enriched["cis_controls"])
            unique_nist.update(c["id"] for c in enriched["nist_controls"])

        # Build per-framework summaries
        cis_summary = sorted(
            [
                {"id": cid, "description": self.cis_descriptions.get(cid, "")}
                for cid in unique_cis
            ],
            key=lambda x: x["id"],
        )
        nist_summary = sorted(
            [
                {"id": nid, "description": self.nist_descriptions.get(nid, "")}
                for nid in unique_nist
            ],
            key=lambda x: x["id"],
        )

        return {
            "scan_id": scan_result.scan_id,
            "target": scan_result.target.to_dict(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(enriched_findings),
                "unique_cis_controls_implicated": len(unique_cis),
                "unique_nist_controls_implicated": len(unique_nist),
                "cis_controls": cis_summary,
                "nist_controls": nist_summary,
            },
            "findings": enriched_findings,
        }

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_compliance_report(
        self,
        scan_result: ScanResult,
        output_file: str | None = None,
    ) -> Path:
        """Generate a JSON compliance report and write it to disk.

        Args:
            scan_result: A completed :class:`ScanResult`.
            output_file: Optional output path. Defaults to
                ``reports/compliance_<scan_id>.json``.

        Returns:
            :class:`Path` to the written report file.
        """
        report_data = self.map_findings(scan_result)

        if output_file is None:
            reports_dir = Path("reports")
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = reports_dir / f"compliance_{scan_result.scan_id}.json"
        else:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        logger.info(
            "compliance_report_generated",
            path=str(output_path),
            findings=report_data["summary"]["total_findings"],
            cis_controls=report_data["summary"]["unique_cis_controls_implicated"],
            nist_controls=report_data["summary"]["unique_nist_controls_implicated"],
        )

        return output_path
