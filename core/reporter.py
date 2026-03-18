"""Report generation for scan results.

Supports HTML, JSON, and CSV output formats.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import ScanResult, Severity

log = structlog.get_logger(component="reporter")

# Severity color mapping for HTML reports
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#0dcaf0",
    "INFO": "#6c757d",
}


class Reporter:
    """Generates scan reports in multiple formats."""

    def __init__(
        self,
        template_dir: str | Path = "templates",
        output_dir: str | Path = "reports",
    ) -> None:
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html"]),
        )

    def generate_html(
        self,
        scan_result: ScanResult,
        output_file: str | None = None,
    ) -> Path:
        """Generate an HTML report from scan results.

        Args:
            scan_result: The completed scan result.
            output_file: Optional output filename.

        Returns:
            Path to the generated HTML report.
        """
        if output_file is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_file = f"scan_{timestamp}.html"

        output_path = self.output_dir / output_file

        template = self._jinja_env.get_template("report.html")
        html = template.render(
            scan=scan_result.to_dict(),
            severity_colors=SEVERITY_COLORS,
            generated_at=datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            severity_order=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        )

        output_path.write_text(html, encoding="utf-8")
        log.info("html_report_saved", path=str(output_path))
        return output_path

    def generate_json(
        self,
        scan_result: ScanResult,
        output_file: str | None = None,
    ) -> Path:
        """Generate a JSON report from scan results."""
        if output_file is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_file = f"scan_{timestamp}.json"

        output_path = self.output_dir / output_file
        output_path.write_text(
            json.dumps(scan_result.to_dict(), indent=2),
            encoding="utf-8",
        )
        log.info("json_report_saved", path=str(output_path))
        return output_path

    def generate_csv(
        self,
        scan_result: ScanResult,
        output_file: str | None = None,
    ) -> Path:
        """Generate a CSV report of all findings."""
        if output_file is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_file = f"scan_{timestamp}.csv"

        output_path = self.output_dir / output_file

        fieldnames = [
            "finding_id",
            "technique_id",
            "technique_name",
            "tactic",
            "severity",
            "description",
            "evidence",
            "recommendation",
            "cwe",
            "timestamp",
        ]

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()

        for finding in scan_result.all_findings:
            row = finding.to_dict()
            row.pop("mitigations", None)
            writer.writerow(row)

        output_path.write_text(buffer.getvalue(), encoding="utf-8")
        log.info("csv_report_saved", path=str(output_path))
        return output_path

    def print_summary(self, scan_result: ScanResult) -> str:
        """Generate a text summary for terminal output.

        Returns:
            Formatted summary string.
        """
        data = scan_result.to_dict()
        lines = [
            "",
            "=" * 66,
            "  SCAN RESULTS SUMMARY",
            "=" * 66,
            f"  Scan ID      : {data['scan_id']}",
            f"  Target       : {data['target']['host']}",
            f"  Profile      : {data['profile']}",
            f"  Simulation   : {'Enabled' if data['simulate'] else 'Disabled'}",
            f"  Start        : {data['start_time']}",
            f"  End          : {data['end_time']}",
            "-" * 66,
            f"  Techniques tested      : {data['techniques_tested']}",
            f"  Techniques w/ findings : {data['techniques_with_findings']}",
            f"  Total findings         : {data['total_findings']}",
            "-" * 66,
            "  FINDINGS BY SEVERITY:",
        ]

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in severity_order:
            count = data["findings_by_severity"].get(sev, 0)
            marker = " !!" if sev in ("CRITICAL", "HIGH") and count > 0 else ""
            lines.append(f"    {sev:<10}: {count}{marker}")

        lines.extend(["=" * 66, ""])
        return "\n".join(lines)
