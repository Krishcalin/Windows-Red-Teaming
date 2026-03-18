"""Maps scan results to MITRE ATT&CK Navigator JSON layers.

Generates ATT&CK Navigator layer files that can be imported into
https://mitre-attack.github.io/attack-navigator/ for visualization.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from core.models import ScanResult, Severity

log = structlog.get_logger(component="mitre_mapper")

# ATT&CK Navigator color mapping by severity
NAVIGATOR_COLORS: dict[str, str] = {
    "CRITICAL": "#ff0000",
    "HIGH": "#ff6600",
    "MEDIUM": "#ffcc00",
    "LOW": "#66ccff",
    "INFO": "#99ccff",
    "CLEAN": "#00cc00",
    "SKIPPED": "#cccccc",
}


class MitreMapper:
    """Generates MITRE ATT&CK Navigator JSON layers from scan results."""

    LAYER_VERSION = "4.5"
    ATT_CK_VERSION = "15"
    NAVIGATOR_VERSION = "4.9.5"
    DOMAIN = "enterprise-attack"

    def __init__(self, output_dir: str | Path = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_layer(
        self,
        scan_result: ScanResult,
        output_file: str | None = None,
    ) -> Path:
        """Generate an ATT&CK Navigator layer JSON from scan results.

        Args:
            scan_result: Completed scan result.
            output_file: Optional output filename.

        Returns:
            Path to the generated layer file.
        """
        if output_file is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_file = f"attack_layer_{timestamp}.json"

        output_path = self.output_dir / output_file

        techniques = self._build_techniques(scan_result)

        layer: dict[str, Any] = {
            "name": f"Red Team Scan — {scan_result.target.host}",
            "versions": {
                "attack": self.ATT_CK_VERSION,
                "navigator": self.NAVIGATOR_VERSION,
                "layer": self.LAYER_VERSION,
            },
            "domain": self.DOMAIN,
            "description": (
                f"Scan results for {scan_result.target.host} "
                f"({scan_result.profile} profile, "
                f"{'simulated' if scan_result.simulate else 'check-only'})"
            ),
            "filters": {
                "platforms": [
                    "Windows",
                ],
            },
            "sorting": 3,  # sort by technique name
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#66ccff", "#ffcc00", "#ff0000"],
                "minValue": 0,
                "maxValue": 4,
            },
            "legendItems": [
                {"label": "Critical finding", "color": NAVIGATOR_COLORS["CRITICAL"]},
                {"label": "High finding", "color": NAVIGATOR_COLORS["HIGH"]},
                {"label": "Medium finding", "color": NAVIGATOR_COLORS["MEDIUM"]},
                {"label": "Low finding", "color": NAVIGATOR_COLORS["LOW"]},
                {"label": "Info only", "color": NAVIGATOR_COLORS["INFO"]},
                {"label": "No findings", "color": NAVIGATOR_COLORS["CLEAN"]},
                {"label": "Not tested", "color": NAVIGATOR_COLORS["SKIPPED"]},
            ],
            "metadata": [
                {"name": "scan_id", "value": scan_result.scan_id},
                {"name": "target", "value": scan_result.target.host},
                {"name": "profile", "value": scan_result.profile},
                {
                    "name": "generated",
                    "value": datetime.now(timezone.utc).isoformat(),
                },
            ],
        }

        output_path.write_text(
            json.dumps(layer, indent=2), encoding="utf-8"
        )
        log.info(
            "attack_layer_saved",
            path=str(output_path),
            techniques=len(techniques),
        )
        return output_path

    def _build_techniques(
        self, scan_result: ScanResult
    ) -> list[dict[str, Any]]:
        """Build the techniques array for the Navigator layer."""
        techniques: list[dict[str, Any]] = []

        for mr in scan_result.module_results:
            technique_id = mr.technique_id

            # Handle sub-technique IDs (T1059.001 → tactic + subtechnique)
            tactic_id = technique_id
            subtechnique_id = ""
            if "." in technique_id:
                parts = technique_id.split(".", 1)
                tactic_id = parts[0]
                subtechnique_id = technique_id

            # Determine color and score based on findings
            if mr.status in ("skipped", "error"):
                color = NAVIGATOR_COLORS["SKIPPED"]
                score = 0
                comment = mr.error_message
            elif mr.has_findings:
                max_sev = mr.max_severity
                color = NAVIGATOR_COLORS.get(
                    max_sev.value if max_sev else "INFO",
                    NAVIGATOR_COLORS["INFO"],
                )
                score = self._severity_to_score(max_sev)
                comment = "; ".join(
                    f.description[:100] for f in mr.findings[:5]
                )
            else:
                color = NAVIGATOR_COLORS["CLEAN"]
                score = 0
                comment = "No findings — control appears effective"

            entry: dict[str, Any] = {
                "techniqueID": subtechnique_id or tactic_id,
                "tactic": self._normalize_tactic(mr.tactic),
                "color": color,
                "comment": comment,
                "score": score,
                "enabled": True,
                "showSubtechniques": bool(subtechnique_id),
                "metadata": [
                    {"name": "status", "value": mr.status.value if hasattr(mr.status, 'value') else mr.status},
                    {"name": "findings_count", "value": str(len(mr.findings))},
                    {"name": "simulated", "value": str(mr.was_simulated)},
                ],
            }
            techniques.append(entry)

        return techniques

    @staticmethod
    def _severity_to_score(severity: Severity | None) -> int:
        """Map severity to a numeric score for the Navigator gradient."""
        if severity is None:
            return 0
        match severity:
            case Severity.CRITICAL:
                return 4
            case Severity.HIGH:
                return 3
            case Severity.MEDIUM:
                return 2
            case Severity.LOW:
                return 1
            case Severity.INFO:
                return 0

    @staticmethod
    def _normalize_tactic(tactic: str) -> str:
        """Normalize tactic name to ATT&CK Navigator format.

        e.g. "Privilege Escalation" → "privilege-escalation"
        """
        return tactic.lower().replace(" ", "-").replace("&", "and")
