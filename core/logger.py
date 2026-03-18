"""Structured logging and evidence chain for the Windows Red Teaming tool.

Uses structlog for structured, context-rich logging. Every scan action
produces an audit log entry with timestamp, target, technique ID, and result.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import structlog


def setup_logging(
    *,
    verbose: bool = False,
    log_file: str | None = None,
    json_output: bool = False,
) -> structlog.stdlib.BoundLogger:
    """Configure structlog for the application.

    Args:
        verbose: Enable DEBUG level output.
        log_file: Optional file path for log output.
        json_output: Use JSON formatting instead of console formatting.

    Returns:
        Configured bound logger instance.
    """
    log_level = "DEBUG" if verbose else "INFO"

    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(
            structlog.dev.ConsoleRenderer(
                colors=sys.stdout.isatty(),
            )
        )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(
            file=open(log_file, "a", encoding="utf-8") if log_file else sys.stderr  # noqa: SIM115
        ),
        cache_logger_on_first_use=True,
    )

    logger = structlog.get_logger()
    structlog.contextvars.clear_contextvars()

    return logger


def get_logger(**kwargs: str) -> structlog.stdlib.BoundLogger:
    """Get a logger instance with optional bound context."""
    return structlog.get_logger(**kwargs)


class EvidenceLogger:
    """Records an audit trail of all scan actions and evidence artifacts.

    Every check/simulate action is logged as a structured JSON entry
    so scans can be reviewed and reproduced.
    """

    def __init__(self, evidence_dir: str | Path = "evidence") -> None:
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._entries: list[dict] = []
        self._log = get_logger(component="evidence")

    def record(
        self,
        *,
        action: str,
        technique_id: str,
        target: str,
        result: str,
        detail: str = "",
        evidence_data: str = "",
    ) -> None:
        """Record a single audit log entry.

        Args:
            action: The action taken (check, simulate, cleanup).
            technique_id: MITRE ATT&CK technique ID.
            target: Target host identifier.
            result: Outcome (pass, fail, error, skipped).
            detail: Human-readable detail string.
            evidence_data: Raw evidence (command output, etc.).
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "technique_id": technique_id,
            "target": target,
            "result": result,
            "detail": detail,
        }
        self._entries.append(entry)
        self._log.info(
            "evidence_recorded",
            action=action,
            technique_id=technique_id,
            target=target,
            result=result,
        )

        if evidence_data:
            self._save_artifact(technique_id, action, evidence_data)

    def _save_artifact(
        self, technique_id: str, action: str, data: str
    ) -> Path:
        """Save raw evidence data to a file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{technique_id}_{action}_{timestamp}.txt"
        artifact_path = self.evidence_dir / filename
        artifact_path.write_text(data, encoding="utf-8")
        self._log.debug("artifact_saved", path=str(artifact_path))
        return artifact_path

    def save_chain(self, scan_id: str) -> Path:
        """Save the full evidence chain for a scan to a JSON file.

        Args:
            scan_id: Unique scan identifier.

        Returns:
            Path to the saved evidence chain file.
        """
        chain_path = self.evidence_dir / f"chain_{scan_id}.json"
        chain_path.write_text(
            json.dumps(self._entries, indent=2), encoding="utf-8"
        )
        self._log.info(
            "evidence_chain_saved",
            path=str(chain_path),
            entries=len(self._entries),
        )
        return chain_path
