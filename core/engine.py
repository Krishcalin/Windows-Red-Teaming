"""Main orchestrator — loads modules, runs scans.

The engine discovers technique modules at runtime by scanning the
modules/ package tree, then executes them against targets based on
the selected profile, tactic, or technique filters.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

import modules as modules_pkg
from core.logger import EvidenceLogger
from core.models import (
    ModuleResult,
    ModuleStatus,
    ScanResult,
    Severity,
    Target,
)
from core.session import BaseSession, create_session
from modules.base import BaseModule

log = structlog.get_logger(component="engine")


class ScanEngine:
    """Main scan orchestrator.

    Discovers technique modules, applies filters, and executes them
    against targets with evidence logging.
    """

    # Authorization banner shown before every scan
    AUTHORIZATION_BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║              WINDOWS RED TEAMING — SECURITY SCANNER             ║
║                                                                  ║
║  WARNING: This tool performs active security testing.             ║
║  Use ONLY on systems you are authorized to test.                 ║
║                                                                  ║
║  Unauthorized access to computer systems is illegal.             ║
║  The user assumes all responsibility for the use of this tool.   ║
╚══════════════════════════════════════════════════════════════════╝
"""

    def __init__(
        self,
        *,
        profile: str = "full",
        simulate: bool = False,
        tactic_filter: str | None = None,
        technique_filter: str | None = None,
        severity_threshold: Severity = Severity.INFO,
        evidence_dir: str = "evidence",
        enabled_techniques: set[str] | None = None,
        disabled_techniques: set[str] | None = None,
    ) -> None:
        self.profile = profile
        self.simulate = simulate
        self.tactic_filter = tactic_filter
        self.technique_filter = technique_filter
        self.severity_threshold = severity_threshold
        self.evidence = EvidenceLogger(evidence_dir)
        self.enabled_techniques = enabled_techniques
        self.disabled_techniques = disabled_techniques or set()

        self._modules: list[BaseModule] = []
        self._discover_modules()

    def _discover_modules(self) -> None:
        """Auto-discover all technique modules under the modules/ package.

        Walks the modules/ package tree, imports every module, and
        collects classes that inherit from BaseModule.
        """
        discovered = 0
        modules_path = Path(modules_pkg.__file__).parent

        for importer, modname, ispkg in pkgutil.walk_packages(
            path=[str(modules_path)],
            prefix="modules.",
        ):
            if ispkg:
                continue
            if modname.endswith("base") or modname.endswith("__init__"):
                continue

            try:
                mod = importlib.import_module(modname)
            except Exception as e:
                log.warning("module_import_error", module=modname, error=str(e))
                continue

            for _name, obj in inspect.getmembers(mod, inspect.isclass):
                if (
                    issubclass(obj, BaseModule)
                    and obj is not BaseModule
                    and not inspect.isabstract(obj)
                ):
                    self._modules.append(obj())
                    discovered += 1
                    log.debug(
                        "module_discovered",
                        technique_id=obj.TECHNIQUE_ID,
                        name=obj.TECHNIQUE_NAME,
                    )

        log.info("discovery_complete", modules_found=discovered)

    def _apply_filters(self) -> list[BaseModule]:
        """Filter discovered modules based on engine configuration."""
        filtered = list(self._modules)

        # Technique filter (single technique)
        if self.technique_filter:
            filtered = [
                m for m in filtered
                if m.TECHNIQUE_ID == self.technique_filter
            ]

        # Tactic filter
        if self.tactic_filter:
            tactic = self.tactic_filter.lower()
            filtered = [
                m for m in filtered
                if m.TACTIC.lower() == tactic
            ]

        # Enabled/disabled technique sets (from config)
        if self.enabled_techniques is not None:
            filtered = [
                m for m in filtered
                if m.TECHNIQUE_ID in self.enabled_techniques
            ]

        if self.disabled_techniques:
            filtered = [
                m for m in filtered
                if m.TECHNIQUE_ID not in self.disabled_techniques
            ]

        return filtered

    def scan(self, target: Target) -> ScanResult:
        """Execute a full scan against a target.

        Args:
            target: The target to scan.

        Returns:
            ScanResult with all module results.
        """
        scan_result = ScanResult(
            target=target,
            profile=self.profile,
            simulate=self.simulate,
        )

        log.info(
            "scan_started",
            target=target.host,
            profile=self.profile,
            simulate=self.simulate,
        )

        modules_to_run = self._apply_filters()
        log.info("modules_selected", count=len(modules_to_run))

        session = create_session(target)

        try:
            session.connect()

            # Detect OS if not already set
            if target.os_type is None:
                session.detect_os()

            for module in modules_to_run:
                result = self._run_module(module, session)
                scan_result.add_module_result(result)

        except (ConnectionError, RuntimeError) as e:
            log.error("scan_connection_error", error=str(e))
            error_result = ModuleResult(
                technique_id="ENGINE",
                technique_name="Connection",
                tactic="Infrastructure",
                status=ModuleStatus.ERROR,
                error_message=str(e),
                target_host=target.host,
            )
            error_result.complete()
            scan_result.add_module_result(error_result)
        finally:
            session.disconnect()

        scan_result.complete()

        # Save evidence chain
        self.evidence.save_chain(scan_result.scan_id)

        log.info(
            "scan_complete",
            target=target.host,
            techniques_tested=scan_result.techniques_tested,
            total_findings=scan_result.total_findings,
            findings_by_severity=scan_result.findings_by_severity,
        )

        return scan_result

    def _run_module(
        self, module: BaseModule, session: BaseSession
    ) -> ModuleResult:
        """Execute a single technique module.

        Handles OS compatibility checks, admin requirements,
        and check/simulate mode selection.
        """
        technique_id = module.TECHNIQUE_ID
        target_host = session.target.host

        log.info(
            "module_start",
            technique_id=technique_id,
            name=module.TECHNIQUE_NAME,
        )

        # OS compatibility check
        if not module.supports_os(session.os_type):
            reason = (
                f"{module.TECHNIQUE_NAME} does not support "
                f"{session.os_type.value if session.os_type else 'unknown OS'}"
            )
            self.evidence.record(
                action="check",
                technique_id=technique_id,
                target=target_host,
                result="skipped",
                detail=reason,
            )
            return module.skip_result(reason, target_host)

        try:
            # Always run the passive check
            result = module.check(session)

            self.evidence.record(
                action="check",
                technique_id=technique_id,
                target=target_host,
                result="findings" if result.has_findings else "clean",
                detail=f"{len(result.findings)} findings",
            )

            # Run simulation if requested and module supports it
            if self.simulate and not module.SAFE_MODE:
                log.info("simulate_start", technique_id=technique_id)
                try:
                    sim_result = module.simulate(session)
                    # Merge simulation findings into the check result
                    for finding in sim_result.findings:
                        result.add_finding(finding)
                    result.was_simulated = True

                    self.evidence.record(
                        action="simulate",
                        technique_id=technique_id,
                        target=target_host,
                        result="complete",
                        detail=f"{len(sim_result.findings)} simulation findings",
                    )
                finally:
                    # Always cleanup after simulation
                    try:
                        module.cleanup(session)
                        self.evidence.record(
                            action="cleanup",
                            technique_id=technique_id,
                            target=target_host,
                            result="success",
                        )
                    except Exception as cleanup_err:
                        log.error(
                            "cleanup_failed",
                            technique_id=technique_id,
                            error=str(cleanup_err),
                        )
                        self.evidence.record(
                            action="cleanup",
                            technique_id=technique_id,
                            target=target_host,
                            result="error",
                            detail=str(cleanup_err),
                        )

            result.complete(ModuleStatus.SUCCESS)

        except Exception as e:
            log.error(
                "module_error",
                technique_id=technique_id,
                error=str(e),
            )
            self.evidence.record(
                action="check",
                technique_id=technique_id,
                target=target_host,
                result="error",
                detail=str(e),
            )
            result = module.error_result(str(e), target_host)

        log.info(
            "module_complete",
            technique_id=technique_id,
            status=result.status.value,
            findings=len(result.findings),
        )

        return result

    @property
    def discovered_modules(self) -> list[dict[str, Any]]:
        """Return metadata about all discovered modules."""
        return [
            {
                "technique_id": m.TECHNIQUE_ID,
                "technique_name": m.TECHNIQUE_NAME,
                "tactic": m.TACTIC,
                "severity": m.SEVERITY.value,
                "requires_admin": m.REQUIRES_ADMIN,
                "safe_mode": m.SAFE_MODE,
                "supported_os": [os.value for os in m.SUPPORTED_OS],
            }
            for m in self._modules
        ]
