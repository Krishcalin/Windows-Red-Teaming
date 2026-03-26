"""Atomic test runner — loads and executes YAML-defined atomic tests.

Discovers atomic test YAML files from the atomics/ directory, resolves
input arguments, checks dependencies, executes commands through our
session abstraction, and runs cleanup commands afterward.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.atomic_models import (
    AtomicTechnique,
    AtomicTest,
    ExecutorType,
)
from core.models import (
    Finding,
    ModuleResult,
    ModuleStatus,
    Severity,
)
from core.session import BaseSession, CommandResult

log = structlog.get_logger(component="atomic_runner")

# Technique → primary tactic mapping (MITRE ATT&CK for Enterprise)
_TECHNIQUE_TACTIC: dict[str, str] = {
    # Reconnaissance (TA0043)
    "T1595": "Reconnaissance", "T1595.001": "Reconnaissance",
    "T1595.002": "Reconnaissance", "T1595.003": "Reconnaissance",
    "T1592": "Reconnaissance", "T1592.001": "Reconnaissance",
    "T1589": "Reconnaissance", "T1590": "Reconnaissance",
    "T1591": "Reconnaissance", "T1593": "Reconnaissance",
    "T1594": "Reconnaissance", "T1596": "Reconnaissance",
    "T1597": "Reconnaissance", "T1598": "Reconnaissance",
    # Initial Access (TA0001)
    "T1566": "Initial Access", "T1566.001": "Initial Access",
    "T1566.002": "Initial Access", "T1190": "Initial Access",
    "T1078": "Initial Access", "T1078.001": "Initial Access",
    "T1078.002": "Initial Access", "T1078.003": "Initial Access",
    "T1133": "Initial Access", "T1195": "Initial Access",
    "T1091": "Initial Access", "T1199": "Initial Access",
    # Execution (TA0002)
    "T1059": "Execution", "T1059.001": "Execution",
    "T1059.003": "Execution", "T1059.005": "Execution",
    "T1059.007": "Execution", "T1059.010": "Execution",
    "T1047": "Execution", "T1053": "Execution",
    "T1053.002": "Execution", "T1053.005": "Execution",
    "T1106": "Execution", "T1129": "Execution",
    "T1204": "Execution", "T1204.002": "Execution",
    "T1559": "Execution", "T1559.002": "Execution",
    "T1569": "Execution", "T1569.002": "Execution",
    "T1072": "Execution",
    # Persistence (TA0003)
    "T1547": "Persistence", "T1547.001": "Persistence",
    "T1547.002": "Persistence", "T1547.003": "Persistence",
    "T1547.004": "Persistence", "T1547.005": "Persistence",
    "T1547.008": "Persistence", "T1547.009": "Persistence",
    "T1547.010": "Persistence", "T1547.012": "Persistence",
    "T1547.014": "Persistence",
    "T1546": "Persistence", "T1546.001": "Persistence",
    "T1546.002": "Persistence", "T1546.003": "Persistence",
    "T1546.007": "Persistence", "T1546.008": "Persistence",
    "T1546.009": "Persistence", "T1546.010": "Persistence",
    "T1546.011": "Persistence", "T1546.012": "Persistence",
    "T1546.013": "Persistence", "T1546.015": "Persistence",
    "T1546.018": "Persistence",
    "T1136": "Persistence", "T1136.001": "Persistence",
    "T1136.002": "Persistence",
    "T1543": "Persistence", "T1543.003": "Persistence",
    "T1505": "Persistence", "T1505.003": "Persistence",
    "T1037": "Persistence", "T1037.001": "Persistence",
    "T1098": "Persistence", "T1176": "Persistence",
    "T1137": "Persistence", "T1137.001": "Persistence",
    "T1137.002": "Persistence", "T1137.004": "Persistence",
    "T1137.006": "Persistence",
    # Privilege Escalation (TA0004)
    "T1134": "Privilege Escalation", "T1134.001": "Privilege Escalation",
    "T1134.002": "Privilege Escalation", "T1134.004": "Privilege Escalation",
    "T1134.005": "Privilege Escalation",
    "T1055": "Privilege Escalation", "T1055.001": "Privilege Escalation",
    "T1055.002": "Privilege Escalation", "T1055.003": "Privilege Escalation",
    "T1055.004": "Privilege Escalation", "T1055.011": "Privilege Escalation",
    "T1055.012": "Privilege Escalation", "T1055.015": "Privilege Escalation",
    "T1548": "Privilege Escalation", "T1548.002": "Privilege Escalation",
    "T1574": "Privilege Escalation", "T1574.001": "Privilege Escalation",
    "T1574.002": "Privilege Escalation", "T1574.008": "Privilege Escalation",
    "T1574.009": "Privilege Escalation", "T1574.011": "Privilege Escalation",
    "T1574.012": "Privilege Escalation",
    "T1484": "Privilege Escalation", "T1484.001": "Privilege Escalation",
    # Defense Evasion (TA0005)
    "T1562": "Defense Evasion", "T1562.001": "Defense Evasion",
    "T1562.002": "Defense Evasion", "T1562.003": "Defense Evasion",
    "T1562.004": "Defense Evasion", "T1562.006": "Defense Evasion",
    "T1562.009": "Defense Evasion", "T1562.010": "Defense Evasion",
    "T1036": "Defense Evasion", "T1036.003": "Defense Evasion",
    "T1036.004": "Defense Evasion", "T1036.005": "Defense Evasion",
    "T1036.007": "Defense Evasion",
    "T1070": "Defense Evasion", "T1070.001": "Defense Evasion",
    "T1070.003": "Defense Evasion", "T1070.004": "Defense Evasion",
    "T1070.005": "Defense Evasion", "T1070.006": "Defense Evasion",
    "T1027": "Defense Evasion", "T1027.004": "Defense Evasion",
    "T1027.006": "Defense Evasion", "T1027.007": "Defense Evasion",
    "T1027.013": "Defense Evasion",
    "T1112": "Defense Evasion",
    "T1218": "Defense Evasion", "T1218.001": "Defense Evasion",
    "T1218.002": "Defense Evasion", "T1218.003": "Defense Evasion",
    "T1218.004": "Defense Evasion", "T1218.005": "Defense Evasion",
    "T1218.007": "Defense Evasion", "T1218.008": "Defense Evasion",
    "T1218.009": "Defense Evasion", "T1218.010": "Defense Evasion",
    "T1218.011": "Defense Evasion",
    "T1140": "Defense Evasion", "T1197": "Defense Evasion",
    "T1202": "Defense Evasion", "T1207": "Defense Evasion",
    "T1216": "Defense Evasion", "T1216.001": "Defense Evasion",
    "T1220": "Defense Evasion", "T1221": "Defense Evasion",
    "T1222": "Defense Evasion", "T1222.001": "Defense Evasion",
    "T1127": "Defense Evasion", "T1127.001": "Defense Evasion",
    "T1553": "Defense Evasion", "T1553.003": "Defense Evasion",
    "T1553.004": "Defense Evasion", "T1553.005": "Defense Evasion",
    "T1553.006": "Defense Evasion",
    "T1550": "Defense Evasion", "T1550.002": "Defense Evasion",
    "T1550.003": "Defense Evasion",
    "T1564": "Defense Evasion", "T1564.001": "Defense Evasion",
    "T1564.002": "Defense Evasion", "T1564.003": "Defense Evasion",
    "T1564.004": "Defense Evasion", "T1564.006": "Defense Evasion",
    "T1006": "Defense Evasion", "T1542": "Defense Evasion",
    "T1542.001": "Defense Evasion",
    "T1497": "Defense Evasion", "T1497.001": "Defense Evasion",
    "T1556": "Defense Evasion", "T1556.002": "Defense Evasion",
    "T1620": "Defense Evasion", "T1622": "Defense Evasion",
    # Credential Access (TA0006)
    "T1003": "Credential Access", "T1003.001": "Credential Access",
    "T1003.002": "Credential Access", "T1003.003": "Credential Access",
    "T1003.004": "Credential Access", "T1003.005": "Credential Access",
    "T1003.006": "Credential Access",
    "T1558": "Credential Access", "T1558.001": "Credential Access",
    "T1558.002": "Credential Access", "T1558.003": "Credential Access",
    "T1558.004": "Credential Access",
    "T1110": "Credential Access", "T1110.001": "Credential Access",
    "T1110.002": "Credential Access", "T1110.003": "Credential Access",
    "T1110.004": "Credential Access",
    "T1552": "Credential Access", "T1552.001": "Credential Access",
    "T1552.002": "Credential Access", "T1552.004": "Credential Access",
    "T1552.006": "Credential Access",
    "T1555": "Credential Access", "T1555.003": "Credential Access",
    "T1555.004": "Credential Access",
    "T1056": "Credential Access", "T1056.001": "Credential Access",
    "T1040": "Credential Access", "T1187": "Credential Access",
    "T1539": "Credential Access", "T1649": "Credential Access",
    "T1557": "Credential Access", "T1557.001": "Credential Access",
    # Discovery (TA0007)
    "T1082": "Discovery", "T1087": "Discovery",
    "T1087.001": "Discovery", "T1087.002": "Discovery",
    "T1069": "Discovery", "T1069.001": "Discovery",
    "T1069.002": "Discovery",
    "T1046": "Discovery", "T1083": "Discovery",
    "T1057": "Discovery", "T1049": "Discovery",
    "T1016": "Discovery", "T1016.001": "Discovery",
    "T1016.002": "Discovery",
    "T1033": "Discovery", "T1007": "Discovery",
    "T1012": "Discovery", "T1018": "Discovery",
    "T1010": "Discovery", "T1120": "Discovery",
    "T1124": "Discovery", "T1135": "Discovery",
    "T1201": "Discovery", "T1217": "Discovery",
    "T1482": "Discovery", "T1518": "Discovery",
    "T1518.001": "Discovery", "T1614": "Discovery",
    "T1614.001": "Discovery", "T1615": "Discovery",
    "T1652": "Discovery", "T1654": "Discovery",
    # Lateral Movement (TA0008)
    "T1021": "Lateral Movement", "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement", "T1021.003": "Lateral Movement",
    "T1021.006": "Lateral Movement",
    "T1570": "Lateral Movement",
    "T1563": "Lateral Movement", "T1563.002": "Lateral Movement",
    # Collection (TA0009)
    "T1113": "Collection", "T1560": "Collection",
    "T1560.001": "Collection",
    "T1074": "Collection", "T1074.001": "Collection",
    "T1115": "Collection", "T1119": "Collection",
    "T1123": "Collection", "T1125": "Collection",
    "T1005": "Collection", "T1025": "Collection",
    "T1039": "Collection", "T1114": "Collection",
    "T1114.001": "Collection",
    # Command and Control (TA0011)
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1071.004": "Command and Control",
    "T1573": "Command and Control",
    "T1090": "Command and Control", "T1090.001": "Command and Control",
    "T1090.003": "Command and Control",
    "T1095": "Command and Control",
    "T1105": "Command and Control",
    "T1132": "Command and Control", "T1132.001": "Command and Control",
    "T1219": "Command and Control",
    "T1571": "Command and Control",
    "T1572": "Command and Control",
    "T1001": "Command and Control", "T1001.002": "Command and Control",
    # Exfiltration (TA0010)
    "T1048": "Exfiltration", "T1048.002": "Exfiltration",
    "T1048.003": "Exfiltration",
    "T1041": "Exfiltration",
    "T1020": "Exfiltration",
    "T1030": "Exfiltration",
    "T1567": "Exfiltration", "T1567.002": "Exfiltration",
    "T1567.003": "Exfiltration",
    # Impact (TA0040)
    "T1489": "Impact", "T1486": "Impact",
    "T1529": "Impact", "T1490": "Impact",
    "T1485": "Impact", "T1491": "Impact",
    "T1491.001": "Impact", "T1496": "Impact",
    "T1531": "Impact",
}

# Default atomics directory relative to project root
DEFAULT_ATOMICS_DIR = Path(__file__).parent.parent / "atomics"


class AtomicRunner:
    """Discovers, loads, and executes YAML-based atomic tests.

    Works alongside the existing Python module system. The engine
    can invoke the runner to execute atomic tests for techniques
    that don't have (or supplement) Python modules.
    """

    def __init__(
        self,
        atomics_dir: Path | None = None,
        *,
        enabled_techniques: set[str] | None = None,
        disabled_techniques: set[str] | None = None,
    ) -> None:
        self.atomics_dir = atomics_dir or DEFAULT_ATOMICS_DIR
        self.enabled_techniques = enabled_techniques
        self.disabled_techniques = disabled_techniques or set()
        self._techniques: dict[str, AtomicTechnique] = {}
        self._discover_atomics()

    def _discover_atomics(self) -> None:
        """Scan the atomics/ directory for technique YAML files."""
        if not self.atomics_dir.exists():
            log.warning("atomics_dir_not_found", path=str(self.atomics_dir))
            return

        count = 0
        for technique_dir in sorted(self.atomics_dir.iterdir()):
            if not technique_dir.is_dir():
                continue
            # Look for T{NNNN}.yaml or T{NNNN}.{NNN}.yaml
            yaml_file = technique_dir / f"{technique_dir.name}.yaml"
            if not yaml_file.exists():
                continue

            try:
                technique = self._load_technique(yaml_file)
                if technique and technique.technique_id:
                    self._techniques[technique.technique_id] = technique
                    count += 1
            except Exception as e:
                log.warning(
                    "atomic_load_error",
                    file=str(yaml_file),
                    error=str(e),
                )

        log.info("atomics_discovered", count=count)

    def _load_technique(self, yaml_path: Path) -> AtomicTechnique:
        """Load a single technique YAML file."""
        with open(yaml_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return AtomicTechnique(technique_id="")

        technique = AtomicTechnique.from_dict(data)

        # Set tactic from our mapping if not in YAML
        if not technique.tactic:
            technique.tactic = _TECHNIQUE_TACTIC.get(
                technique.technique_id, "Unknown"
            )

        return technique

    @property
    def discovered_techniques(self) -> list[dict[str, Any]]:
        """Return metadata about all discovered atomic techniques."""
        results = []
        for tid, tech in sorted(self._techniques.items()):
            win_tests = tech.windows_tests
            results.append({
                "technique_id": tid,
                "display_name": tech.display_name,
                "tactic": tech.tactic,
                "total_tests": tech.test_count,
                "windows_tests": len(win_tests),
                "elevation_required": any(
                    t.executor.elevation_required for t in win_tests
                ),
            })
        return results

    @property
    def technique_ids(self) -> set[str]:
        """All discovered technique IDs."""
        return set(self._techniques.keys())

    def get_technique(self, technique_id: str) -> AtomicTechnique | None:
        """Get a technique by ID."""
        return self._techniques.get(technique_id)

    def get_tests_for_technique(
        self, technique_id: str
    ) -> list[AtomicTest]:
        """Get all Windows-compatible tests for a technique."""
        tech = self._techniques.get(technique_id)
        if not tech:
            return []
        return tech.windows_tests

    def apply_filters(
        self,
        *,
        tactic: str | None = None,
        technique_id: str | None = None,
    ) -> list[AtomicTechnique]:
        """Filter techniques by tactic or technique ID."""
        techniques = list(self._techniques.values())

        if technique_id:
            techniques = [t for t in techniques if t.technique_id == technique_id]

        if tactic:
            tactic_lower = tactic.lower().replace("_", " ").replace("-", " ")
            techniques = [
                t for t in techniques
                if t.tactic.lower().replace("_", " ").replace("-", " ") == tactic_lower
            ]

        # Apply enabled/disabled filters
        if self.enabled_techniques is not None:
            techniques = [
                t for t in techniques
                if t.technique_id in self.enabled_techniques
            ]

        if self.disabled_techniques:
            techniques = [
                t for t in techniques
                if t.technique_id not in self.disabled_techniques
            ]

        return techniques

    def check_dependencies(
        self,
        test: AtomicTest,
        session: BaseSession,
    ) -> list[str]:
        """Check if all dependencies for a test are met.

        Returns:
            List of unmet dependency descriptions (empty = all met).
        """
        unmet: list[str] = []
        dep_executor = test.dependency_executor_name or ExecutorType.POWERSHELL

        for dep in test.dependencies:
            if not dep.prereq_command:
                continue

            cmd = dep.prereq_command.strip()
            result = self._execute_command(session, cmd, dep_executor)

            if not result.success:
                unmet.append(dep.description)
                log.debug(
                    "dependency_unmet",
                    description=dep.description,
                    stderr=result.stderr[:200],
                )

        return unmet

    def satisfy_dependencies(
        self,
        test: AtomicTest,
        session: BaseSession,
    ) -> list[str]:
        """Attempt to satisfy unmet dependencies.

        Returns:
            List of dependency descriptions that could not be satisfied.
        """
        failures: list[str] = []
        dep_executor = test.dependency_executor_name or ExecutorType.POWERSHELL

        for dep in test.dependencies:
            if not dep.prereq_command:
                continue

            # Check if already met
            check_result = self._execute_command(
                session, dep.prereq_command.strip(), dep_executor
            )
            if check_result.success:
                continue

            # Try to satisfy
            if not dep.get_prereq_command:
                failures.append(dep.description)
                continue

            get_result = self._execute_command(
                session, dep.get_prereq_command.strip(), dep_executor
            )
            if not get_result.success:
                failures.append(dep.description)
                log.warning(
                    "dependency_install_failed",
                    description=dep.description,
                    stderr=get_result.stderr[:200],
                )

        return failures

    def execute_test(
        self,
        test: AtomicTest,
        session: BaseSession,
        *,
        arg_overrides: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> ModuleResult:
        """Execute a single atomic test.

        Args:
            test: The atomic test to execute.
            session: Connected session to the target.
            arg_overrides: Override input argument values.
            timeout: Command timeout in seconds.

        Returns:
            ModuleResult with execution findings.
        """
        technique_id = _extract_technique_id(test.guid, test.name)
        technique = self._find_technique_for_test(test)
        technique_id = technique.technique_id if technique else "UNKNOWN"
        tactic = technique.tactic if technique else "Unknown"
        display_name = technique.display_name if technique else test.name

        result = ModuleResult(
            technique_id=technique_id,
            technique_name=display_name,
            tactic=tactic,
            target_host=session.target.host,
            was_simulated=True,
        )

        log.info(
            "atomic_test_start",
            test_name=test.name,
            guid=test.guid[:12],
            technique_id=technique_id,
        )

        # Manual tests cannot be auto-executed
        if test.executor.name == ExecutorType.MANUAL:
            result.status = ModuleStatus.SKIPPED
            result.error_message = (
                f"Manual test — requires human execution: {test.executor.steps or test.name}"
            )
            result.complete()
            return result

        # Render command
        command = test.render_command(arg_overrides)
        if not command.strip():
            result.status = ModuleStatus.ERROR
            result.error_message = "Empty command after rendering"
            result.complete()
            return result

        # Execute
        try:
            cmd_result = self._execute_command(
                session, command, test.executor.name, timeout
            )

            severity = Severity.INFO
            if cmd_result.success:
                severity = Severity.HIGH  # Technique succeeded = vulnerability
                finding_desc = f"Atomic test succeeded: {test.name}"
            else:
                severity = Severity.INFO
                finding_desc = f"Atomic test blocked/failed: {test.name}"

            finding = Finding(
                technique_id=technique_id,
                technique_name=display_name,
                tactic=tactic,
                severity=severity,
                description=finding_desc,
                evidence=_truncate(cmd_result.stdout, 2000),
                recommendation=test.description,
            )
            result.add_finding(finding)
            result.complete(ModuleStatus.SUCCESS)

        except Exception as e:
            log.error("atomic_test_error", test=test.name, error=str(e))
            result.status = ModuleStatus.ERROR
            result.error_message = str(e)
            result.complete()

        return result

    def cleanup_test(
        self,
        test: AtomicTest,
        session: BaseSession,
        *,
        arg_overrides: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> bool:
        """Run cleanup command for a test.

        Returns:
            True if cleanup succeeded or no cleanup needed.
        """
        cleanup_cmd = test.render_cleanup(arg_overrides)
        if not cleanup_cmd or not cleanup_cmd.strip():
            return True

        log.info("atomic_cleanup", test_name=test.name)

        try:
            result = self._execute_command(
                session, cleanup_cmd, test.executor.name, timeout
            )
            if not result.success:
                log.warning(
                    "atomic_cleanup_failed",
                    test=test.name,
                    stderr=result.stderr[:200],
                )
                return False
            return True
        except Exception as e:
            log.error("atomic_cleanup_error", test=test.name, error=str(e))
            return False

    def run_technique(
        self,
        technique_id: str,
        session: BaseSession,
        *,
        check_deps: bool = True,
        auto_satisfy_deps: bool = False,
        arg_overrides: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> list[ModuleResult]:
        """Run all atomic tests for a technique.

        Args:
            technique_id: MITRE technique ID.
            session: Connected target session.
            check_deps: Check dependencies before running.
            auto_satisfy_deps: Attempt to install missing dependencies.
            arg_overrides: Override input argument values.
            timeout: Per-test command timeout.

        Returns:
            List of ModuleResults, one per test.
        """
        technique = self._techniques.get(technique_id)
        if not technique:
            log.warning("technique_not_found", technique_id=technique_id)
            return []

        results: list[ModuleResult] = []
        tests = technique.windows_tests

        log.info(
            "technique_run_start",
            technique_id=technique_id,
            test_count=len(tests),
        )

        for test in tests:
            # Dependency check
            if check_deps:
                unmet = self.check_dependencies(test, session)
                if unmet:
                    if auto_satisfy_deps:
                        still_unmet = self.satisfy_dependencies(test, session)
                        if still_unmet:
                            skip_result = ModuleResult(
                                technique_id=technique_id,
                                technique_name=technique.display_name,
                                tactic=technique.tactic,
                                status=ModuleStatus.SKIPPED,
                                error_message=f"Unmet dependencies: {', '.join(still_unmet)}",
                                target_host=session.target.host,
                            )
                            skip_result.complete()
                            results.append(skip_result)
                            continue
                    else:
                        skip_result = ModuleResult(
                            technique_id=technique_id,
                            technique_name=technique.display_name,
                            tactic=technique.tactic,
                            status=ModuleStatus.SKIPPED,
                            error_message=f"Unmet dependencies: {', '.join(unmet)}",
                            target_host=session.target.host,
                        )
                        skip_result.complete()
                        results.append(skip_result)
                        continue

            # Execute
            test_result = self.execute_test(
                test, session, arg_overrides=arg_overrides, timeout=timeout
            )
            results.append(test_result)

            # Cleanup
            self.cleanup_test(test, session, arg_overrides=arg_overrides)

        return results

    def _execute_command(
        self,
        session: BaseSession,
        command: str,
        executor: ExecutorType,
        timeout: int = 30,
    ) -> CommandResult:
        """Execute a command via the session using the specified executor."""
        match executor:
            case ExecutorType.POWERSHELL:
                return session.run_powershell(command, timeout=timeout)
            case ExecutorType.COMMAND_PROMPT:
                return session.run_cmd(command, timeout=timeout)
            case _:
                return session.run_cmd(command, timeout=timeout)

    def _find_technique_for_test(
        self, test: AtomicTest
    ) -> AtomicTechnique | None:
        """Find the parent technique for a given test."""
        for technique in self._techniques.values():
            if test in technique.atomic_tests:
                return technique
        return None


def _extract_technique_id(guid: str, name: str) -> str:
    """Best-effort extraction of technique ID from test metadata."""
    match = re.search(r"T\d{4}(?:\.\d{3})?", name)
    return match.group(0) if match else "UNKNOWN"


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len, appending '...' if truncated."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
