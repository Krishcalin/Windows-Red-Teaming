"""Tests for the atomic test runner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.atomic_models import (
    AtomicTechnique,
    AtomicTest,
    Dependency,
    Executor,
    ExecutorType,
    InputArgument,
    InputType,
)
from core.atomic_runner import AtomicRunner
from core.models import ModuleStatus, Severity
from core.session import BaseSession, CommandResult


@pytest.fixture()
def atomics_dir(tmp_path: Path) -> Path:
    """Create a temporary atomics directory with a sample technique."""
    tech_dir = tmp_path / "T1082"
    tech_dir.mkdir()
    yaml_content = """\
attack_technique: T1082
display_name: "System Information Discovery"
tactic: Discovery
atomic_tests:
  - name: "systeminfo command"
    auto_generated_guid: abcd1234
    description: "Runs systeminfo"
    supported_platforms:
      - windows
    executor:
      name: command_prompt
      command: |
        systeminfo
      elevation_required: false

  - name: "hostname command"
    auto_generated_guid: efgh5678
    description: "Runs hostname"
    supported_platforms:
      - windows
    input_arguments:
      verbose:
        description: "Verbose flag"
        type: string
        default: "/v"
    executor:
      name: command_prompt
      command: |
        hostname #{verbose}
      cleanup_command: |
        echo cleanup done
      elevation_required: false

  - name: "Linux only test"
    auto_generated_guid: ijkl9012
    description: "uname"
    supported_platforms:
      - linux
    executor:
      name: sh
      command: uname -a
"""
    (tech_dir / "T1082.yaml").write_text(yaml_content, encoding="utf-8")

    # Add another technique
    tech_dir2 = tmp_path / "T1059.001"
    tech_dir2.mkdir()
    yaml2 = """\
attack_technique: T1059.001
display_name: "PowerShell"
tactic: Execution
atomic_tests:
  - name: "Get-Process"
    auto_generated_guid: mnop3456
    description: "Lists processes"
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: Get-Process
      elevation_required: false
"""
    (tech_dir2 / "T1059.001.yaml").write_text(yaml2, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def runner(atomics_dir: Path) -> AtomicRunner:
    return AtomicRunner(atomics_dir=atomics_dir)


@pytest.fixture()
def mock_session() -> MagicMock:
    from core.models import ConnectionMethod, Target

    session = MagicMock(spec=BaseSession)
    ok = CommandResult(stdout="test output", stderr="", return_code=0, success=True)
    session.run_cmd.return_value = ok
    session.run_powershell.return_value = ok
    session.target = Target(host="localhost", connection=ConnectionMethod.LOCAL)
    return session


class TestAtomicRunnerDiscovery:
    def test_discovers_techniques(self, runner: AtomicRunner):
        assert len(runner.technique_ids) == 2
        assert "T1082" in runner.technique_ids
        assert "T1059.001" in runner.technique_ids

    def test_discovered_techniques_metadata(self, runner: AtomicRunner):
        techs = runner.discovered_techniques
        assert len(techs) == 2
        t1082 = next(t for t in techs if t["technique_id"] == "T1082")
        assert t1082["display_name"] == "System Information Discovery"
        assert t1082["tactic"] == "Discovery"
        assert t1082["windows_tests"] == 2  # Excludes Linux-only test

    def test_get_technique(self, runner: AtomicRunner):
        tech = runner.get_technique("T1082")
        assert tech is not None
        assert tech.technique_id == "T1082"
        assert tech.test_count == 3  # Including Linux test

    def test_get_technique_not_found(self, runner: AtomicRunner):
        assert runner.get_technique("T9999") is None

    def test_get_windows_tests(self, runner: AtomicRunner):
        tests = runner.get_tests_for_technique("T1082")
        assert len(tests) == 2  # Excludes Linux-only
        assert all("windows" in t.supported_platforms for t in tests)


class TestAtomicRunnerFilters:
    def test_filter_by_technique(self, runner: AtomicRunner):
        results = runner.apply_filters(technique_id="T1082")
        assert len(results) == 1
        assert results[0].technique_id == "T1082"

    def test_filter_by_tactic(self, runner: AtomicRunner):
        results = runner.apply_filters(tactic="Discovery")
        assert len(results) == 1
        assert results[0].technique_id == "T1082"

    def test_filter_by_tactic_execution(self, runner: AtomicRunner):
        results = runner.apply_filters(tactic="Execution")
        assert len(results) == 1
        assert results[0].technique_id == "T1059.001"

    def test_filter_no_match(self, runner: AtomicRunner):
        results = runner.apply_filters(tactic="Impact")
        assert len(results) == 0

    def test_no_atomics_dir(self, tmp_path: Path):
        runner = AtomicRunner(atomics_dir=tmp_path / "nonexistent")
        assert len(runner.technique_ids) == 0


class TestAtomicRunnerExecution:
    def test_execute_test(self, runner: AtomicRunner, mock_session: MagicMock):
        tests = runner.get_tests_for_technique("T1082")
        result = runner.execute_test(tests[0], mock_session)
        assert result.status == ModuleStatus.SUCCESS
        assert result.was_simulated is True
        assert len(result.findings) == 1
        mock_session.run_cmd.assert_called_once()

    def test_execute_powershell_test(
        self, runner: AtomicRunner, mock_session: MagicMock
    ):
        tests = runner.get_tests_for_technique("T1059.001")
        result = runner.execute_test(tests[0], mock_session)
        assert result.status == ModuleStatus.SUCCESS
        mock_session.run_powershell.assert_called_once()

    def test_execute_test_success_means_high(
        self, runner: AtomicRunner, mock_session: MagicMock
    ):
        tests = runner.get_tests_for_technique("T1082")
        result = runner.execute_test(tests[0], mock_session)
        # Successful technique execution = HIGH severity finding
        assert result.findings[0].severity == Severity.HIGH

    def test_execute_test_failure_means_info(
        self, runner: AtomicRunner, mock_session: MagicMock
    ):
        mock_session.run_cmd.return_value = CommandResult(
            stdout="", stderr="Access denied", return_code=1, success=False
        )
        tests = runner.get_tests_for_technique("T1082")
        result = runner.execute_test(tests[0], mock_session)
        assert result.findings[0].severity == Severity.INFO

    def test_cleanup_test(self, runner: AtomicRunner, mock_session: MagicMock):
        tests = runner.get_tests_for_technique("T1082")
        # Test with cleanup command (second test)
        success = runner.cleanup_test(tests[1], mock_session)
        assert success is True
        mock_session.run_cmd.assert_called()

    def test_cleanup_no_command(self, runner: AtomicRunner, mock_session: MagicMock):
        tests = runner.get_tests_for_technique("T1082")
        # First test has no cleanup
        success = runner.cleanup_test(tests[0], mock_session)
        assert success is True

    def test_run_technique(self, runner: AtomicRunner, mock_session: MagicMock):
        results = runner.run_technique(
            "T1082", mock_session, check_deps=False
        )
        assert len(results) == 2  # 2 Windows tests
        assert all(r.status == ModuleStatus.SUCCESS for r in results)


class TestAtomicRunnerDependencies:
    def test_check_dependencies_met(
        self, runner: AtomicRunner, mock_session: MagicMock
    ):
        test = AtomicTest(
            name="Dep Test",
            executor=Executor(name=ExecutorType.POWERSHELL, command="Test"),
            dependencies=[
                Dependency(
                    description="Tool exists",
                    prereq_command="exit 0",
                ),
            ],
        )
        unmet = runner.check_dependencies(test, mock_session)
        assert len(unmet) == 0

    def test_check_dependencies_unmet(
        self, runner: AtomicRunner, mock_session: MagicMock
    ):
        mock_session.run_powershell.return_value = CommandResult(
            stdout="", stderr="not found", return_code=1, success=False
        )
        test = AtomicTest(
            name="Dep Test",
            executor=Executor(name=ExecutorType.POWERSHELL, command="Test"),
            dependencies=[
                Dependency(
                    description="Missing tool",
                    prereq_command="where nonexistent",
                ),
            ],
        )
        unmet = runner.check_dependencies(test, mock_session)
        assert len(unmet) == 1
        assert "Missing tool" in unmet

    def test_manual_test_skipped(
        self, runner: AtomicRunner, mock_session: MagicMock
    ):
        test = AtomicTest(
            name="Manual",
            executor=Executor(
                name=ExecutorType.MANUAL,
                steps="Do this manually",
            ),
        )
        result = runner.execute_test(test, mock_session)
        assert result.status == ModuleStatus.SKIPPED
