"""Tests for atomic test data models."""

from __future__ import annotations

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


class TestInputArgument:
    def test_from_dict_basic(self):
        arg = InputArgument.from_dict("target", {
            "description": "Target host",
            "type": "string",
            "default": "localhost",
        })
        assert arg.name == "target"
        assert arg.description == "Target host"
        assert arg.type == InputType.STRING
        assert arg.default == "localhost"

    def test_from_dict_path_type(self):
        arg = InputArgument.from_dict("output", {
            "type": "path",
            "default": "C:\\Temp\\out.txt",
        })
        assert arg.type == InputType.PATH

    def test_from_dict_no_default(self):
        arg = InputArgument.from_dict("required_arg", {
            "description": "Required",
        })
        assert arg.default is None

    def test_from_dict_unknown_type_defaults_string(self):
        arg = InputArgument.from_dict("x", {"type": "unknown_type"})
        assert arg.type == InputType.STRING


class TestDependency:
    def test_from_dict(self):
        dep = Dependency.from_dict({
            "description": "Tool must exist",
            "prereq_command": "where mimikatz",
            "get_prereq_command": "Invoke-WebRequest ...",
        })
        assert dep.description == "Tool must exist"
        assert dep.prereq_command == "where mimikatz"
        assert dep.get_prereq_command == "Invoke-WebRequest ..."

    def test_from_dict_no_get_command(self):
        dep = Dependency.from_dict({
            "description": "Manual prerequisite",
            "prereq_command": "exit 1",
        })
        assert dep.get_prereq_command is None


class TestExecutor:
    def test_from_dict_powershell(self):
        ex = Executor.from_dict({
            "name": "powershell",
            "command": "Get-Process",
            "cleanup_command": "Stop-Process -Name test",
            "elevation_required": True,
        })
        assert ex.name == ExecutorType.POWERSHELL
        assert ex.command == "Get-Process"
        assert ex.cleanup_command == "Stop-Process -Name test"
        assert ex.elevation_required is True

    def test_from_dict_manual(self):
        ex = Executor.from_dict({
            "name": "manual",
            "steps": "1. Open Task Manager\n2. Find lsass.exe",
        })
        assert ex.name == ExecutorType.MANUAL
        assert ex.steps is not None

    def test_from_dict_unknown_name(self):
        ex = Executor.from_dict({"name": "bash"})
        assert ex.name == ExecutorType.COMMAND_PROMPT  # fallback


class TestAtomicTest:
    @pytest.fixture()
    def sample_test_dict(self) -> dict:
        return {
            "name": "Enumerate Users",
            "auto_generated_guid": "abc123",
            "description": "Test user enum",
            "supported_platforms": ["windows"],
            "input_arguments": {
                "user_name": {
                    "description": "User to check",
                    "type": "string",
                    "default": "Administrator",
                },
            },
            "executor": {
                "name": "command_prompt",
                "command": "net user #{user_name}",
                "cleanup_command": None,
                "elevation_required": False,
            },
        }

    def test_from_dict(self, sample_test_dict):
        test = AtomicTest.from_dict(sample_test_dict)
        assert test.name == "Enumerate Users"
        assert test.guid == "abc123"
        assert "windows" in test.supported_platforms
        assert "user_name" in test.input_arguments
        assert test.executor.name == ExecutorType.COMMAND_PROMPT

    def test_render_command_defaults(self, sample_test_dict):
        test = AtomicTest.from_dict(sample_test_dict)
        cmd = test.render_command()
        assert "net user Administrator" in cmd

    def test_render_command_overrides(self, sample_test_dict):
        test = AtomicTest.from_dict(sample_test_dict)
        cmd = test.render_command({"user_name": "JohnDoe"})
        assert "net user JohnDoe" in cmd

    def test_render_cleanup_none(self, sample_test_dict):
        test = AtomicTest.from_dict(sample_test_dict)
        assert test.render_cleanup() is None

    def test_render_cleanup_with_args(self):
        test = AtomicTest.from_dict({
            "name": "Test",
            "executor": {
                "name": "command_prompt",
                "command": "reg add #{key}",
                "cleanup_command": "reg delete #{key} /f",
            },
            "input_arguments": {
                "key": {"default": "HKCU\\Test"},
            },
        })
        cleanup = test.render_cleanup()
        assert cleanup == "reg delete HKCU\\Test /f"

    def test_from_dict_with_dependencies(self):
        test = AtomicTest.from_dict({
            "name": "With Deps",
            "executor": {"name": "powershell", "command": "Test"},
            "dependencies": [
                {"description": "Module needed", "prereq_command": "exit 0"},
            ],
            "dependency_executor_name": "powershell",
        })
        assert len(test.dependencies) == 1
        assert test.dependency_executor_name == ExecutorType.POWERSHELL


class TestAtomicTechnique:
    def test_from_dict(self):
        tech = AtomicTechnique.from_dict({
            "attack_technique": "T1082",
            "display_name": "System Information Discovery",
            "tactic": "Discovery",
            "atomic_tests": [
                {
                    "name": "systeminfo",
                    "executor": {"name": "command_prompt", "command": "systeminfo"},
                    "supported_platforms": ["windows"],
                },
                {
                    "name": "Linux only",
                    "executor": {"name": "sh", "command": "uname -a"},
                    "supported_platforms": ["linux"],
                },
            ],
        })
        assert tech.technique_id == "T1082"
        assert tech.display_name == "System Information Discovery"
        assert tech.test_count == 2
        assert len(tech.windows_tests) == 1

    def test_empty_technique(self):
        tech = AtomicTechnique.from_dict({
            "attack_technique": "T9999",
            "display_name": "Empty",
        })
        assert tech.test_count == 0
        assert tech.windows_tests == []
