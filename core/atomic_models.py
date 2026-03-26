"""Data models for YAML-based atomic red team tests.

Defines the schema for atomic test definitions that are loaded from
YAML files under the atomics/ directory. Compatible with the Atomic
Red Team test format but adapted for our session-based execution engine.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExecutorType(str, Enum):
    """Supported command executor types."""

    POWERSHELL = "powershell"
    COMMAND_PROMPT = "command_prompt"
    MANUAL = "manual"


class InputType(str, Enum):
    """Supported input argument types."""

    STRING = "string"
    PATH = "path"
    URL = "url"
    INTEGER = "integer"
    FLOAT = "float"


@dataclass
class InputArgument:
    """A parameterized input for an atomic test.

    Attributes:
        name: Argument identifier used in #{name} templating.
        description: Human-readable description.
        type: Data type hint.
        default: Default value (None means required).
    """

    name: str
    description: str = ""
    type: InputType = InputType.STRING
    default: str | None = None

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> InputArgument:
        input_type = InputType.STRING
        raw_type = data.get("type", "string")
        if isinstance(raw_type, str):
            try:
                input_type = InputType(raw_type.lower())
            except ValueError:
                input_type = InputType.STRING

        return cls(
            name=name,
            description=data.get("description", ""),
            type=input_type,
            default=data.get("default"),
        )


@dataclass
class Dependency:
    """A prerequisite that must be satisfied before a test runs.

    Attributes:
        description: What must be true.
        prereq_command: Command that exits 0 if prerequisite is met.
        get_prereq_command: Command to install/satisfy the prerequisite.
    """

    description: str
    prereq_command: str = ""
    get_prereq_command: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Dependency:
        return cls(
            description=data.get("description", ""),
            prereq_command=data.get("prereq_command", ""),
            get_prereq_command=data.get("get_prereq_command"),
        )


@dataclass
class Executor:
    """Defines how an atomic test is executed.

    Attributes:
        name: Executor type (powershell, command_prompt, manual).
        command: The command/script to run.
        cleanup_command: Command to revert changes (optional).
        elevation_required: Whether admin privileges are needed.
        steps: Manual steps (only for manual executor type).
    """

    name: ExecutorType
    command: str = ""
    cleanup_command: str | None = None
    elevation_required: bool = False
    steps: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Executor:
        name_str = data.get("name", "command_prompt")
        try:
            name = ExecutorType(name_str)
        except ValueError:
            name = ExecutorType.COMMAND_PROMPT

        return cls(
            name=name,
            command=data.get("command", ""),
            cleanup_command=data.get("cleanup_command"),
            elevation_required=data.get("elevation_required", False),
            steps=data.get("steps"),
        )


@dataclass
class AtomicTest:
    """A single atomic red team test definition.

    Each technique YAML file can contain multiple atomic tests. Each
    test is a self-contained, executable procedure that demonstrates
    one specific aspect of the ATT&CK technique.

    Attributes:
        name: Short descriptive test name.
        guid: Unique test identifier (UUID hex).
        description: Detailed description of what the test does.
        supported_platforms: OS platforms this test runs on.
        executor: How to execute the test.
        input_arguments: Parameterized inputs with defaults.
        dependencies: Prerequisites that must be met.
        dependency_executor_name: Executor for running prereq commands.
    """

    name: str
    guid: str = field(default_factory=lambda: uuid.uuid4().hex)
    description: str = ""
    supported_platforms: list[str] = field(default_factory=lambda: ["windows"])
    executor: Executor = field(default_factory=Executor)
    input_arguments: dict[str, InputArgument] = field(default_factory=dict)
    dependencies: list[Dependency] = field(default_factory=list)
    dependency_executor_name: ExecutorType | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AtomicTest:
        # Parse input arguments
        input_args: dict[str, InputArgument] = {}
        for arg_name, arg_data in data.get("input_arguments", {}).items():
            input_args[arg_name] = InputArgument.from_dict(arg_name, arg_data)

        # Parse dependencies
        deps = [
            Dependency.from_dict(d)
            for d in data.get("dependencies", [])
        ]

        # Parse dependency executor
        dep_exec = None
        dep_exec_str = data.get("dependency_executor_name")
        if dep_exec_str:
            try:
                dep_exec = ExecutorType(dep_exec_str)
            except ValueError:
                dep_exec = None

        return cls(
            name=data.get("name", "Unnamed Test"),
            guid=data.get("auto_generated_guid", uuid.uuid4().hex),
            description=data.get("description", ""),
            supported_platforms=data.get("supported_platforms", ["windows"]),
            executor=Executor.from_dict(data.get("executor", {})),
            input_arguments=input_args,
            dependencies=deps,
            dependency_executor_name=dep_exec,
        )

    def render_command(self, overrides: dict[str, str] | None = None) -> str:
        """Render the executor command with input argument substitution.

        Replaces #{arg_name} placeholders with actual values.

        Args:
            overrides: Optional dict of arg_name -> value overrides.

        Returns:
            Rendered command string.
        """
        command = self.executor.command
        for arg_name, arg in self.input_arguments.items():
            value = (overrides or {}).get(arg_name) or arg.default or ""
            # Convert to string for substitution
            command = command.replace(f"#{{{arg_name}}}", str(value))
        return command

    def render_cleanup(self, overrides: dict[str, str] | None = None) -> str | None:
        """Render the cleanup command with input argument substitution."""
        if not self.executor.cleanup_command:
            return None
        cleanup = self.executor.cleanup_command
        for arg_name, arg in self.input_arguments.items():
            value = (overrides or {}).get(arg_name) or arg.default or ""
            cleanup = cleanup.replace(f"#{{{arg_name}}}", str(value))
        return cleanup


@dataclass
class AtomicTechnique:
    """A MITRE ATT&CK technique with one or more atomic tests.

    Loaded from a single YAML file (e.g., atomics/T1082/T1082.yaml).

    Attributes:
        technique_id: MITRE ATT&CK technique ID (e.g., T1082).
        display_name: Human-readable technique name.
        tactic: Primary ATT&CK tactic (set from directory or metadata).
        atomic_tests: List of atomic tests for this technique.
    """

    technique_id: str
    display_name: str = ""
    tactic: str = ""
    atomic_tests: list[AtomicTest] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AtomicTechnique:
        tests = [
            AtomicTest.from_dict(t)
            for t in data.get("atomic_tests", [])
        ]
        return cls(
            technique_id=data.get("attack_technique", ""),
            display_name=data.get("display_name", ""),
            tactic=data.get("tactic", ""),
            atomic_tests=tests,
        )

    @property
    def test_count(self) -> int:
        return len(self.atomic_tests)

    @property
    def windows_tests(self) -> list[AtomicTest]:
        """Return only tests that support Windows."""
        return [
            t for t in self.atomic_tests
            if "windows" in t.supported_platforms
        ]
