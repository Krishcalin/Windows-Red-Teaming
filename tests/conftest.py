"""Shared pytest fixtures for the Windows Red Teaming test suite."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.models import (
    ConnectionMethod,
    Finding,
    ModuleResult,
    Severity,
    Target,
)
from core.session import BaseSession, CommandResult


@pytest.fixture()
def sample_target() -> Target:
    """A remote target reachable over WinRM."""
    return Target(host="192.168.1.10", connection=ConnectionMethod.WINRM)


@pytest.fixture()
def local_target() -> Target:
    """A localhost target using local execution."""
    return Target(host="localhost", connection=ConnectionMethod.LOCAL)


@pytest.fixture()
def mock_session() -> MagicMock:
    """A MagicMock spec'd to BaseSession with successful command helpers."""
    session = MagicMock(spec=BaseSession)
    ok = CommandResult(stdout="OK", stderr="", return_code=0, success=True)
    session.run_cmd.return_value = ok
    session.run_powershell.return_value = ok
    return session


@pytest.fixture()
def sample_finding() -> Finding:
    """A representative Finding for unit tests."""
    return Finding(
        technique_id="T1082",
        technique_name="System Info",
        tactic="Discovery",
        severity=Severity.MEDIUM,
        description="Test finding",
    )


@pytest.fixture()
def sample_module_result() -> ModuleResult:
    """A representative ModuleResult for unit tests."""
    return ModuleResult(
        technique_id="T1082",
        technique_name="System Info",
        tactic="Discovery",
    )
