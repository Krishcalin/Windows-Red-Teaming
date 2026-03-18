"""Unit tests for core.session classes and factory."""

from __future__ import annotations

import pytest

from core.models import ConnectionMethod, Target
from core.session import (
    CommandResult,
    LocalSession,
    WinRMSession,
    create_session,
)


def test_local_session_connect_disconnect(local_target: Target):
    """LocalSession transitions connected state on connect/disconnect."""
    session = LocalSession(local_target)
    assert session.is_connected is False

    session.connect()
    assert session.is_connected is True

    session.disconnect()
    assert session.is_connected is False


def test_command_result_bool():
    """CommandResult is truthy when success=True, falsy otherwise."""
    ok = CommandResult(stdout="data", success=True)
    fail = CommandResult(stderr="err", return_code=1, success=False)
    assert bool(ok) is True
    assert bool(fail) is False


def test_create_session_local(local_target: Target):
    """Factory returns a LocalSession for LOCAL connection method."""
    session = create_session(local_target)
    assert isinstance(session, LocalSession)


def test_create_session_winrm(sample_target: Target):
    """Factory returns a WinRMSession for WINRM connection method."""
    session = create_session(sample_target)
    assert isinstance(session, WinRMSession)


def test_create_session_smb_not_implemented():
    """Factory raises ValueError for SMB (not yet implemented)."""
    target = Target(host="10.0.0.1", connection=ConnectionMethod.SMB)
    with pytest.raises(ValueError, match="SMB"):
        create_session(target)
