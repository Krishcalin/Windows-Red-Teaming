"""Unit tests for core.engine.ScanEngine."""

from __future__ import annotations

from unittest.mock import patch

from core.engine import ScanEngine


def test_engine_discovers_no_modules():
    """When modules/ has no technique files, engine discovers 0 modules."""
    with patch("pkgutil.walk_packages", return_value=[]):
        engine = ScanEngine()
        assert len(engine._modules) == 0


def test_engine_authorization_banner_exists():
    """The engine class carries a non-empty authorization banner."""
    assert hasattr(ScanEngine, "AUTHORIZATION_BANNER")
    assert "authorized" in ScanEngine.AUTHORIZATION_BANNER.lower()
    assert len(ScanEngine.AUTHORIZATION_BANNER) > 0
