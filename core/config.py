"""Configuration loader for the Windows Red Teaming tool.

Loads settings from YAML files and scan profiles, merging them
into a unified configuration used by the engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.models import ConnectionMethod, Target

log = structlog.get_logger(component="config")

DEFAULT_CONFIG_DIR = Path("config")
DEFAULT_SETTINGS_FILE = DEFAULT_CONFIG_DIR / "settings.yaml"
DEFAULT_TECHNIQUES_FILE = DEFAULT_CONFIG_DIR / "techniques.yaml"
DEFAULT_PROFILES_DIR = DEFAULT_CONFIG_DIR / "profiles"


@dataclass
class ScanConfig:
    """Merged scan configuration from settings + profile + CLI overrides."""

    targets: list[Target] = field(default_factory=list)
    profile: str = "full"
    simulate: bool = False
    tactic_filter: str | None = None
    technique_filter: str | None = None
    enabled_techniques: set[str] | None = None
    disabled_techniques: set[str] = field(default_factory=set)
    report_dir: str = "reports"
    evidence_dir: str = "evidence"
    output_formats: list[str] = field(default_factory=lambda: ["html", "json"])
    attack_layer: bool = True
    verbose: bool = False
    log_file: str | None = None
    json_output: bool = False
    require_authorization: bool = True


def load_settings(settings_path: Path | None = None) -> dict[str, Any]:
    """Load the global settings.yaml file.

    Args:
        settings_path: Path to settings file. Defaults to config/settings.yaml.

    Returns:
        Parsed settings dictionary, or empty dict if file not found.
    """
    path = settings_path or DEFAULT_SETTINGS_FILE
    if not path.exists():
        log.warning("settings_not_found", path=str(path))
        return {}

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    log.info("settings_loaded", path=str(path))
    return data


def load_techniques(techniques_path: Path | None = None) -> dict[str, bool]:
    """Load the technique enable/disable configuration.

    Args:
        techniques_path: Path to techniques.yaml.

    Returns:
        Dict mapping technique IDs to enabled/disabled booleans.
    """
    path = techniques_path or DEFAULT_TECHNIQUES_FILE
    if not path.exists():
        log.debug("techniques_config_not_found", path=str(path))
        return {}

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return data.get("techniques", {})


def load_profile(profile_name: str) -> dict[str, Any]:
    """Load a scan profile by name.

    Args:
        profile_name: Profile name (e.g. "quick", "full", "stealth").

    Returns:
        Parsed profile dictionary.

    Raises:
        FileNotFoundError: If the profile file doesn't exist.
    """
    profile_path = DEFAULT_PROFILES_DIR / f"{profile_name}.yaml"
    if not profile_path.exists():
        raise FileNotFoundError(
            f"Scan profile not found: {profile_path}"
        )

    with open(profile_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    log.info("profile_loaded", name=profile_name, path=str(profile_path))
    return data


def _parse_target(raw: dict[str, Any]) -> Target:
    """Parse a target dictionary from settings into a Target object."""
    connection_str = raw.get("connection", "local").lower()
    try:
        connection = ConnectionMethod(connection_str)
    except ValueError:
        log.warning("unknown_connection_method", value=connection_str)
        connection = ConnectionMethod.LOCAL

    return Target(
        host=raw["host"],
        connection=connection,
        port=raw.get("port"),
        domain=raw.get("domain", ""),
        username=raw.get("username", ""),
        password=raw.get("password", ""),
        use_kerberos=raw.get("use_kerberos", False),
        ssl=raw.get("ssl", True),
    )


def build_config(
    *,
    target_host: str | None = None,
    profile_name: str = "full",
    simulate: bool = False,
    tactic: str | None = None,
    technique: str | None = None,
    verbose: bool = False,
    settings_path: Path | None = None,
) -> ScanConfig:
    """Build a merged ScanConfig from all sources.

    Priority: CLI args > profile > settings.yaml > defaults.

    Args:
        target_host: Target from CLI (overrides settings).
        profile_name: Profile to load.
        simulate: Enable active simulation.
        tactic: Filter to a single tactic.
        technique: Filter to a single technique.
        verbose: Enable verbose logging.
        settings_path: Override settings file path.

    Returns:
        Fully resolved ScanConfig.
    """
    settings = load_settings(settings_path)
    techniques_config = load_techniques()

    try:
        profile = load_profile(profile_name)
    except FileNotFoundError:
        log.warning("profile_not_found_using_defaults", name=profile_name)
        profile = {}

    # Build targets list
    targets: list[Target] = []
    if target_host:
        if target_host in ("localhost", "127.0.0.1", "::1"):
            targets.append(Target(host=target_host, connection=ConnectionMethod.LOCAL))
        else:
            # Check if target is in settings for connection details
            settings_targets = settings.get("targets", [])
            matched = False
            for raw_target in settings_targets:
                if raw_target.get("host") == target_host:
                    targets.append(_parse_target(raw_target))
                    matched = True
                    break
            if not matched:
                # Default to WinRM for remote targets
                targets.append(
                    Target(host=target_host, connection=ConnectionMethod.WINRM)
                )
    else:
        for raw_target in settings.get("targets", []):
            targets.append(_parse_target(raw_target))

    # Resolve enabled/disabled techniques
    enabled: set[str] | None = None
    disabled: set[str] = set()

    # From techniques.yaml
    for tid, is_enabled in techniques_config.items():
        if not is_enabled:
            disabled.add(str(tid))

    # From profile (if profile specifies a technique list, use it)
    profile_techniques = profile.get("techniques", [])
    if profile_techniques:
        enabled = {str(t) for t in profile_techniques}

    # Single technique override
    technique_filter = technique
    if technique:
        enabled = {technique}

    # Output settings
    output = settings.get("output", {})

    config = ScanConfig(
        targets=targets,
        profile=profile.get("name", profile_name),
        simulate=simulate or profile.get("simulate", False),
        tactic_filter=tactic,
        technique_filter=technique_filter,
        enabled_techniques=enabled,
        disabled_techniques=disabled,
        report_dir=output.get("report_dir", "reports"),
        evidence_dir=output.get("evidence_dir", "evidence"),
        output_formats=output.get("formats", ["html", "json"]),
        attack_layer=output.get("attack_layer", True),
        verbose=verbose,
        log_file=settings.get("logging", {}).get("log_file"),
        json_output=settings.get("logging", {}).get("json_output", False),
        require_authorization=settings.get("safety", {}).get(
            "require_authorization_banner", True
        ),
    )

    log.info(
        "config_built",
        profile=config.profile,
        targets=len(config.targets),
        simulate=config.simulate,
    )

    return config
