"""Target session management for the Windows Red Teaming tool.

Provides a unified interface for executing commands and queries on targets
via Local, WinRM, SMB, or WMI connections.
"""

from __future__ import annotations

import platform
import subprocess
from abc import ABC, abstractmethod
from typing import Any

import structlog

from core.models import ConnectionMethod, OSType, Target

log = structlog.get_logger(component="session")


class CommandResult:
    """Result from executing a command on a target."""

    def __init__(
        self,
        stdout: str = "",
        stderr: str = "",
        return_code: int = 0,
        success: bool = True,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code
        self.success = success

    def __bool__(self) -> bool:
        return self.success

    def __repr__(self) -> str:
        status = "OK" if self.success else f"FAIL(rc={self.return_code})"
        return f"CommandResult({status}, stdout={len(self.stdout)} chars)"


class BaseSession(ABC):
    """Abstract session interface for target connections."""

    def __init__(self, target: Target) -> None:
        self.target = target
        self._connected = False
        self._os_type: OSType | None = target.os_type

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def os_type(self) -> OSType | None:
        return self._os_type

    @abstractmethod
    def connect(self) -> None:
        """Establish connection to the target."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close the connection."""

    @abstractmethod
    def run_cmd(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute a Windows command (cmd.exe) on the target."""

    @abstractmethod
    def run_powershell(self, script: str, timeout: int = 30) -> CommandResult:
        """Execute a PowerShell script on the target."""

    @abstractmethod
    def read_registry(
        self, hive: str, key: str, value_name: str
    ) -> Any:
        """Read a registry value from the target."""

    @abstractmethod
    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the target."""

    @abstractmethod
    def read_file(self, path: str) -> str:
        """Read file contents from the target."""

    def detect_os(self) -> OSType | None:
        """Detect the target OS version."""
        result = self.run_powershell(
            "(Get-CimInstance Win32_OperatingSystem).Caption"
        )
        if not result.success:
            return None

        caption = result.stdout.strip().lower()
        if "server 2022" in caption:
            self._os_type = OSType.SERVER_2022
        elif "server 2019" in caption:
            self._os_type = OSType.SERVER_2019
        elif "windows 11" in caption:
            self._os_type = OSType.WIN11
        elif "windows 10" in caption:
            self._os_type = OSType.WIN10
        else:
            log.warning("unknown_os", caption=caption)
            self._os_type = None

        return self._os_type

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False


class LocalSession(BaseSession):
    """Session for scanning the local Windows machine.

    Uses subprocess for command execution and winreg/PowerShell
    for registry access.
    """

    def connect(self) -> None:
        if platform.system() != "Windows":
            log.warning("local_session_non_windows",
                        system=platform.system())
        self._connected = True
        log.info("local_session_connected", host="localhost")

    def disconnect(self) -> None:
        self._connected = False
        log.info("local_session_disconnected")

    def run_cmd(self, command: str, timeout: int = 30) -> CommandResult:
        log.debug("run_cmd", command=command)
        try:
            proc = subprocess.run(
                ["cmd.exe", "/c", command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return CommandResult(
                stdout=proc.stdout,
                stderr=proc.stderr,
                return_code=proc.returncode,
                success=proc.returncode == 0,
            )
        except subprocess.TimeoutExpired:
            log.error("cmd_timeout", command=command, timeout=timeout)
            return CommandResult(
                stderr=f"Command timed out after {timeout}s",
                return_code=-1,
                success=False,
            )
        except OSError as e:
            log.error("cmd_error", command=command, error=str(e))
            return CommandResult(
                stderr=str(e), return_code=-1, success=False
            )

    def run_powershell(self, script: str, timeout: int = 30) -> CommandResult:
        log.debug("run_powershell", script=script[:200])
        try:
            proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", script,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return CommandResult(
                stdout=proc.stdout,
                stderr=proc.stderr,
                return_code=proc.returncode,
                success=proc.returncode == 0,
            )
        except subprocess.TimeoutExpired:
            log.error("powershell_timeout", timeout=timeout)
            return CommandResult(
                stderr=f"PowerShell timed out after {timeout}s",
                return_code=-1,
                success=False,
            )
        except OSError as e:
            log.error("powershell_error", error=str(e))
            return CommandResult(
                stderr=str(e), return_code=-1, success=False
            )

    def read_registry(
        self, hive: str, key: str, value_name: str
    ) -> Any:
        """Read a registry value using PowerShell.

        Args:
            hive: Registry hive (e.g. HKLM, HKCU).
            key: Registry key path.
            value_name: Name of the value to read.

        Returns:
            The registry value, or None if not found.
        """
        ps_hive = hive.replace("HKLM", "HKLM:").replace("HKCU", "HKCU:")
        if not ps_hive.endswith(":"):
            ps_hive += ":"
        script = (
            f"(Get-ItemProperty -Path '{ps_hive}\\{key}' "
            f"-Name '{value_name}' -ErrorAction SilentlyContinue)"
            f".'{value_name}'"
        )
        result = self.run_powershell(script)
        if result.success and result.stdout.strip():
            return result.stdout.strip()
        return None

    def file_exists(self, path: str) -> bool:
        result = self.run_powershell(f"Test-Path '{path}'")
        return result.success and result.stdout.strip().lower() == "true"

    def read_file(self, path: str) -> str:
        result = self.run_powershell(
            f"Get-Content -Path '{path}' -Raw -ErrorAction Stop"
        )
        if result.success:
            return result.stdout
        return ""


class WinRMSession(BaseSession):
    """Session for remote scanning via WinRM/PowerShell Remoting.

    Uses pypsrp for WinRM connections and PowerShell execution.
    """

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self._client = None

    def connect(self) -> None:
        try:
            from pypsrp.client import Client

            self._client = Client(
                self.target.host,
                port=self.target.effective_port,
                username=self.target.username or None,
                password=self.target.password or None,
                ssl=self.target.ssl,
                auth="kerberos" if self.target.use_kerberos else "negotiate",
                cert_validation=False,
            )
            # Test connection with a simple command
            self._client.execute_ps("$true")
            self._connected = True
            log.info(
                "winrm_connected",
                host=self.target.host,
                port=self.target.effective_port,
            )
        except ImportError:
            log.error("pypsrp_not_installed")
            raise RuntimeError(
                "pypsrp is required for WinRM connections. "
                "Install with: pip install pypsrp"
            )
        except Exception as e:
            log.error("winrm_connect_failed", host=self.target.host, error=str(e))
            raise ConnectionError(
                f"Failed to connect to {self.target.host} via WinRM: {e}"
            )

    def disconnect(self) -> None:
        self._client = None
        self._connected = False
        log.info("winrm_disconnected", host=self.target.host)

    def _ensure_connected(self) -> None:
        if not self._connected or self._client is None:
            raise RuntimeError("WinRM session not connected")

    def run_cmd(self, command: str, timeout: int = 30) -> CommandResult:
        self._ensure_connected()
        log.debug("winrm_cmd", command=command)
        try:
            stdout, stderr, rc = self._client.execute_cmd(command)
            return CommandResult(
                stdout=stdout,
                stderr=stderr,
                return_code=rc,
                success=rc == 0,
            )
        except Exception as e:
            log.error("winrm_cmd_error", error=str(e))
            return CommandResult(
                stderr=str(e), return_code=-1, success=False
            )

    def run_powershell(self, script: str, timeout: int = 30) -> CommandResult:
        self._ensure_connected()
        log.debug("winrm_powershell", script=script[:200])
        try:
            stdout, streams, had_errors = self._client.execute_ps(script)
            stderr = ""
            if had_errors and streams and streams.error:
                stderr = "\n".join(str(e) for e in streams.error)
            return CommandResult(
                stdout=stdout,
                stderr=stderr,
                return_code=1 if had_errors else 0,
                success=not had_errors,
            )
        except Exception as e:
            log.error("winrm_ps_error", error=str(e))
            return CommandResult(
                stderr=str(e), return_code=-1, success=False
            )

    def read_registry(
        self, hive: str, key: str, value_name: str
    ) -> Any:
        ps_hive = hive.replace("HKLM", "HKLM:").replace("HKCU", "HKCU:")
        if not ps_hive.endswith(":"):
            ps_hive += ":"
        script = (
            f"(Get-ItemProperty -Path '{ps_hive}\\{key}' "
            f"-Name '{value_name}' -ErrorAction SilentlyContinue)"
            f".'{value_name}'"
        )
        result = self.run_powershell(script)
        if result.success and result.stdout.strip():
            return result.stdout.strip()
        return None

    def file_exists(self, path: str) -> bool:
        result = self.run_powershell(f"Test-Path '{path}'")
        return result.success and result.stdout.strip().lower() == "true"

    def read_file(self, path: str) -> str:
        result = self.run_powershell(
            f"Get-Content -Path '{path}' -Raw -ErrorAction Stop"
        )
        return result.stdout if result.success else ""


def create_session(target: Target) -> BaseSession:
    """Factory function to create the appropriate session type.

    Args:
        target: Target configuration.

    Returns:
        A session instance matching the target's connection method.

    Raises:
        ValueError: If the connection method is not supported.
    """
    match target.connection:
        case ConnectionMethod.LOCAL:
            return LocalSession(target)
        case ConnectionMethod.WINRM:
            return WinRMSession(target)
        case ConnectionMethod.SMB:
            raise ValueError(
                "SMB session not yet implemented — planned for Phase 2"
            )
        case ConnectionMethod.WMI:
            raise ValueError(
                "WMI session not yet implemented — planned for Phase 2"
            )
        case _:
            raise ValueError(f"Unknown connection method: {target.connection}")
