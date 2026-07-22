"""Common utility helpers shared across recon modules.

Includes directory management, file writing, JSON serialization, time
formatting, and safe subprocess execution.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)


def ensure_directory(path: Path) -> Path:
    """Create a directory (and parents) if it does not already exist.

    Args:
        path: Directory path to create.

    Returns:
        The same path, for convenient chaining.
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_lines(path: Path, lines: Iterable[str]) -> None:
    """Write an iterable of strings to a text file, one per line.

    Args:
        path: Destination file path. Parent directories are created.
        lines: Iterable of strings to write. Order is preserved and
            duplicate blank entries are skipped.
    """
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        for line in lines:
            stripped = line.strip()
            if stripped:
                handle.write(stripped + "\n")


def write_json(path: Path, data: Any) -> None:
    """Serialize ``data`` to JSON and write it to ``path``.

    Dataclass instances (including nested ones inside lists/dicts) are
    converted to plain dictionaries before serialization.

    Args:
        path: Destination file path. Parent directories are created.
        data: JSON-serializable data, or a dataclass instance.
    """
    ensure_directory(path.parent)

    def _default(obj: Any) -> Any:
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, set):
            return sorted(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    payload = asdict(data) if is_dataclass(data) and not isinstance(data, type) else data
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=_default, sort_keys=False)


def read_json(path: Path) -> Any:
    """Read and parse a JSON file.

    Args:
        path: Path to the JSON file.

    Returns:
        The parsed JSON content.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def format_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string.

    Args:
        seconds: Duration in seconds.

    Returns:
        A string like ``"2m 14s"`` or ``"45s"``.
    """
    total_seconds = int(round(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def timestamp() -> str:
    """Return the current UTC time formatted for scan IDs and logs.

    Returns:
        A timestamp string in ``YYYYMMDD-HHMMSS`` format.
    """
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


class CommandResult:
    """Result of an executed shell command.

    Attributes:
        command: The command that was executed.
        returncode: The process exit code.
        stdout: Captured standard output.
        stderr: Captured standard error.
        succeeded: Whether the command completed successfully.
    """

    def __init__(self, command: list[str], returncode: int, stdout: str, stderr: str) -> None:
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.succeeded = returncode == 0

    def __repr__(self) -> str:  # pragma: no cover - debug convenience
        return (
            f"CommandResult(command={self.command!r}, returncode={self.returncode}, "
            f"succeeded={self.succeeded})"
        )


def run_command(
    command: list[str],
    timeout: int = 60,
    cwd: Path | None = None,
) -> CommandResult:
    """Execute an external command safely and capture its output.

    The command is executed without a shell to avoid injection risks.
    Failures (missing binary, timeout, non-zero exit) are captured in the
    returned :class:`CommandResult` rather than raised, so callers can
    decide how to react.

    Args:
        command: The command and its arguments as a list, e.g.
            ``["nmap", "-sV", "example.com"]``.
        timeout: Maximum time in seconds to allow the command to run.
        cwd: Optional working directory for the command.

    Returns:
        A :class:`CommandResult` describing the outcome.
    """
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
        return CommandResult(command, completed.returncode, completed.stdout, completed.stderr)
    except FileNotFoundError:
        logger.error("Command not found: %s", command[0])
        return CommandResult(command, 127, "", f"Command not found: {command[0]}")
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ss: %s", timeout, " ".join(command))
        return CommandResult(command, 124, "", f"Timed out after {timeout}s")
    except OSError as exc:
        logger.error("Failed to execute command %s: %s", command, exc)
        return CommandResult(command, 1, "", str(exc))


def tool_available(tool_name: str) -> bool:
    """Check whether an external tool is available on the system PATH.

    Args:
        tool_name: Name of the executable, e.g. ``"nmap"``.

    Returns:
        ``True`` if the tool can be located, ``False`` otherwise.
    """
    import shutil

    return shutil.which(tool_name) is not None
