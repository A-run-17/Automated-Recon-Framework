"""
Logging utilities for the Recon Framework.

Provides a colored console logger alongside a plain-text file logger so
that scan activity is both easy to read interactively and preserved for
later analysis.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path


class _ColorFormatter(logging.Formatter):
    """Formatter that adds ANSI colors to console log records.

    Colors are only applied to the console handler. The file handler uses
    a plain formatter so log files remain free of escape codes.
    """

    _RESET = "\x1b[0m"
    _COLORS = {
        logging.DEBUG   : "\x1b[36m",     # cyan
        logging.INFO    : "\x1b[32m",     # green
        logging.WARNING : "\x1b[33m",     # yellow
        logging.ERROR   : "\x1b[31m",     # red
        logging.CRITICAL: "\x1b[41m",     # red background
    }

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        color = self._COLORS.get(record.levelno, self._RESET)
        message = super().format(record)
        return f"{color}{message}{self._RESET}"


def setup_logger(
    name: str,
    log_file: Path | None = None,
    level: str = "INFO",
) -> logging.Logger:
    """Create or retrieve a configured logger.

    Args:
        name: Logger name, typically the module's ``__name__``.
        log_file: Optional path to a file where plain-text logs are
            appended. Parent directories are created if needed.
        level: Logging level name (e.g. ``"DEBUG"``, ``"INFO"``).

    Returns:
        A configured :class:`logging.Logger` instance.
    """
    logger = logging.getLogger(name)

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Avoid attaching duplicate handlers if the logger was already configured
    # (e.g. when setup_logger is called multiple times for the same name).
    if logger.handlers:
        return logger

    logger.propagate = False

    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(_ColorFormatter())
    console_handler.setLevel(numeric_level)
    logger.addHandler(console_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(numeric_level)
        logger.addHandler(file_handler)

    return logger
