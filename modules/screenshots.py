"""
Screenshot capture module.

Wraps GoWitness to capture screenshots of every live host discovered
during HTTP probing.
"""

from __future__ import annotations

import logging
from pathlib import Path

from config import Config
from utils.helpers import ensure_directory, run_command, tool_available, write_lines

logger = logging.getLogger(__name__)


def capture_screenshots(hosts: list[str], report_dir: Path, config: Config) -> list[str]:
    """Capture screenshots for a list of live hosts using GoWitness.

    Args:
        hosts: Live host URLs (typically from :mod:`modules.http_probe`).
        report_dir: Scan report directory; screenshots are stored under
            ``report_dir / "screenshots"``.
        config: Active :class:`~config.Config`.

    Returns:
        A list of hosts that were successfully submitted for screenshot
        capture. Returns an empty list if GoWitness is unavailable or no
        hosts are supplied.
    """
    tool = config.tool_paths.gowitness
    screenshots_dir = ensure_directory(report_dir / "screenshots")

    if not tool_available(tool):
        logger.warning("gowitness not found on PATH, skipping screenshots")
        return []

    if not hosts:
        logger.info("No hosts supplied to capture_screenshots")
        return []

    targets_file = report_dir / "_screenshot_targets.txt"
    write_lines(targets_file, hosts)

    command = [
        tool,
        "scan",
        "file",
        "-f",
        str(targets_file),
        "--screenshot-path",
        str(screenshots_dir),
        "--timeout",
        str(config.screenshot_timeout),
    ]

    result = run_command(
        command,
        timeout=config.screenshot_timeout * max(1, len(hosts)),
    )

    targets_file.unlink(missing_ok=True)

    if not result.succeeded:
        logger.warning("gowitness reported an issue: %s", result.stderr.strip())
        # gowitness may still have captured some screenshots even on a
        # non-zero exit (e.g. a handful of hosts timing out), so we don't
        # treat this as a hard failure.

    captured = sorted(p.name for p in screenshots_dir.glob("*.png"))
    logger.info("Captured %d screenshot(s) for %d host(s)", len(captured), len(hosts))
    return hosts
