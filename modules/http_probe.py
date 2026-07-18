"""
HTTP probing module.

Uses httpx (the ProjectDiscovery CLI tool) to identify which hosts are
alive, along with status codes, page titles, and detected technologies.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

from config import Config
from utils.helpers import run_command, tool_available, write_json, write_lines

logger = logging.getLogger(__name__)


@dataclass
class HttpResult:
    """
    A single host's HTTP probe result.

    Attributes:
        url: The probed URL.
        status_code: HTTP status code returned.
        title: Page title, if any.
        technologies: List of detected technologies.
        webserver: Reported web server header, if any.
        content_length: Response body length in bytes, if known.
    """

    url: str
    status_code: int | None = None
    title: str = ""
    technologies: list[str] | None = None
    webserver: str = ""
    content_length: int | None = None


def _build_targets(hosts: list[str]) -> list[str]:
    """Expand bare hostnames into both http and https candidate URLs."""
    targets: list[str] = []
    for host in hosts:
        if host.startswith("http://") or host.startswith("https://"):
            targets.append(host)
        else:
            targets.append(f"https://{host}")
            targets.append(f"http://{host}")
    return targets


def probe_hosts(hosts: list[str], report_dir: Path, config: Config) -> list[HttpResult]:
    """Probe a list of hosts for liveness using httpx.

    Args:
        hosts: Hostnames or URLs to probe (typically the output of
            subdomain enumeration).
        report_dir: Directory to write ``alive.txt`` / ``alive.json`` into.
        config: Active :class:`~config.Config`.

    Returns:
        A list of :class:`HttpResult` for hosts that responded, sorted by
        URL. Returns an empty list if httpx is unavailable or no hosts
        respond.
    """
    tool = config.tool_paths.httpx
    if not tool_available(tool):
        logger.warning("httpx not found on PATH, skipping HTTP probing")
        write_lines(report_dir / "alive.txt", [])
        write_json(report_dir / "alive.json", [])
        return []

    if not hosts:
        logger.info("No hosts supplied to probe_hosts")
        write_lines(report_dir / "alive.txt", [])
        write_json(report_dir / "alive.json", [])
        return []

    targets = _build_targets(hosts)
    input_text = "\n".join(targets)

    command = [
        tool,
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-web-server",
        "-content-length",
        "-timeout",
        str(config.timeout),
        "-threads",
        str(min(config.threads, 100)),
        "-H",
        f"User-Agent: {config.user_agent}",
    ]

    import subprocess

    try:
        completed = subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=config.timeout * max(1, len(targets) // 10 + 5),
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("httpx timed out while probing %d target(s)", len(targets))
        write_lines(report_dir / "alive.txt", [])
        write_json(report_dir / "alive.json", [])
        return []
    except FileNotFoundError:
        logger.error("httpx executable could not be started")
        return []

    results: list[HttpResult] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        results.append(
            HttpResult(
                url=record.get("url", ""),
                status_code=record.get("status_code"),
                title=record.get("title", ""),
                technologies=record.get("tech", []) or [],
                webserver=record.get("webserver", ""),
                content_length=record.get("content_length"),
            )
        )

    results.sort(key=lambda r: r.url)

    write_lines(report_dir / "alive.txt", [r.url for r in results])
    write_json(report_dir / "alive.json", [asdict(r) for r in results])

    logger.info("Alive hosts: %d / %d probed", len(results), len(targets))
    return results
