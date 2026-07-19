"""
Subdomain enumeration module.

Runs Subfinder, Amass, and Assetfinder (whichever are installed) against
a target domain, merges and deduplicates their results, and writes
``subdomains.txt`` into the scan's report directory.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from config import Config
from utils.helpers import run_command, tool_available, write_lines

logger = logging.getLogger(__name__)


def _run_subfinder(domain: str, config: Config) -> set[str]:
    """Run Subfinder against ``domain`` and return discovered subdomains."""
    tool = config.tool_paths.subfinder
    if not tool_available(tool):
        logger.warning("subfinder not found on PATH, skipping")
        return set()

    result = run_command([tool, "-d", domain, "-silent"], timeout=config.timeout * 6)
    if not result.succeeded:
        logger.warning("subfinder failed for %s: %s", domain, result.stderr.strip())
        return set()

    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _run_amass(domain: str, config: Config) -> set[str]:
    """Run Amass passive enumeration against ``domain``."""
    tool = config.tool_paths.amass
    if not tool_available(tool):
        logger.warning("amass not found on PATH, skipping")
        return set()

    result = run_command(
        [tool, "enum", "-passive", "-d", domain, "-silent"],
        timeout=config.timeout * 8,
    )
    if not result.succeeded:
        logger.warning("amass failed for %s: %s", domain, result.stderr.strip())
        return set()

    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _run_assetfinder(domain: str, config: Config) -> set[str]:
    """Run Assetfinder against ``domain``."""
    tool = config.tool_paths.assetfinder
    if not tool_available(tool):
        logger.warning("assetfinder not found on PATH, skipping")
        return set()

    result = run_command([tool, "--subs-only", domain], timeout=config.timeout * 4)
    if not result.succeeded:
        logger.warning("assetfinder failed for %s: %s", domain, result.stderr.strip())
        return set()

    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def enumerate_subdomains(domain: str, report_dir: Path, config: Config) -> list[str]:
    """
    Enumerate subdomains for ``domain`` using all available tools.

    Runs each available enumeration tool concurrently, merges and
    deduplicates the results (always including the base domain itself),
    and persists them to ``subdomains.txt``.

    Args:
        domain: The target domain to enumerate.
        report_dir: Directory to write ``subdomains.txt`` into.
        config: Active :class:`~config.Config`.

    Returns:
        A sorted list of unique subdomains, including the base domain.
    """
    runners = {
        "subfinder": _run_subfinder,
        "amass": _run_amass,
        "assetfinder": _run_assetfinder,
    }

    found: set[str] = {domain}

    with ThreadPoolExecutor(max_workers=len(runners)) as executor:
        futures = {
            executor.submit(fn, domain, config): name for name, fn in runners.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results = future.result()
                logger.info("%s found %d subdomain(s)", name, len(results))
                found.update(results)
            except Exception as exc:  # noqa: BLE001 - isolate per-tool failures
                logger.error("%s raised an unexpected error: %s", name, exc)

    # Filter out anything that isn't actually a subdomain of the target
    # (defensive cleanup against noisy tool output).
    cleaned = {s for s in found if s == domain or s.endswith(f".{domain}")}

    sorted_subdomains = sorted(cleaned)
    write_lines(report_dir / "subdomains.txt", sorted_subdomains)
    logger.info("Total unique subdomains for %s: %d", domain, len(sorted_subdomains))
    return sorted_subdomains
