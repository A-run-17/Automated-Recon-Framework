"""
Input handling for the Recon Framework.

Validates and normalizes the user-supplied target, creates the scan's
report directory, generates a unique scan ID, and persists the initial
``input.json`` metadata file.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path

from utils.helpers import ensure_directory, timestamp, write_json
from utils.validator import classify_target, normalize_target


@dataclass
class Scan:
    """
    Represents a single reconnaissance scan.

    Attributes:
        target: The normalized target (domain, IP, or CIDR).
        target_type: One of ``"domain"``, ``"ipv4"``, ``"ipv6"``, ``"cidr"``.
        raw_input: The original, unmodified value supplied by the user.
        scan_id: Unique identifier for this scan run.
        report_dir: Directory where this scan's artifacts are stored.
        threads: Number of worker threads to use for concurrent operations.
        timeout: Per-command timeout in seconds for external tools.
    """

    target: str
    target_type: str
    raw_input: str
    scan_id: str
    report_dir: Path
    threads: int = 50
    timeout: int = 20


def generate_scan_id() -> str:
    """Generate a unique scan identifier.

    Combines a UTC timestamp with a short random suffix so scan IDs are
    both human-readable and collision-resistant.

    Returns:
        A scan ID string, e.g. ``"20260712-093015-a1b2c3"``.
    """
    return f"{timestamp()}-{uuid.uuid4().hex[:6]}"


def prepare_scan(
    raw_target: str,
    reports_dir: Path,
    threads: int = 50,
    timeout: int = 20,
) -> Scan:
    """Validate a target, create its report directory, and build a Scan.

    Args:
        raw_target: The target string as supplied on the command line
            (domain, URL, IP address, or CIDR range).
        reports_dir: Root directory under which per-target reports live.
        threads: Number of worker threads to use for concurrent operations.
        timeout: Per-command timeout in seconds for external tools.

    Returns:
        A populated :class:`Scan` instance with its report directory
        already created and ``input.json`` written.

    Raises:
        ValueError: If ``raw_target`` is not a valid domain, URL, IP
            address, or CIDR range.
    """
    normalized = normalize_target(raw_target)
    target_type = classify_target(normalized)
    scan_id = generate_scan_id()

    report_dir = ensure_directory(reports_dir / normalized / scan_id)
    ensure_directory(report_dir / "screenshots")

    scan = Scan(
        target=normalized,
        target_type=target_type,
        raw_input=raw_target,
        scan_id=scan_id,
        report_dir=report_dir,
        threads=threads,
        timeout=timeout,
    )

    write_json(
        report_dir / "input.json",
        {
            "target": scan.target,
            "target_type": scan.target_type,
            "raw_input": scan.raw_input,
            "scan_id": scan.scan_id,
            "report_dir": str(scan.report_dir),
            "threads": scan.threads,
            "timeout": scan.timeout,
        },
    )

    return scan
