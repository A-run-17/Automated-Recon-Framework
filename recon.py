#!/usr/bin/env python3
"""
Automated Recon Framework — CLI entry point.

Orchestrates subdomain enumeration, HTTP probing, port scanning,
JavaScript analysis, screenshot capture, and report generation for a
given target.

This tool is intended for authorized security testing only. Only scan
targets you own or have explicit written permission to test.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True # To avoid the accumulation of pychache

import argparse
import logging
import time

from config import load_config
from modules.http_probe import probe_hosts
from modules.input_module import prepare_scan
from modules.javascript import analyze_hosts
from modules.port_scan import scan_ports
from modules.report import build_summary, generate_all_reports
from modules.screenshots import capture_screenshots
from modules.subdomain import enumerate_subdomains

from utils.banner import print_banner
from utils.logger import setup_logger


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Construct the CLI argument parser.
    Returns:
        A configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description=(
            "Automated Recon Framework — modular reconnaissance for "
            "authorized security testing and bug bounty hunting."
        ),
    )
    parser.add_argument("target", help="Target domain, URL, IP address, or CIDR range")

    stage_group = parser.add_argument_group("scan stages")
    stage_group.add_argument("--full", action="store_true", help="Run all stages")
    stage_group.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    stage_group.add_argument("--http", action="store_true", help="Run HTTP probing")
    stage_group.add_argument("--ports", action="store_true", help="Run port scanning")
    stage_group.add_argument("--javascript", action="store_true", help="Run JavaScript analysis")
    stage_group.add_argument("--screenshots", action="store_true", help="Capture screenshots")
    stage_group.add_argument("--report", action="store_true", help="Generate reports")

    tuning_group = parser.add_argument_group("tuning")
    tuning_group.add_argument("--threads", type=int, default=50, help="Worker threads (default: 50)")
    tuning_group.add_argument("--timeout", type=int, default=20, help="Per-command timeout in seconds (default: 20)")
    tuning_group.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    return parser


def _resolve_stages(args: argparse.Namespace) -> dict[str, bool]:
    """Determine which stages to run based on CLI flags.

    If no specific stage flags are given, all stages run by default
    (equivalent to ``--full``).

    Args:
        args: Parsed CLI arguments.

    Returns:
        A mapping of stage name to whether it should run.
    """
    explicit_flags = [args.subdomains, args.http, args.ports, args.javascript, args.screenshots, args.report]
    run_all = args.full or not any(explicit_flags)

    return {
        "subdomains": run_all or args.subdomains,
        "http": run_all or args.http,
        "ports": run_all or args.ports,
        "javascript": run_all or args.javascript,
        "screenshots": run_all or args.screenshots,
        "report": run_all or args.report,
    }


def main(argv: list[str] | None = None) -> int:
    """Run the recon framework CLI.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code (``0`` on success, non-zero on failure).
    """
    print_banner()

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config = load_config(threads=args.threads, timeout=args.timeout, log_level=args.log_level)

    try:
        scan = prepare_scan(args.target, config.reports_dir, threads=args.threads, timeout=args.timeout)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    log_file = scan.report_dir / "scan.log"
    logger = setup_logger("recon", log_file=log_file, level=args.log_level)

    logger.info("Starting scan of %s (scan ID: %s)", scan.target, scan.scan_id)
    logger.info("Report directory: %s", scan.report_dir)

    stages = _resolve_stages(args)
    start_time = time.monotonic()

    subdomains: list[str] = [scan.target]
    alive_hosts = []
    port_results = []
    js_findings = []
    screenshot_hosts: list[str] = []

    if scan.target_type != "domain" and stages["subdomains"]:
        logger.info("Target is not a domain (%s); skipping subdomain enumeration", scan.target_type)
        stages["subdomains"] = False

    if stages["subdomains"]:
        logger.info("Stage: subdomain enumeration")
        subdomains = enumerate_subdomains(scan.target, scan.report_dir, config)

    if stages["http"]:
        logger.info("Stage: HTTP probing")
        alive_hosts = probe_hosts(subdomains, scan.report_dir, config)

    live_urls = [h.url for h in alive_hosts] if alive_hosts else subdomains

    if stages["ports"]:
        logger.info("Stage: port scanning")
        port_targets = subdomains if subdomains else [scan.target]
        port_results = scan_ports(port_targets, scan.report_dir, config)

    if stages["javascript"]:
        logger.info("Stage: JavaScript analysis")
        js_findings = analyze_hosts(live_urls, scan.report_dir, config)

    if stages["screenshots"]:
        logger.info("Stage: screenshot capture")
        screenshot_hosts = capture_screenshots(live_urls, scan.report_dir, config)

    duration = time.monotonic() - start_time

    if stages["report"]:
        logger.info("Stage: report generation")
        summary = build_summary(
            scan,
            duration_seconds=duration,
            subdomains=subdomains,
            alive_hosts=alive_hosts,
            port_results=port_results,
            js_findings=js_findings,
            screenshot_hosts=screenshot_hosts,
        )
        generate_all_reports(summary, scan.report_dir)

    logger.info("Scan complete in %.1fs", duration)
    logger.info("Results saved to %s", scan.report_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
