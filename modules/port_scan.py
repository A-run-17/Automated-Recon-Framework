"""
Port scanning module.

Wraps Nmap to discover open ports, running services, version banners,
and (when possible) operating system guesses for a target.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path

from config import Config
from utils.helpers import run_command, tool_available, write_json, write_lines

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    """
    A single open port discovered on a host.

    Attributes:
        port: Port number.
        protocol: Transport protocol, e.g. ``"tcp"``.
        state: Port state, e.g. ``"open"``.
        service: Service name, e.g. ``"http"``.
        product: Detected product/software name, if any.
        version: Detected product version, if any.
    """

    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""


@dataclass
class HostScanResult:
    """
    Nmap scan results for a single host.

    Attributes:
        host: The scanned hostname or IP address.
        os_guess: Best-effort operating system guess, if available.
        ports: List of discovered open ports.
    """

    host: str
    os_guess: str = ""
    ports: list[PortResult] = field(default_factory=list)


def _parse_nmap_xml(xml_output: str) -> list[HostScanResult]:
    """Parse Nmap's XML output (``-oX -``) into structured results."""
    results: list[HostScanResult] = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        logger.error("Failed to parse nmap XML output: %s", exc)
        return results

    for host_elem in root.findall("host"):
        address_elem = host_elem.find("address")
        host_addr = address_elem.get("addr") if address_elem is not None else "unknown"

        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None and hostname_elem.get("name"):
                host_addr = hostname_elem.get("name")

        os_guess = ""
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_guess = osmatch.get("name", "")

        host_result = HostScanResult(host=host_addr, os_guess=os_guess)

        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "") if state_elem is not None else ""
                if state != "open":
                    continue

                service_elem = port_elem.find("service")
                service_name = service_elem.get("name", "") if service_elem is not None else ""
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""

                host_result.ports.append(
                    PortResult(
                        port=int(port_elem.get("portid", 0)),
                        protocol=port_elem.get("protocol", "tcp"),
                        state=state,
                        service=service_name,
                        product=product,
                        version=version,
                    )
                )

        results.append(host_result)

    return results


def scan_ports(
    targets: list[str],
    report_dir: Path,
    config: Config,
    top_ports: int = 1000,
) -> list[HostScanResult]:
    """
    Run an Nmap service/version scan against one or more targets.

    Args:
        targets: Hostnames or IP addresses to scan.
        report_dir: Directory to write ``ports.txt`` / ``ports.json`` into.
        config: Active :class:`~config.Config`.
        top_ports: Number of most-common ports to scan per host.

    Returns:
        A list of :class:`HostScanResult`, one per scanned host that
        responded. Returns an empty list if nmap is unavailable or no
        targets are supplied.
    """
    tool = config.tool_paths.nmap
    if not tool_available(tool):
        logger.warning("nmap not found on PATH, skipping port scan")
        write_lines(report_dir / "ports.txt", [])
        write_json(report_dir / "ports.json", [])
        return []

    if not targets:
        logger.info("No targets supplied to scan_ports")
        write_lines(report_dir / "ports.txt", [])
        write_json(report_dir / "ports.json", [])
        return []

    command = [
        tool,
        "-sV",
        "--top-ports",
        str(top_ports),
        "-T4",
        "--host-timeout",
        f"{config.timeout * 10}s",
        "-oX",
        "-",
        *targets,
    ]

    result = run_command(command, timeout=config.timeout * 10 * max(1, len(targets)))
    if not result.succeeded or not result.stdout.strip():
        logger.warning("nmap scan produced no output: %s", result.stderr.strip())
        write_lines(report_dir / "ports.txt", [])
        write_json(report_dir / "ports.json", [])
        return []

    host_results = _parse_nmap_xml(result.stdout)

    text_lines: list[str] = []
    for host_result in host_results:
        for port in host_result.ports:
            service_desc = port.service
            if port.product:
                service_desc += f" ({port.product} {port.version})".rstrip()
            text_lines.append(
                f"{host_result.host}\t{port.port}/{port.protocol}\t{port.state}\t{service_desc}"
            )

    write_lines(report_dir / "ports.txt", text_lines)
    write_json(report_dir / "ports.json", [asdict(h) for h in host_results])

    total_ports = sum(len(h.ports) for h in host_results)
    logger.info("Port scan complete: %d open port(s) across %d host(s)", total_ports, len(host_results))
    return host_results
