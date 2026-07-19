"""
Report generation module.

Aggregates all scan results into a single structured summary and renders
it as HTML, JSON, and Markdown reports.
"""

from __future__ import annotations

import html
import logging
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

from modules.http_probe import HttpResult
from modules.input_module import Scan
from modules.javascript import JsFinding
from modules.port_scan import HostScanResult
from utils.helpers import format_duration, write_json

logger = logging.getLogger(__name__)


@dataclass
class ScanSummary:
    """Aggregated results for a completed scan.

    Attributes:
        target: The scanned target.
        scan_id: Unique scan identifier.
        duration_seconds: Total scan duration in seconds.
        subdomains: Discovered subdomains.
        alive_hosts: HTTP probe results for live hosts.
        port_results: Nmap results per host.
        js_findings: JavaScript analysis findings.
        screenshot_hosts: Hosts that had screenshots captured.
    """

    target: str
    scan_id: str
    duration_seconds: float
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[HttpResult] = field(default_factory=list)
    port_results: list[HostScanResult] = field(default_factory=list)
    js_findings: list[JsFinding] = field(default_factory=list)
    screenshot_hosts: list[str] = field(default_factory=list)

    @property
    def statistics(self) -> dict[str, int]:
        """Summary statistics for quick-glance reporting."""
        total_open_ports = sum(len(h.ports) for h in self.port_results)
        total_secrets = sum(len(f.secrets) for f in self.js_findings)
        return {
            "subdomains_found": len(self.subdomains),
            "alive_hosts": len(self.alive_hosts),
            "hosts_port_scanned": len(self.port_results),
            "open_ports_found": total_open_ports,
            "js_files_analyzed": len(self.js_findings),
            "possible_secrets_found": total_secrets,
            "screenshots_captured": len(self.screenshot_hosts),
        }


def _to_plain(obj: Any) -> Any:
    """Recursively convert dataclasses to plain dicts for serialization."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_plain(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_plain(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, Path):
        return str(obj)
    return obj


def build_summary(
    scan: Scan,
    duration_seconds: float,
    subdomains: list[str] | None = None,
    alive_hosts: list[HttpResult] | None = None,
    port_results: list[HostScanResult] | None = None,
    js_findings: list[JsFinding] | None = None,
    screenshot_hosts: list[str] | None = None,
) -> ScanSummary:
    """Assemble a :class:`ScanSummary` from individual module outputs.

    Args:
        scan: The originating :class:`~modules.input_module.Scan`.
        duration_seconds: Total wall-clock duration of the scan.
        subdomains: Results from subdomain enumeration.
        alive_hosts: Results from HTTP probing.
        port_results: Results from port scanning.
        js_findings: Results from JavaScript analysis.
        screenshot_hosts: Hosts screenshots were captured for.

    Returns:
        A populated :class:`ScanSummary`.
    """
    return ScanSummary(
        target=scan.target,
        scan_id=scan.scan_id,
        duration_seconds=duration_seconds,
        subdomains=subdomains or [],
        alive_hosts=alive_hosts or [],
        port_results=port_results or [],
        js_findings=js_findings or [],
        screenshot_hosts=screenshot_hosts or [],
    )


def generate_json_report(summary: ScanSummary, report_dir: Path) -> Path:
    """Write the scan summary as ``report.json``.

    Args:
        summary: The scan summary to serialize.
        report_dir: Directory to write the report into.

    Returns:
        Path to the written JSON report.
    """
    output_path = report_dir / "report.json"
    payload = _to_plain(summary)
    payload["statistics"] = summary.statistics
    write_json(output_path, payload)
    return output_path


def generate_markdown_report(summary: ScanSummary, report_dir: Path) -> Path:
    """Write the scan summary as ``report.md``.

    Args:
        summary: The scan summary to render.
        report_dir: Directory to write the report into.

    Returns:
        Path to the written Markdown report.
    """
    stats = summary.statistics
    lines: list[str] = [
        f"# Recon Report: {summary.target}",
        "",
        f"- **Scan ID:** {summary.scan_id}",
        f"- **Duration:** {format_duration(summary.duration_seconds)}",
        "",
        "## Statistics",
        "",
    ]
    for key, value in stats.items():
        lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")

    lines += ["", "## Subdomains", ""]
    if summary.subdomains:
        lines += [f"- {s}" for s in summary.subdomains]
    else:
        lines.append("_No subdomains found._")

    lines += ["", "## Alive Hosts", ""]
    if summary.alive_hosts:
        lines.append("| URL | Status | Title | Web Server |")
        lines.append("|---|---|---|---|")
        for h in summary.alive_hosts:
            lines.append(f"| {h.url} | {h.status_code} | {h.title} | {h.webserver} |")
    else:
        lines.append("_No alive hosts found._")

    lines += ["", "## Open Ports", ""]
    if summary.port_results:
        for host_result in summary.port_results:
            lines.append(f"### {host_result.host}")
            if host_result.os_guess:
                lines.append(f"- OS guess: {host_result.os_guess}")
            if host_result.ports:
                lines.append("| Port | Protocol | Service | Product/Version |")
                lines.append("|---|---|---|---|")
                for port in host_result.ports:
                    prod = f"{port.product} {port.version}".strip()
                    lines.append(f"| {port.port} | {port.protocol} | {port.service} | {prod} |")
            else:
                lines.append("_No open ports found._")
            lines.append("")
    else:
        lines.append("_No hosts were port scanned._")

    lines += ["", "## JavaScript Findings", ""]
    if summary.js_findings:
        for finding in summary.js_findings:
            lines.append(f"### {finding.source_url}")
            if finding.endpoints:
                lines.append(f"- Endpoints found: {len(finding.endpoints)}")
            if finding.urls:
                lines.append(f"- URLs found: {len(finding.urls)}")
            if finding.secrets:
                lines.append(f"- **Possible secrets:** {', '.join(finding.secrets.keys())}")
            lines.append("")
    else:
        lines.append("_No JavaScript findings._")

    lines += ["", "## Screenshots", ""]
    if summary.screenshot_hosts:
        lines.append(f"Screenshots captured for {len(summary.screenshot_hosts)} host(s), "
                      "stored in the `screenshots/` directory.")
    else:
        lines.append("_No screenshots captured._")

    output_path = report_dir / "report.md"
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def generate_html_report(summary: ScanSummary, report_dir: Path) -> Path:
    """Write the scan summary as ``report.html``.

    Args:
        summary: The scan summary to render.
        report_dir: Directory to write the report into.

    Returns:
        Path to the written HTML report.
    """
    stats = summary.statistics
    e = html.escape

    stat_rows = "".join(
        f"<tr><td>{e(k.replace('_', ' ').title())}</td><td>{v}</td></tr>"
        for k, v in stats.items()
    )

    subdomain_items = "".join(f"<li>{e(s)}</li>" for s in summary.subdomains) or "<li>None found</li>"

    alive_rows = "".join(
        f"<tr><td>{e(h.url)}</td><td>{h.status_code}</td><td>{e(h.title)}</td>"
        f"<td>{e(h.webserver)}</td></tr>"
        for h in summary.alive_hosts
    ) or "<tr><td colspan='4'>None found</td></tr>"

    port_sections = ""
    for host_result in summary.port_results:
        port_rows = "".join(
            f"<tr><td>{p.port}</td><td>{e(p.protocol)}</td><td>{e(p.service)}</td>"
            f"<td>{e((p.product + ' ' + p.version).strip())}</td></tr>"
            for p in host_result.ports
        ) or "<tr><td colspan='4'>No open ports</td></tr>"
        os_line = f"<p>OS guess: {e(host_result.os_guess)}</p>" if host_result.os_guess else ""
        port_sections += (
            f"<h3>{e(host_result.host)}</h3>{os_line}"
            f"<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product/Version</th></tr>"
            f"{port_rows}</table>"
        )
    if not summary.port_results:
        port_sections = "<p>No hosts were port scanned.</p>"

    js_sections = ""
    for finding in summary.js_findings:
        secrets_str = ", ".join(finding.secrets.keys()) if finding.secrets else "None"
        js_sections += (
            f"<h3>{e(finding.source_url)}</h3>"
            f"<p>Endpoints: {len(finding.endpoints)} | URLs: {len(finding.urls)} | "
            f"Possible secrets: {e(secrets_str)}</p>"
        )
    if not summary.js_findings:
        js_sections = "<p>No JavaScript findings.</p>"

    screenshot_text = (
        f"<p>Screenshots captured for {len(summary.screenshot_hosts)} host(s). "
        f"See the <code>screenshots/</code> directory.</p>"
        if summary.screenshot_hosts
        else "<p>No screenshots captured.</p>"
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report - {e(summary.target)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }}
  h1 {{ border-bottom: 3px solid #2563eb; padding-bottom: 0.5rem; }}
  h2 {{ margin-top: 2rem; color: #2563eb; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem 0; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 0.9rem; }}
  th {{ background: #2563eb; color: #fff; }}
  .meta {{ color: #555; margin-bottom: 1.5rem; }}
  code {{ background: #eee; padding: 2px 5px; border-radius: 3px; }}
</style>
</head>
<body>
<h1>Recon Report: {e(summary.target)}</h1>
<p class="meta">Scan ID: {e(summary.scan_id)} &middot; Duration: {e(format_duration(summary.duration_seconds))}</p>

<h2>Statistics</h2>
<table><tr><th>Metric</th><th>Value</th></tr>{stat_rows}</table>

<h2>Subdomains ({len(summary.subdomains)})</h2>
<ul>{subdomain_items}</ul>

<h2>Alive Hosts ({len(summary.alive_hosts)})</h2>
<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Web Server</th></tr>{alive_rows}</table>

<h2>Open Ports</h2>
{port_sections}

<h2>JavaScript Findings</h2>
{js_sections}

<h2>Screenshots</h2>
{screenshot_text}

</body>
</html>
"""

    output_path = report_dir / "report.html"
    output_path.write_text(html_doc, encoding="utf-8")
    return output_path


def generate_all_reports(summary: ScanSummary, report_dir: Path) -> dict[str, Path]:
    """Generate JSON, Markdown, and HTML reports for a scan.

    Args:
        summary: The scan summary to render.
        report_dir: Directory to write reports into.

    Returns:
        A mapping of report format to output path, e.g.
        ``{"json": Path(...), "markdown": Path(...), "html": Path(...)}``.
    """
    paths = {
        "json": generate_json_report(summary, report_dir),
        "markdown": generate_markdown_report(summary, report_dir),
        "html": generate_html_report(summary, report_dir),
    }
    logger.info("Reports generated: %s", ", ".join(str(p) for p in paths.values()))
    return paths
