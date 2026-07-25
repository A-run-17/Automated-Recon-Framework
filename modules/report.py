"""
Report generation module.

Aggregates all scan results into a single, self-contained HTML report:
subdomains as clickable links, JSON-derived data rendered as styled
tables, screenshots embedded inline as base64 so the whole report is
one file with no external assets or network dependency.
"""

from __future__ import annotations

import base64
import html
import json
import logging
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

from modules.http_probe import HttpResult
from modules.input_module import Scan
from modules.javascript import JsFinding
from modules.port_scan import HostScanResult
from utils.helpers import format_duration

logger = logging.getLogger(__name__)

_IMAGE_MIME_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


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


def _status_class(status: int | None) -> str:
    """Map an HTTP status code to a CSS badge class."""
    if status is None:
        return "badge-unknown"
    if 200 <= status < 300:
        return "badge-ok"
    if 300 <= status < 400:
        return "badge-redirect"
    if 400 <= status < 500:
        return "badge-client-error"
    return "badge-server-error"


def _embed_screenshots(report_dir: Path) -> list[dict[str, str]]:
    """Read every screenshot on disk and embed it as a base64 data URI.

    Args:
        report_dir: The scan's report directory (contains ``screenshots/``).

    Returns:
        A list of dicts with ``name`` and ``data_uri`` keys, sorted by
        filename. Empty if no screenshots exist.
    """
    screenshots_dir = report_dir / "screenshots"
    if not screenshots_dir.exists():
        return []

    embedded: list[dict[str, str]] = []
    for image_path in sorted(screenshots_dir.iterdir()):
        mime = _IMAGE_MIME_TYPES.get(image_path.suffix.lower())
        if mime is None:
            continue
        try:
            raw = image_path.read_bytes()
        except OSError as exc:
            logger.warning("Could not read screenshot %s: %s", image_path, exc)
            continue
        encoded = base64.b64encode(raw).decode("ascii")
        embedded.append({"name": image_path.stem, "data_uri": f"data:{mime};base64,{encoded}"})

    return embedded

'''
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
'''

def generate_report(summary: ScanSummary, report_dir: Path) -> Path:
    """Generate a single, self-contained HTML report for a scan.

    Everything — statistics, clickable subdomains, alive-host and port
    tables, JavaScript findings, and screenshots — is embedded directly
    in one HTML file (screenshots as base64 data URIs), so the report
    can be opened, shared, or archived with no other files or network
    access required.

    Args:
        summary: The scan summary to render.
        report_dir: Directory to write ``report.html`` into.

    Returns:
        Path to the written HTML report.
    """
    e = html.escape
    stats = summary.statistics
    screenshots = _embed_screenshots(report_dir)

    # ---- Stat cards -----------------------------------------------------
    stat_labels = {
        "subdomains_found": "Subdomains",
        "alive_hosts": "Alive Hosts",
        "hosts_port_scanned": "Hosts Scanned",
        "open_ports_found": "Open Ports",
        "js_files_analyzed": "JS Files",
        "possible_secrets_found": "Possible Secrets",
        "screenshots_captured": "Screenshots",
    }
    stat_cards = "".join(
        f'<div class="stat-card{" stat-alert" if key == "possible_secrets_found" and value else ""}">'
        f'<div class="stat-value">{value}</div>'
        f'<div class="stat-label">{e(stat_labels.get(key, key))}</div></div>'
        for key, value in stats.items()
    )

    # ---- Subdomains as clickable chips -----------------------------------
    if summary.subdomains:
        subdomain_chips = "".join(
            f'<a class="chip" href="https://{e(s)}" target="_blank" rel="noopener noreferrer" '
            f'data-filter="{e(s.lower())}">{e(s)}</a>'
            for s in summary.subdomains
        )
    else:
        subdomain_chips = '<p class="empty">No subdomains found.</p>'

    # ---- Alive hosts table ------------------------------------------------
    if summary.alive_hosts:
        alive_rows = "".join(
            f'<tr><td><a href="{e(h.url)}" target="_blank" rel="noopener noreferrer">{e(h.url)}</a></td>'
            f'<td><span class="badge {_status_class(h.status_code)}">{h.status_code or "?"}</span></td>'
            f'<td>{e(h.title) or "&mdash;"}</td>'
            f'<td>{e(h.webserver) or "&mdash;"}</td>'
            f'<td>{", ".join(e(t) for t in (h.technologies or [])) or "&mdash;"}</td></tr>'
            for h in summary.alive_hosts
        )
        alive_table = (
            '<table><thead><tr><th>URL</th><th>Status</th><th>Title</th>'
            '<th>Server</th><th>Technologies</th></tr></thead>'
            f"<tbody>{alive_rows}</tbody></table>"
        )
    else:
        alive_table = '<p class="empty">No alive hosts found.</p>'

    # ---- Ports, grouped per host in collapsible sections ------------------
    if summary.port_results:
        port_sections = ""
        for host_result in summary.port_results:
            if host_result.ports:
                port_rows = "".join(
                    f'<tr><td>{p.port}</td><td>{e(p.protocol)}</td>'
                    f'<td>{e(p.service) or "&mdash;"}</td>'
                    f'<td>{e((p.product + " " + p.version).strip()) or "&mdash;"}</td></tr>'
                    for p in host_result.ports
                )
                port_table = (
                    '<table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th>'
                    f'<th>Product / Version</th></tr></thead><tbody>{port_rows}</tbody></table>'
                )
            else:
                port_table = '<p class="empty">No open ports found.</p>'

            os_line = f'<p class="os-guess">OS guess: {e(host_result.os_guess)}</p>' if host_result.os_guess else ""
            port_sections += (
                f'<details class="host-block" open><summary>{e(host_result.host)} '
                f'<span class="count-pill">{len(host_result.ports)} open</span></summary>'
                f"{os_line}{port_table}</details>"
            )
    else:
        port_sections = '<p class="empty">No hosts were port scanned.</p>'

    # ---- JavaScript findings table -----------------------------------------
    if summary.js_findings:
        js_rows = ""
        for finding in summary.js_findings:
            has_secrets = bool(finding.secrets)
            secrets_cell = (
                "".join(f'<span class="tag tag-danger">{e(k)}</span>' for k in finding.secrets)
                if has_secrets
                else '<span class="tag tag-safe">none</span>'
            )
            js_rows += (
                f'<tr class="{"row-alert" if has_secrets else ""}">'
                f'<td><a href="{e(finding.source_url)}" target="_blank" rel="noopener noreferrer">'
                f'{e(finding.source_url)}</a></td>'
                f"<td>{len(finding.endpoints)}</td>"
                f"<td>{len(finding.urls)}</td>"
                f"<td>{secrets_cell}</td></tr>"
            )
        js_table = (
            '<table><thead><tr><th>Source File</th><th>Endpoints</th>'
            "<th>URLs</th><th>Possible Secrets</th></tr></thead>"
            f"<tbody>{js_rows}</tbody></table>"
        )
    else:
        js_table = '<p class="empty">No JavaScript findings.</p>'

    # ---- Screenshot gallery (fully embedded, no external files) -----------
    if screenshots:
        gallery_items = "".join(
            f'<a class="gallery-item" href="{shot["data_uri"]}" target="_blank" rel="noopener noreferrer">'
            f'<img src="{shot["data_uri"]}" alt="{e(shot["name"])}" loading="lazy">'
            f'<span class="gallery-caption">{e(shot["name"])}</span></a>'
            for shot in screenshots
        )
        gallery = f'<div class="gallery">{gallery_items}</div>'
    else:
        gallery = '<p class="empty">No screenshots captured.</p>'

    # ---- Embedded raw data (for anyone who wants to script against it) -----
    raw_payload = _to_plain(summary)
    raw_payload["statistics"] = stats
    raw_json = json.dumps(raw_payload, indent=2)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report — {e(summary.target)}</title>
<style>
  :root {{
    --bg: #0f1420;
    --surface: #161d2e;
    --surface-alt: #1d2740;
    --border: #2a3550;
    --text: #e6ebf5;
    --text-dim: #93a1c2;
    --accent: #4f8cff;
    --ok: #2ecc71;
    --redirect: #f1c40f;
    --client-error: #e67e22;
    --server-error: #e74c3c;
    --danger: #e74c3c;
    --safe: #2ecc71;
    --radius: 10px;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }}
  header.top {{
    display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between;
    border-bottom: 1px solid var(--border); padding-bottom: 1.25rem; margin-bottom: 2rem;
  }}
  header.top h1 {{ margin: 0; font-size: 1.7rem; font-weight: 700; }}
  header.top .meta {{ color: var(--text-dim); font-size: 0.9rem; }}
  h2 {{
    font-size: 1.1rem; text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--text-dim); margin: 2.5rem 0 1rem; font-weight: 600;
  }}
  .stat-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 0.75rem; margin-top: 1rem;
  }}
  .stat-card {{
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 1rem; text-align: center;
  }}
  .stat-card.stat-alert {{ border-color: var(--danger); background: rgba(231, 76, 60, 0.08); }}
  .stat-value {{ font-size: 1.6rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.04em; margin-top: 0.25rem; }}

  input#subdomain-filter {{
    width: 100%; padding: 0.6rem 0.9rem; border-radius: var(--radius); border: 1px solid var(--border);
    background: var(--surface); color: var(--text); font-size: 0.9rem; margin-bottom: 0.85rem;
  }}
  .chip-grid {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
  .chip {{
    display: inline-block; padding: 0.35rem 0.75rem; background: var(--surface-alt);
    border: 1px solid var(--border); border-radius: 999px; color: var(--accent);
    text-decoration: none; font-size: 0.85rem; transition: border-color 0.15s;
  }}
  .chip:hover {{ border-color: var(--accent); }}

  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: var(--radius); overflow: hidden; }}
  th, td {{ padding: 0.6rem 0.85rem; text-align: left; font-size: 0.88rem; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--surface-alt); color: var(--text-dim); font-weight: 600; text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.04em; }}
  tr:last-child td {{ border-bottom: none; }}
  td a {{ color: var(--accent); text-decoration: none; word-break: break-all; }}
  td a:hover {{ text-decoration: underline; }}

  .badge {{ padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.78rem; font-weight: 600; }}
  .badge-ok {{ background: rgba(46, 204, 113, 0.15); color: var(--ok); }}
  .badge-redirect {{ background: rgba(241, 196, 15, 0.15); color: var(--redirect); }}
  .badge-client-error {{ background: rgba(230, 126, 34, 0.15); color: var(--client-error); }}
  .badge-server-error {{ background: rgba(231, 76, 60, 0.15); color: var(--server-error); }}
  .badge-unknown {{ background: rgba(147, 161, 194, 0.15); color: var(--text-dim); }}

  details.host-block {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 0.75rem; padding: 0.85rem 1rem; }}
  details.host-block summary {{ cursor: pointer; font-weight: 600; list-style: none; display: flex; align-items: center; gap: 0.6rem; }}
  details.host-block summary::-webkit-details-marker {{ display: none; }}
  details.host-block table {{ margin-top: 0.75rem; }}
  .count-pill {{ font-size: 0.72rem; font-weight: 600; color: var(--text-dim); background: var(--surface-alt); padding: 0.1rem 0.5rem; border-radius: 999px; }}
  .os-guess {{ color: var(--text-dim); font-size: 0.85rem; margin: 0.4rem 0 0; }}

  .tag {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; margin: 0.1rem; }}
  .tag-danger {{ background: rgba(231, 76, 60, 0.15); color: var(--danger); }}
  .tag-safe {{ background: rgba(46, 204, 113, 0.12); color: var(--safe); }}
  tr.row-alert {{ background: rgba(231, 76, 60, 0.06); }}

  .gallery {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 1rem; }}
  .gallery-item {{ display: block; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; text-decoration: none; }}
  .gallery-item img {{ width: 100%; display: block; aspect-ratio: 16 / 10; object-fit: cover; background: #000; }}
  .gallery-caption {{ display: block; padding: 0.5rem 0.7rem; font-size: 0.78rem; color: var(--text-dim); word-break: break-all; }}

  .empty {{ color: var(--text-dim); font-style: italic; font-size: 0.9rem; }}
  footer {{ margin-top: 3rem; padding-top: 1.25rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <h1>{e(summary.target)}</h1>
    <div class="meta">Scan ID: {e(summary.scan_id)} &middot; Duration: {e(format_duration(summary.duration_seconds))}</div>
  </header>

  <section>
    <h2>Overview</h2>
    <div class="stat-grid">{stat_cards}</div>
  </section>

  <section>
    <h2>Subdomains ({len(summary.subdomains)})</h2>
    <input type="text" id="subdomain-filter" placeholder="Filter subdomains..." oninput="filterSubdomains(this.value)">
    <div class="chip-grid" id="subdomain-chips">{subdomain_chips}</div>
  </section>

  <section>
    <h2>Alive Hosts ({len(summary.alive_hosts)})</h2>
    {alive_table}
  </section>

  <section>
    <h2>Open Ports</h2>
    {port_sections}
  </section>

  <section>
    <h2>JavaScript Findings</h2>
    {js_table}
  </section>

  <section>
    <h2>Screenshots ({len(screenshots)})</h2>
    {gallery}
  </section>

  <footer>
    Generated by Automated Recon Framework. For authorized security testing only.
  </footer>

</div>

<script type="application/json" id="scan-data">{raw_json}</script>
<script>
  function filterSubdomains(query) {{
    const q = query.trim().toLowerCase();
    document.querySelectorAll('#subdomain-chips .chip').forEach(function (chip) {{
      const match = chip.getAttribute('data-filter').includes(q);
      chip.style.display = match ? 'inline-block' : 'none';
    }});
  }}
</script>
</body>
</html>
"""

    output_path = report_dir / "report.html"
    output_path.write_text(html_doc, encoding="utf-8")
    logger.info("Report generated: %s", output_path)
    return output_path
