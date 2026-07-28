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
    stat_anchors = {
        "subdomains_found": "#subdomains",
        "alive_hosts": "#alive-hosts",
        "hosts_port_scanned": "#open-ports",
        "open_ports_found": "#open-ports",
        "js_files_analyzed": "#js-findings",
        "possible_secrets_found": "#js-findings",
        "screenshots_captured": "#screenshots",
    }
    stat_cards = "".join(
        f'<a class="stat-card{" stat-alert" if key == "possible_secrets_found" and value else ""}" '
        f'href="{stat_anchors.get(key, "#overview")}">'
        f'<div class="stat-value">{value}</div>'
        f'<div class="stat-label">{e(stat_labels.get(key, key))}</div></a>'
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
                f'<details class="host-block" data-filter="{e(host_result.host.lower())}">'
                f'<summary>{e(host_result.host)} '
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

    # ---- Screenshot slideshow (fully embedded, no external files) ---------
    if screenshots:
        gallery = f"""<div class="slideshow">
      <div class="slide-viewport">
        <button class="slide-nav prev" onclick="changeSlide(-1)" aria-label="Previous screenshot">&#10094;</button>
        <img id="slide-image" src="{screenshots[0]['data_uri']}" alt="{e(screenshots[0]['name'])}">
        <button class="slide-nav next" onclick="changeSlide(1)" aria-label="Next screenshot">&#10095;</button>
        <div class="slide-counter"><span id="slide-index">1</span> / {len(screenshots)}</div>
      </div>
      <div class="slide-caption" id="slide-caption">{e(screenshots[0]['name'])}</div>
      <div class="slide-dots" id="slide-dots"></div>
    </div>"""
    else:
        gallery = '<p class="empty">No screenshots captured.</p>'
    screenshot_json = json.dumps(screenshots)

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
    --bg: #060a08;
    --surface: #0b120d;
    --surface-alt: #101a13;
    --border: #1e3a26;
    --border-bright: #00ff7f;
    --text: #c9ffd6;
    --text-dim: #5d8a6b;
    --accent: #00ff7f;
    --accent-glow: rgba(0, 255, 127, 0.35);
    --ok: #00ff7f;
    --redirect: #ffe066;
    --client-error: #ff9f43;
    --server-error: #ff5c5c;
    --danger: #ff5c5c;
    --safe: #00ff7f;
    --radius: 6px;
    --mono: "Consolas", "SFMono-Regular", "Courier New", monospace;
  }}
  * {{ box-sizing: border-box; }}
  html {{ scroll-behavior: smooth; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    line-height: 1.55;
    position: relative;
  }}
  body::before {{
    content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 999;
    background: repeating-linear-gradient(0deg, rgba(0,255,127,0.025) 0px, rgba(0,255,127,0.025) 1px, transparent 1px, transparent 3px);
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }}
  section {{ scroll-margin-top: 4.5rem; }}

  /* Terminal-style header */
  .term-window {{
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 1.5rem;
    box-shadow: 0 0 30px rgba(0, 255, 127, 0.06);
  }}
  .term-bar {{
    background: #0d1710; padding: 0.55rem 0.9rem; display: flex; align-items: center; gap: 0.4rem;
    border-bottom: 1px solid var(--border);
  }}
  .term-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
  .term-dot.red {{ background: #ff5f56; }}
  .term-dot.yellow {{ background: #ffbd2e; }}
  .term-dot.green {{ background: #27c93f; }}
  .term-title {{ margin-left: 0.6rem; color: var(--text-dim); font-size: 0.78rem; }}
  .term-body {{ padding: 1.15rem 1.4rem; }}
  .term-body h1 {{
    margin: 0; font-size: 1.35rem; font-weight: 700; display: flex; align-items: baseline;
    gap: 0.4rem; flex-wrap: wrap;
  }}
  .prompt {{ color: var(--accent); }}
  .prompt-sep, .prompt-path {{ color: var(--text-dim); }}
  .target-name {{ color: var(--text); }}
  .cursor {{ display: inline-block; width: 0.5em; color: var(--accent); animation: blink 1s steps(1) infinite; }}
  @keyframes blink {{ 50% {{ opacity: 0; }} }}
  .meta {{ color: var(--text-dim); font-size: 0.82rem; margin-top: 0.4rem; }}

  /* Quick nav */
  .quick-nav {{
    position: sticky; top: 0.75rem; z-index: 10; display: flex; flex-wrap: wrap; gap: 0.25rem;
    background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
    padding: 0.5rem; margin-bottom: 2rem;
  }}
  .quick-nav a {{
    color: var(--text-dim); text-decoration: none; font-size: 0.76rem; padding: 0.3rem 0.6rem;
    border-radius: 4px; transition: background 0.15s, color 0.15s;
  }}
  .quick-nav a::before {{ content: "#"; margin-right: 0.15rem; opacity: 0.6; }}
  .quick-nav a:hover {{ color: var(--bg); background: var(--accent); }}

  h2 {{
    font-size: 1rem; letter-spacing: 0.03em; color: var(--accent); margin: 2.25rem 0 1rem;
    font-weight: 600; border-left: 3px solid var(--accent); padding-left: 0.6rem;
  }}
  .stat-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 0.75rem; margin-top: 1rem;
  }}
  .stat-card {{
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 1rem; text-align: center; text-decoration: none; color: inherit; display: block;
    transition: transform 0.15s, box-shadow 0.15s, border-color 0.15s; cursor: pointer;
  }}
  .stat-card:hover {{ transform: translateY(-3px); border-color: var(--accent); box-shadow: 0 0 18px var(--accent-glow); }}
  .stat-card.stat-alert {{ border-color: var(--danger); background: rgba(255, 92, 92, 0.08); }}
  .stat-value {{ font-size: 1.6rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.04em; margin-top: 0.25rem; }}

  input[type="text"] {{
    width: 100%; padding: 0.6rem 0.9rem; border-radius: var(--radius); border: 1px solid var(--border);
    background: var(--surface); color: var(--text); font-size: 0.85rem; font-family: var(--mono);
  }}
  input[type="text"]:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-glow); }}

  /* Contained scroll panels so long lists don't push the whole page down */
  .scroll-panel {{
    max-height: 420px; overflow-y: auto; border: 1px solid var(--border); border-radius: var(--radius);
    padding: 0.85rem; background: var(--surface);
  }}
  .scroll-panel::-webkit-scrollbar {{ width: 8px; }}
  .scroll-panel::-webkit-scrollbar-track {{ background: var(--surface); }}
  .scroll-panel::-webkit-scrollbar-thumb {{ background: var(--border-bright); border-radius: 4px; opacity: 0.5; }}

  .panel-toolbar {{ display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; margin-bottom: 0.75rem; }}
  .panel-toolbar input {{ flex: 1; min-width: 200px; margin-bottom: 0; }}
  .toolbar-buttons {{ display: flex; gap: 0.4rem; }}
  .btn-term {{
    background: var(--surface-alt); border: 1px solid var(--border); color: var(--accent);
    padding: 0.45rem 0.8rem; border-radius: 4px; font-family: var(--mono); font-size: 0.75rem;
    cursor: pointer; transition: border-color 0.15s, box-shadow 0.15s; white-space: nowrap;
  }}
  .btn-term:hover {{ border-color: var(--accent); box-shadow: 0 0 10px var(--accent-glow); }}

  #subdomain-filter {{ margin-bottom: 0.85rem; }}
  .chip-grid {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
  .chip {{
    display: inline-block; padding: 0.35rem 0.75rem; background: var(--surface-alt);
    border: 1px solid var(--border); border-radius: 999px; color: var(--accent);
    text-decoration: none; font-size: 0.82rem; transition: border-color 0.15s;
  }}
  .chip:hover {{ border-color: var(--accent); box-shadow: 0 0 8px var(--accent-glow); }}

  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: var(--radius); overflow: hidden; }}
  th, td {{ padding: 0.6rem 0.85rem; text-align: left; font-size: 0.85rem; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--surface-alt); color: var(--text-dim); font-weight: 600; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.04em; }}
  tr:last-child td {{ border-bottom: none; }}
  td a {{ color: var(--accent); text-decoration: none; word-break: break-all; }}
  td a:hover {{ text-decoration: underline; }}

  .badge {{ padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.76rem; font-weight: 600; }}
  .badge-ok {{ background: rgba(0, 255, 127, 0.15); color: var(--ok); }}
  .badge-redirect {{ background: rgba(255, 224, 102, 0.15); color: var(--redirect); }}
  .badge-client-error {{ background: rgba(255, 159, 67, 0.15); color: var(--client-error); }}
  .badge-server-error {{ background: rgba(255, 92, 92, 0.15); color: var(--server-error); }}
  .badge-unknown {{ background: rgba(93, 138, 107, 0.2); color: var(--text-dim); }}

  details.host-block {{
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    margin-bottom: 0.65rem; padding: 0.8rem 1rem;
  }}
  details.host-block:last-child {{ margin-bottom: 0; }}
  details.host-block summary {{ cursor: pointer; font-weight: 600; list-style: none; display: flex; align-items: center; gap: 0.6rem; }}
  details.host-block summary::-webkit-details-marker {{ display: none; }}
  details.host-block summary::before {{ content: "▸"; color: var(--accent); transition: transform 0.15s; }}
  details.host-block[open] summary::before {{ transform: rotate(90deg); }}
  details.host-block table {{ margin-top: 0.75rem; }}
  .count-pill {{ font-size: 0.7rem; font-weight: 600; color: var(--text-dim); background: var(--surface-alt); padding: 0.1rem 0.5rem; border-radius: 999px; }}
  .os-guess {{ color: var(--text-dim); font-size: 0.82rem; margin: 0.4rem 0 0; }}

  .tag {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.72rem; font-weight: 600; margin: 0.1rem; }}
  .tag-danger {{ background: rgba(255, 92, 92, 0.15); color: var(--danger); }}
  .tag-safe {{ background: rgba(0, 255, 127, 0.12); color: var(--safe); }}
  tr.row-alert {{ background: rgba(255, 92, 92, 0.06); }}

  /* Screenshot slideshow */
  .slideshow {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem; }}
  .slide-viewport {{
    position: relative; display: flex; align-items: center; justify-content: center;
    background: #000; border-radius: 4px; min-height: 280px; overflow: hidden;
  }}
  #slide-image {{ max-width: 100%; max-height: 480px; object-fit: contain; display: block; }}
  .slide-nav {{
    position: absolute; top: 50%; transform: translateY(-50%); background: rgba(0,0,0,0.55);
    border: 1px solid var(--border-bright); color: var(--accent); width: 38px; height: 38px;
    border-radius: 50%; cursor: pointer; font-size: 1rem; display: flex; align-items: center;
    justify-content: center; transition: background 0.15s, box-shadow 0.15s;
  }}
  .slide-nav:hover {{ background: rgba(0,255,127,0.2); box-shadow: 0 0 12px var(--accent-glow); }}
  .slide-nav.prev {{ left: 0.75rem; }}
  .slide-nav.next {{ right: 0.75rem; }}
  .slide-counter {{
    position: absolute; top: 0.6rem; right: 0.75rem; background: rgba(0,0,0,0.6); color: var(--accent);
    font-size: 0.72rem; padding: 0.2rem 0.55rem; border-radius: 999px;
  }}
  .slide-caption {{ text-align: center; margin-top: 0.75rem; color: var(--text-dim); font-size: 0.82rem; word-break: break-all; }}
  .slide-dots {{ display: flex; justify-content: center; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.75rem; }}
  .dot {{ width: 9px; height: 9px; border-radius: 50%; border: 1px solid var(--border-bright); background: transparent; cursor: pointer; padding: 0; }}
  .dot.active {{ background: var(--accent); box-shadow: 0 0 6px var(--accent-glow); }}

  .empty {{ color: var(--text-dim); font-style: italic; font-size: 0.88rem; }}
  footer {{ margin-top: 3rem; padding-top: 1.25rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.78rem; }}
</style>
</head>
<body>
<div class="wrap">

  <div class="term-window">
    <div class="term-bar">
      <span class="term-dot red"></span><span class="term-dot yellow"></span><span class="term-dot green"></span>
      <span class="term-title">recon@framework:~/{e(summary.scan_id)}</span>
    </div>
    <div class="term-body">
      <h1>
        <span class="prompt">root@recon</span><span class="prompt-sep">:</span><span class="prompt-path">~$</span>
        <span class="target-name">recon {e(summary.target)}</span><span class="cursor">&#9608;</span>
      </h1>
      <div class="meta">Scan ID: {e(summary.scan_id)} &middot; Duration: {e(format_duration(summary.duration_seconds))}</div>
    </div>
  </div>

  <nav class="quick-nav">
    <a href="#overview">overview</a>
    <a href="#subdomains">subdomains</a>
    <a href="#alive-hosts">alive_hosts</a>
    <a href="#open-ports">open_ports</a>
    <a href="#js-findings">js_findings</a>
    <a href="#screenshots">screenshots</a>
  </nav>

  <section id="overview">
    <h2>// Overview</h2>
    <div class="stat-grid">{stat_cards}</div>
  </section>

  <section id="subdomains">
    <h2>// Subdomains ({len(summary.subdomains)})</h2>
    <input type="text" id="subdomain-filter" placeholder="Filter subdomains..." oninput="filterSubdomains(this.value)">
    <div class="scroll-panel">
      <div class="chip-grid" id="subdomain-chips">{subdomain_chips}</div>
    </div>
  </section>

  <section id="alive-hosts">
    <h2>// Alive Hosts ({len(summary.alive_hosts)})</h2>
    {alive_table}
  </section>

  <section id="open-ports">
    <h2>// Open Ports</h2>
    <div class="panel-toolbar">
      <input type="text" id="port-filter" placeholder="Filter hosts..." oninput="filterPorts(this.value)">
      <div class="toolbar-buttons">
        <button class="btn-term" onclick="toggleAllDetails(true)">Expand All</button>
        <button class="btn-term" onclick="toggleAllDetails(false)">Collapse All</button>
      </div>
    </div>
    <div class="scroll-panel" id="port-panel">{port_sections}</div>
  </section>

  <section id="js-findings">
    <h2>// JavaScript Findings</h2>
    {js_table}
  </section>

  <section id="screenshots">
    <h2>// Screenshots ({len(screenshots)})</h2>
    {gallery}
  </section>

  <footer>
    Generated by Automated Recon Framework. For authorized security testing only.
  </footer>

</div>

<script type="application/json" id="scan-data">{raw_json}</script>
<script type="application/json" id="screenshot-data">{screenshot_json}</script>
<script>
  function filterSubdomains(query) {{
    const q = query.trim().toLowerCase();
    document.querySelectorAll('#subdomain-chips .chip').forEach(function (chip) {{
      const match = chip.getAttribute('data-filter').includes(q);
      chip.style.display = match ? 'inline-block' : 'none';
    }});
  }}

  function filterPorts(query) {{
    const q = query.trim().toLowerCase();
    document.querySelectorAll('#port-panel .host-block').forEach(function (block) {{
      const match = block.getAttribute('data-filter').includes(q);
      block.style.display = match ? 'block' : 'none';
    }});
  }}

  function toggleAllDetails(state) {{
    document.querySelectorAll('#port-panel .host-block').forEach(function (d) {{ d.open = state; }});
  }}

  (function initSlideshow() {{
    const dataEl = document.getElementById('screenshot-data');
    if (!dataEl) return;
    let slides = [];
    try {{ slides = JSON.parse(dataEl.textContent || '[]'); }} catch (err) {{ slides = []; }}
    if (!slides.length) return;

    let idx = 0;
    const img = document.getElementById('slide-image');
    const caption = document.getElementById('slide-caption');
    const counter = document.getElementById('slide-index');
    const dotsWrap = document.getElementById('slide-dots');

    slides.forEach(function (_, i) {{
      const dot = document.createElement('button');
      dot.className = 'dot';
      dot.setAttribute('aria-label', 'Screenshot ' + (i + 1));
      dot.onclick = function () {{ goToSlide(i); }};
      dotsWrap.appendChild(dot);
    }});

    function render() {{
      img.src = slides[idx].data_uri;
      img.alt = slides[idx].name;
      caption.textContent = slides[idx].name;
      counter.textContent = String(idx + 1);
      document.querySelectorAll('#slide-dots .dot').forEach(function (d, i) {{
        d.classList.toggle('active', i === idx);
      }});
    }}

    window.changeSlide = function (delta) {{
      idx = (idx + delta + slides.length) % slides.length;
      render();
    }};
    window.goToSlide = function (i) {{
      idx = i;
      render();
    }};

    document.addEventListener('keydown', function (e) {{
      if (e.key === 'ArrowLeft') window.changeSlide(-1);
      if (e.key === 'ArrowRight') window.changeSlide(1);
    }});

    render();
  }})();
</script>
</body>
</html>
"""

    output_path = report_dir / "report.html"
    output_path.write_text(html_doc, encoding="utf-8")
    logger.info("Report generated: %s", output_path)
    return output_path
