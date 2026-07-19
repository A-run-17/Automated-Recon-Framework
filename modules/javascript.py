"""
JavaScript analysis module.

Collects JavaScript files reachable from live hosts and statically scans
them for endpoints, likely secrets, API keys, and other interesting
URLs using regular expression heuristics.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from config import Config
from utils.helpers import write_json

logger = logging.getLogger(__name__)

# Heuristic patterns for interesting findings inside JS source.
_ENDPOINT_PATTERN = re.compile(r"""["'](/[a-zA-Z0-9_\-/.]{2,}?)["']""")
_URL_PATTERN = re.compile(r"""["'](https?://[^\s"'<>]{4,})["']""")

_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key": re.compile(
        r"""(?i)api[_-]?key["'\s:=]{1,5}["']([A-Za-z0-9_\-]{16,45})["']"""
    ),
    "bearer_token": re.compile(r"""(?i)bearer\s+[A-Za-z0-9\-_.=]{10,}"""),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
}


@dataclass
class JsFinding:
    """Findings extracted from a single JavaScript file.

    Attributes:
        source_url: URL of the JavaScript file that was analyzed.
        endpoints: Relative endpoint paths found in the source.
        urls: Absolute URLs found in the source.
        secrets: Mapping of secret type to list of matched values
            (values are truncated for safety/readability).
    """

    source_url: str
    endpoints: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    secrets: dict[str, list[str]] = field(default_factory=dict)


def discover_js_files(html: str, base_url: str) -> list[str]:
    """Extract JavaScript file URLs referenced in an HTML document.

    Args:
        html: Raw HTML content of a page.
        base_url: The URL the HTML was fetched from, used to resolve
            relative script paths.

    Returns:
        A list of absolute JavaScript file URLs.
    """
    from urllib.parse import urljoin

    script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", html, re.IGNORECASE)
    return sorted({urljoin(base_url, src) for src in script_srcs})


def _fetch(url: str, timeout: int, user_agent: str) -> str | None:
    """Fetch a URL's text content, returning None on any failure."""
    try:
        request = Request(url, headers={"User-Agent": user_agent})
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - intended HTTP fetch
            raw = response.read(2_000_000)  # cap at ~2MB per file
            return raw.decode("utf-8", errors="ignore")
    except (URLError, HTTPError, ValueError, TimeoutError) as exc:
        logger.debug("Failed to fetch %s: %s", url, exc)
        return None


def analyze_js_source(source_url: str, source: str) -> JsFinding:
    """Statically analyze JavaScript source for endpoints and secrets.

    Args:
        source_url: URL the source was retrieved from.
        source: Raw JavaScript source text.

    Returns:
        A :class:`JsFinding` describing what was discovered.
    """
    endpoints = sorted(set(_ENDPOINT_PATTERN.findall(source)))
    urls = sorted(set(_URL_PATTERN.findall(source)))

    secrets: dict[str, list[str]] = {}
    for label, pattern in _SECRET_PATTERNS.items():
        matches = pattern.findall(source)
        if matches:
            # findall on a pattern with one group returns the group; otherwise
            # the whole match. Normalize to strings and truncate for display.
            normalized = [m if isinstance(m, str) else m[0] for m in matches]
            secrets[label] = sorted({m[:60] for m in normalized})

    return JsFinding(source_url=source_url, endpoints=endpoints, urls=urls, secrets=secrets)


def analyze_hosts(hosts: list[str], report_dir: Path, config: Config) -> list[JsFinding]:
    """Discover and analyze JavaScript files across a list of live hosts.

    For each host, fetches the root page, extracts referenced JS files,
    downloads each one, and runs static analysis for endpoints, URLs,
    and likely secrets.

    Args:
        hosts: Live host URLs (typically from :mod:`modules.http_probe`).
        report_dir: Directory to write ``javascript.json`` into.
        config: Active :class:`~config.Config`.

    Returns:
        A list of :class:`JsFinding`, one per discovered JS file.
    """
    findings: list[JsFinding] = []
    seen_js_urls: set[str] = set()

    for host in hosts:
        page_html = _fetch(host, config.timeout, config.user_agent)
        if page_html is None:
            continue

        js_urls = discover_js_files(page_html, host)
        for js_url in js_urls:
            if js_url in seen_js_urls:
                continue
            seen_js_urls.add(js_url)

            js_source = _fetch(js_url, config.timeout, config.user_agent)
            if js_source is None:
                continue

            finding = analyze_js_source(js_url, js_source)
            if finding.endpoints or finding.urls or finding.secrets:
                findings.append(finding)

    write_json(report_dir / "javascript.json", [asdict(f) for f in findings])

    total_secrets = sum(len(f.secrets) for f in findings)
    logger.info(
        "JavaScript analysis complete: %d file(s) analyzed, %d with possible secrets",
        len(findings),
        total_secrets,
    )
    return findings
