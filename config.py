"""Central configuration for the Recon Framework.

All tunable defaults (timeouts, thread counts, tool paths, wordlists,
etc.) live here so that other modules never hardcode these values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Project root, resolved relative to this file so the framework works
# regardless of the current working directory it is invoked from.
BASE_DIR: Path = Path(__file__).resolve().parent
REPORTS_DIR: Path = BASE_DIR / "reports"
TOOLS_DIR: Path = BASE_DIR / "tools"
WORDLISTS_DIR: Path = TOOLS_DIR / "wordlists"

DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) ReconFramework/0.1.0"
)


@dataclass(frozen=True)
class ToolPaths:
    """Executable names/paths for external tools used by the framework.

    Defaults assume each tool is available on the system ``PATH``. Override
    any field to point at a specific binary location.
    """

    subfinder: str = "subfinder"
    amass: str = "amass"
    assetfinder: str = "assetfinder"
    httpx: str = "httpx"
    nmap: str = "nmap"
    ffuf: str = "ffuf"
    katana: str = "katana"
    gau: str = "gau"
    waybackurls: str = "waybackurls"
    gowitness: str = "gowitness"


@dataclass(frozen=True)
class Config:
    """Runtime configuration for a recon scan.

    Attributes:
        timeout: Per-command timeout in seconds for external tool calls.
        threads: Number of worker threads for concurrent operations.
        reports_dir: Root directory under which per-target reports are stored.
        tools_dir: Directory where optional bundled tools/binaries live.
        wordlists_dir: Directory containing wordlists for enumeration/fuzzing.
        user_agent: Default User-Agent header for HTTP requests.
        log_level: Default logging level name.
        tool_paths: Executable names/paths for external tools.
        default_wordlist: Wordlist file used for directory enumeration.
        directory_scan_timeout: Overall timeout for directory enumeration.
        screenshot_timeout: Per-host timeout for screenshot capture.
    """

    timeout: int = 20
    threads: int = 50
    reports_dir: Path = field(default_factory=lambda: REPORTS_DIR)
    tools_dir: Path = field(default_factory=lambda: TOOLS_DIR)
    wordlists_dir: Path = field(default_factory=lambda: WORDLISTS_DIR)
    user_agent: str = DEFAULT_USER_AGENT
    log_level: str = "INFO"
    tool_paths: ToolPaths = field(default_factory=ToolPaths)
    default_wordlist: Path = field(
        default_factory=lambda: WORDLISTS_DIR / "common.txt"
    )
    directory_scan_timeout: int = 120
    screenshot_timeout: int = 60


def load_config(**overrides: object) -> Config:
    """Build a :class:`Config`, applying any keyword overrides.

    Args:
        **overrides: Field names and values to override the defaults with.
            Unknown keys are ignored with a warning printed to stderr.

    Returns:
        A fully-populated :class:`Config` instance.
    """
    valid_fields = {f for f in Config.__dataclass_fields__}
    filtered = {k: v for k, v in overrides.items() if k in valid_fields}
    return Config(**filtered)
