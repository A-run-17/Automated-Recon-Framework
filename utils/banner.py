"""
ASCII startup banner for the Recon Framework."""

from __future__ import annotations

_BANNER = r"""
 ____
|  _ \ ___  ___ ___  _ __
| |_) / _ \/ __/ _ \| '_ \
|  _ <  __/ (_| (_) | | | |
|_| \_\___|\___\___/|_| |_|
   Automated Recon Framework
"""

_VERSION = "0.1.1"
_TAGLINE = "For authorized security testing and bug bounty use only."


def print_banner(version: str = _VERSION) -> None:
    """Print the ASCII startup banner to stdout.

    Args:
        version: Version string to display beneath the banner art.
    """
    print(_BANNER)
    print(f"  v{version}  |  {_TAGLINE}\n")
