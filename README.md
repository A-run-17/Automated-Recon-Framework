# Automated Recon Framework CLI

A modular Python reconnaissance framework for authorized security testing and bug bounty hunting. Orchestrates industry-standard recon tools behind a single CLI and produces structured HTML, JSON.


![Python](https://img.shields.io/badge/Python-3.11+-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

- Subdomain enumeration (Subfinder, Amass, Assetfinder)
- HTTP probing with technology detection (httpx)
- Port and service scanning (Nmap)
- JavaScript endpoint and secret discovery
- Screenshot capture (GoWitness)
- HTML / JSON / Markdown report generation
- Graceful degradation — any missing tool is skipped, not fatal

## Requirements

- Python 3.11+
- One or more of the external tools listed below (each is optional; a stage is skipped with a warning if its tool isn't installed)

| Tool | Purpose | Install |
|---|---|---|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [Amass](https://github.com/owasp-amass/amass) | Asset discovery | `go install github.com/owasp-amass/amass/v4/...@master` |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) | Passive enumeration | `go install github.com/tomnomnom/assetfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [Nmap](https://nmap.org/) | Port scanning | `apt install nmap` / `brew install nmap` |
| [GoWitness](https://github.com/sensepost/gowitness) | Screenshots | `go install github.com/sensepost/gowitness@latest` |

## Installation

```bash
# Clone the repository
git clone https://github.com/A-run-17/Automated-Recon-Framework.git

# Navigate into the project directory
cd Automated-Recon-Framework

# Install dependencies
chmod +x install.sh

# Restart the terminal and Run the tool
recon example.com
```

> Follow as instructed after running the `install.sh` file and restart the terminal. Then run the `recon` command at the desired directory for reports.

## Usage

```bash
recon example.com                 # run all stages (default)
recon example.com --full          # explicit full scan
recon example.com --subdomains    # subdomain enumeration only
recon example.com --http          # HTTP probing only
recon example.com --ports         # port scanning only
recon example.com --javascript    # JavaScript analysis only
recon example.com --screenshots   # screenshots only
recon example.com --report        # regenerate reports only
recon example.com --threads 50 --timeout 20
```

Accepted targets: domains, URLs, IPv4/IPv6 addresses, and CIDR ranges. Subdomain enumeration runs only for domain targets.

## Output

Each run creates a timestamped report directory:

```
reports/
└── example.com/
    └── 20260712-093015-a1b2c3/
        ├── input.json
        ├── subdomains.txt
        ├── alive.txt / alive.json
        ├── ports.txt / ports.json
        ├── javascript.json
        ├── screenshots/
        ├── scan.log
        └── report.html 
```

## Project Structure

```
Automated-Recon-Framework/
├── recon.py                # CLI entry point
├── config.py               # Central configuration
├── requirements.txt
├── install.sh              # Installing dependencies
├── installation.md         # Detailed manual instructions for installing (.gitignored)
├── modules/
│   ├── input_module.py     # Target validation, scan setup
│   ├── subdomain.py        # Subfinder / Amass / Assetfinder
│   ├── http_probe.py       # httpx liveness + tech detection
│   ├── port_scan.py        # Nmap service/version scanning
│   ├── javascript.py       # JS endpoint & secret discovery
│   ├── screenshots.py      # GoWitness screenshot capture
│   └── report.py           # Report generation
├── utils/
│   ├── logger.py
│   ├── validator.py
│   ├── helpers.py
│   └── banner.py
├── tools/                  # Optional bundled tools / wordlists
└── reports/                # Sample output (.gitignored)
```

---

## Project Goals

- Build a production-quality reconnaissance framework
- Automate repetitive reconnaissance tasks
- Create a tool useful for bug bounty hunting and penetration testing
- Maintain clean, modular, and well-documented code

---
## Configuration

Defaults (timeout, thread count, tool paths, User-Agent, log level) live in `config.py` and can be overridden via CLI flags.

## Contributing

If you'd like to improve the project, feel free to fork the repository, create a feature branch, and submit a pull request.
