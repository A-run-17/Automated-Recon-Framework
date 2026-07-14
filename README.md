# Recon Framework

> A modular Python-based reconnaissance framework that automates information gathering for ethical hacking, bug bounty hunting, and security assessments.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-orange)

---

## 📖 Overview

Recon Framework is an open-source Python project that automates the reconnaissance phase of penetration testing and bug bounty hunting.

Instead of manually running multiple tools, Recon Framework provides a unified interface to perform reconnaissance tasks and organize the results into structured reports.

The framework is designed with a modular architecture, making it easy to add new reconnaissance modules as the project grows.

---

## ✨ Features

- Clean and modular architecture
- Command-line interface (CLI)
- Target validation and normalization
- Automatic report generation
- Organized scan directories
- Easy integration with third-party reconnaissance tools
- Extensible plugin-like module system

---

## 🚀 Planned Features

### Information Gathering

- [ ] Subdomain Enumeration
- [ ] Passive OSINT
- [ ] DNS Enumeration
- [ ] WHOIS Lookup
- [ ] ASN Enumeration

### Host Discovery

- [ ] Live Host Detection
- [ ] HTTP Probing
- [ ] Technology Detection
- [ ] SSL Analysis

### Scanning

- [ ] Port Scanning
- [ ] Service Detection
- [ ] Banner Grabbing
- [ ] Directory Enumeration
- [ ] Historical URL Collection

### JavaScript Analysis

- [ ] Endpoint Discovery
- [ ] Secret Detection
- [ ] API Key Discovery

### Reporting

- [ ] HTML Report
- [ ] JSON Report
- [ ] CSV Export
- [ ] Markdown Report

### Quality of Life

- [ ] Configuration File
- [ ] Logging
- [ ] Parallel Scanning
- [ ] Resume Previous Scans
- [ ] Progress Bars

---

## 📂 Project Structure

```text
Automated-Recon-Framework/
│
├── recon.py
├── config.py
├── requirements.txt
│
├── modules/
│   ├── __init__.py
│   ├── http_probe.py
│   ├── input_module.py
│   ├── javascript.py
│   ├── port_scan.py
│   ├── report.py
│   ├── screenshots.py
│   └── subdomain.py
│
├── reports/
│
├── tools/
│
├── utils
|   ├── __init__.py
|   ├── banner.py
|   ├── helpers.py
|   ├── logger.py
|   └── validator.py
│
└── README.md
```

---

## 🛠 Installation

Clone the repository

```bash
git clone https://github.com/A-run_17/Automated-Recon-Framework.git
```

Navigate to the project

```bash
cd ReconFramework
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## ⚡ Usage

Run the framework

```bash
python recon.py example.com
```

or

```bash
python recon.py https://example.com
```

Future commands

```bash
python recon.py example.com --full
python recon.py example.com --ports
python recon.py example.com --screenshots
```

---

## 📁 Output

Each scan creates its own report directory.

```text
reports/
└── example.com/
    ├── input.json
    ├── subdomains.txt
    ├── alive.txt
    ├── ports.txt
    ├── urls.txt
    ├── screenshots/
    └── report.html
```

---

## 🧱 Architecture

```text
User
 │
 ▼
Input Module
 │
 ▼
Subdomain Enumeration
 │
 ▼
Host Discovery
 │
 ▼
Port Scanning
 │
 ▼
Service Detection
 │
 ▼
Directory Enumeration
 │
 ▼
JavaScript Analysis
 │
 ▼
Report Generator
```

---

## 🧰 Planned Tool Integrations

| Tool | Purpose |
|------|---------|
| Subfinder | Subdomain Enumeration |
| Amass | Asset Discovery |
| Assetfinder | Passive Enumeration |
| httpx | Live Host Detection |
| Nmap | Port Scanning |
| RustScan | Fast Port Scanning |
| ffuf | Directory Enumeration |
| Katana | Web Crawling |
| gau | Historical URLs |
| waybackurls | Archived URLs |
| gowitness | Screenshots |

---

## 🎯 Project Goals

- Build a production-quality reconnaissance framework
- Learn software architecture through a real-world cybersecurity project
- Automate repetitive reconnaissance tasks
- Create a tool useful for bug bounty hunting and penetration testing
- Maintain clean, modular, and well-documented code

---

## 🤝 Contributing

Contributions are welcome!

If you'd like to improve the project, feel free to fork the repository, create a feature branch, and submit a pull request.

---

## ⭐ Support

If you find this project useful, consider giving it a ⭐ on GitHub.

It helps others discover the project and motivates future development.
