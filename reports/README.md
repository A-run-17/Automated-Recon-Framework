# Recon Reports — example.com

This folder contains the output of an automated reconnaissance run against `example.com`. It includes raw scan input, subdomain enumeration results, liveness checks, and port scan data in both machine-readable (`.json`) and human-readable (`.txt`) formats.

## Contents

| File | Format | Description |
|---|---|---|
| `input.json` | JSON | Initial scan configuration — target domain(s), modules enabled, and any options/flags passed to the framework at run time. |
| `subdomains.txt` | Text | Flat list of subdomains discovered for `example.com` via enumeration (e.g. certificate transparency logs, DNS brute-forcing, passive sources). |
| `alive.txt` | Text | Subset of `subdomains.txt` confirmed reachable (resolves and/or responds over HTTP/HTTPS). |
| `alive.json` | JSON | Structured version of `alive.txt` — typically includes per-host metadata such as status code, response headers, title, or technology fingerprint, depending on the probing tool used. |
| `ports.txt` | Text | Human-readable list of open ports discovered per live host. |
| `ports.json` | JSON | Structured port scan results — host, port, protocol, and (if available) detected service/version. |
| `scan.log` | Text | Raw execution log of the recon run — timestamps, module start/end, errors, warnings, and tool output for debugging or audit purposes. |

## Suggested Workflow

1. **`input.json`** — confirms exactly what was scanned and with what settings (useful for reproducing or auditing the run).
2. **`subdomains.txt`** → **`alive.txt` / `alive.json`** — enumeration output is filtered down to hosts that actually responded.
3. **`alive.*`** → **`ports.txt` / `ports.json`** — port scanning is run against the live host set only.
4. **`scan.log`** — cross-reference here if any file looks incomplete or a module appears to have failed mid-run.

## Notes

- `example.com` is used here as a test target — this framework can be pointed at any domain.
- JSON files are intended for programmatic parsing (e.g. feeding into further tooling, dashboards, or diffing between scans); `.txt` counterparts are for quick manual review.
- File contents will vary slightly depending on which modules/tools are wired into the framework (e.g. `subfinder`/`amass` for subdomains, `httpx` for liveness, `naabu`/`nmap` for ports) — update this README if the underlying tool or output schema changes.

## HTML Report 



https://github.com/user-attachments/assets/d2b009ac-36a2-460e-8958-535e13ed2d94



