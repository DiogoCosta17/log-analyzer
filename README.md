# Log Analyzer

A CLI cybersecurity log analysis tool that detects threats in Apache, Nginx, SSH,
syslog, and Windows Event logs.

## Install

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Analyze an Apache/Nginx access log (format auto-detected)
python log_analyzer.py --file access.log

# SSH auth.log with explicit format
python log_analyzer.py --file /var/log/auth.log --format ssh

# Export to JSON + HTML (files saved alongside the log)
python log_analyzer.py --file access.log --export json --export html

# Export CSV of suspicious IPs only
python log_analyzer.py --file access.log --export csv

# Skip geolocation (faster, no internet needed)
python log_analyzer.py --file access.log --no-geo

# Watch mode — tail the file in real time
python log_analyzer.py --file access.log --watch

# Compare two log files and show what changed
python log_analyzer.py --file access_today.log --diff access_yesterday.log

# Custom thresholds and time window
python log_analyzer.py --file access.log \
  --threshold 50 \
  --brute-threshold 3 \
  --brute-window 5 \
  --suspicious-hours 22-6

# Apply IP whitelist and blacklist
python log_analyzer.py --file access.log \
  --whitelist config/whitelist.txt \
  --blacklist config/blacklist.txt

# Export all formats to a custom output path
python log_analyzer.py --file access.log \
  --output /reports/june-15 \
  --export json --export csv --export html
```

## Supported Log Formats

| Format | Example file | Detection |
|--------|-------------|-----------|
| Apache / Nginx Combined | `access.log` | Auto |
| SSH auth.log | `/var/log/auth.log` | Auto |
| Syslog (RFC 3164 & 5424) | `/var/log/syslog` | Auto |
| Windows Event Log (text export) | `security.log` | Auto |
| Compressed files | `access.log.gz` | Transparent |

Use `--format auto` (default) or specify explicitly:
`apache`, `nginx`, `ssh`, `syslog`, `windows`.

## Threat Detection

| Threat | Severity | Trigger |
|--------|----------|---------|
| SSH brute force | HIGH / CRITICAL | >5 failed logins per IP in 10 min |
| HTTP brute force | HIGH / CRITICAL | >5 × 401 responses per IP in 10 min |
| Endpoint scan | MEDIUM / HIGH | >20 unique paths per IP in 5 min |
| SQL Injection | CRITICAL | 20+ known SQLi patterns in URL/params |
| XSS | HIGH | 13+ known XSS patterns |
| Directory traversal | HIGH | `../`, `/etc/passwd`, `win.ini`, etc. |
| Scanner user-agents | MEDIUM | nikto, sqlmap, nmap, masscan, gobuster, … |
| High request rate | MEDIUM / HIGH | Configurable (default 100 req per IP) |
| HTTP error spike | LOW / MEDIUM | ≥10 4xx/5xx responses from same IP |
| Off-hours activity | LOW | Configurable hour range (default 00–06) |
| Blacklisted IPs | CRITICAL | Any IP listed in `--blacklist` file |

## CLI Reference

```
Options:
  -f, --file TEXT                Log file to analyze  [required]
  -F, --format [auto|apache|nginx|ssh|syslog|windows]
                                 Force log format  [default: auto]
  -o, --output TEXT              Base path for exported files
  -e, --export [json|csv|html]   Export format (repeatable)
  -t, --threshold INTEGER        Request-rate alert threshold  [default: 100]
      --brute-threshold INTEGER  Failed login threshold  [default: 5]
      --brute-window INTEGER     Brute-force window (minutes)  [default: 10]
      --scan-threshold INTEGER   Unique endpoint scan threshold  [default: 20]
      --suspicious-hours TEXT    Off-hours range HH-HH  [default: 0-6]
      --top-n INTEGER            Top IPs / endpoints to display  [default: 10]
      --whitelist FILE           File of whitelisted IPs
      --blacklist FILE           File of blacklisted IPs
      --diff FILE                Second log to compare against
      --no-geo                   Skip geolocation (faster)
  -w, --watch                    Real-time tail / watch mode
  -h, --help                     Show this message and exit
```

## Exported Files

| Format | Content |
|--------|---------|
| `*_report.json` | Full report: stats, threats, geo data |
| `*_suspicious_ips.csv` | Per-IP table: requests, threats, geo, severity |
| `*_report.html` | Standalone dark-theme HTML dashboard |

## Project Structure

```
log_analyzer.py          # CLI entry point
modules/
  parser.py              # Log format detection & parsing
  detector.py            # Threat detection engine
  reporter.py            # Terminal / JSON / CSV / HTML output
  geoip.py               # IP geolocation (ip-api.com)
  watcher.py             # Real-time file monitoring
config/
  whitelist.txt          # IPs to exclude from analysis
  blacklist.txt          # IPs to flag as CRITICAL
requirements.txt
```

## IP Whitelist / Blacklist

Plain text files, one IP per line. Lines starting with `#` are comments.

```
# config/whitelist.txt
10.0.0.1       # internal monitoring
192.168.1.1    # office gateway
```

```
# config/blacklist.txt
198.51.100.99  # known threat actor
```

## Geolocation

Uses the free [ip-api.com](http://ip-api.com) batch API (no API key required).
Private / RFC 1918 addresses are skipped automatically.
Pass `--no-geo` to disable entirely.

## Watch Mode

Monitors the file for new lines and prints real-time threat alerts:

```
python log_analyzer.py --file access.log --watch
```

Output format:
```
10:23:45  [HIGH]  Brute Force  10.0.0.1  — HTTP brute force: 7 401 responses within 10 minutes
```

## Requirements

- Python 3.9+
- Windows 10 / Linux / macOS
