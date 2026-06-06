# 📊 SOC Log Analyzer

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

> Detects suspicious activity in Linux system logs using pattern matching and threat detection.

## Overview
Analyzes auth logs, web server logs, and syslog files for security threats including SSH brute force attacks, SQL injection attempts, XSS payloads, and system anomalies. Generates color-coded terminal alerts and JSON reports for SOC teams.

## Features
- **Auth Log Analysis** – Detects SSH brute force, invalid usernames, root logins, and privilege escalation
- **Web Log Analysis** – Identifies SQL injection, XSS, path traversal, and automated scanner activity
- **Syslog Scanning** – Captures out-of-memory events, segmentation faults, and service failures
- **Configurable Thresholds** – Tune detection sensitivity for your environment
- **JSON Reports** – Exports findings with timestamps for compliance and incident response
- **Sample Generator** – Built-in test logs for quick validation

## Prerequisites
- Python 3.10+
- Log files from:
  - Linux auth.log (or /var/log/secure)
  - Apache/Nginx access logs (combined format)
  - Syslog (/var/log/syslog or /var/log/messages)

## Installation
```bash
git clone https://github.com/aadharsh99/Projects.git
cd Projects
python log_analyzer.py --help
```

## Usage

**Analyze auth logs:**
```bash
python log_analyzer.py --auth /var/log/auth.log
```

**Analyze web access logs:**
```bash
python log_analyzer.py --web /var/log/nginx/access.log
```

**Analyze syslog:**
```bash
python log_analyzer.py --syslog /var/log/syslog
```

**Analyze all logs at once:**
```bash
python log_analyzer.py --auth auth.log --web access.log --syslog syslog
```

**Generate sample logs for testing:**
```bash
python log_analyzer.py --sample
```

### Example Output
```
════════════════════════════════════════════════════════════
  SOC Log Analyzer
  2024-01-15 14:32:01
════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────
 Auth Log  →  samples/auth.log
────────────────────────────────────────────────────────────
  [INFO] Looking for SSH brute force attacks (trigger: 5+ failures from one IP)
  [ALERT] Brute force from 192.168.1.100 — 6 failed attempts
  [WARN] A few failed logins from 192.168.1.200 (2 attempts)
  [OK] Logged in: admin from 10.0.0.5
  [ALERT] Someone logged in directly as root from 203.0.113.50
  [INFO] 1 sudo command(s) run:
    sudo: /bin/bash

────────────────────────────────────────────────────────────
 Web Access Log  →  samples/access.log
────────────────────────────────────────────────────────────
  [ALERT] SQL injection attempt — 192.168.1.50  →  /index.php?id=1 union select 1,2,3--
  [ALERT] XSS attempt — 10.0.0.20  →  /search?q=<script>alert(1)</script>
  [ALERT] Path traversal — 172.16.0.5  →  /../../../../etc/passwd
  [ALERT] Scanner detected — sqlmap/1.7 from 203.0.113.99
  [OK] No other suspicious patterns found

────────────────────────────────────────────────────────────
 Syslog  →  samples/syslog
────────────────────────────────────────────────────────────
  [ALERT] Out-of-memory event: kernel: Out of memory: Kill process
  [WARN] Segfault detected: segfault at 0 ip 00007f
  [INFO] Out-of-memory events : 1
  [INFO] Segfaults            : 1
  [INFO] Cron jobs seen       : 1
  [INFO] Service failures     : 1

────────────────────────────────────────────────────────────
 Scan Summary
────────────────────────────────────────────────────────────
  Total findings : 13
  Critical : 7
  Warnings : 3
  Info     : 3

  Things that need your attention:
    • [SSH Brute Force] 192.168.1.100 made 6 failed login attempts
    • [SQL Injection] 192.168.1.50 tried: /index.php?id=1 union select 1,2,3--
    • [XSS Attempt] 10.0.0.20 tried: /search?q=<script>alert(1)</script>
    • [Path Traversal] 172.16.0.5 tried: /../../../../etc/passwd
    • [Scanner Detected] sqlmap/1.7 from 203.0.113.99
    • [Root Login] Root account accessed directly from 203.0.113.50
    • [OOM Killer] kernel: Out of memory: Kill process

  Full report saved to: log_analysis_20240115_143201.json
```

## Report Output
The tool generates a timestamped JSON report with all findings:

```json
{
  "scanned_at": "20240115_143201",
  "summary": {
    "critical": 7,
    "warnings": 3,
    "info": 3
  },
  "findings": [
    {
      "severity": "alert",
      "category": "SSH Brute Force",
      "detail": "192.168.1.100 made 6 failed login attempts",
      "raw_line": "Dec  1 10:01:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
    },
    {
      "severity": "alert",
      "category": "SQL Injection",
      "detail": "192.168.1.50 tried: /index.php?id=1 union select 1,2,3--",
      "raw_line": "192.168.1.50 - - [01/Dec/2025:10:00:01 +0000] \"GET /index.php?id=1 union select 1,2,3-- HTTP/1.1\" 200"
    }
  ]
}
```

## Configuration
Edit these thresholds in the script to adjust detection sensitivity:

```python
BRUTE_FORCE_THRESHOLD = 5    # failed SSH logins from one IP
PORT_SCAN_THRESHOLD   = 10   # suspicious connection attempts
WEB_SCAN_THRESHOLD    = 20   # automated web requests from one IP
```

## Log Format Support
- **Auth logs:** Standard Linux sshd format (auth.log, secure)
- **Web logs:** Apache/Nginx combined format
- **Syslog:** Standard syslog format

## Technologies
| Library | Purpose |
|---------|---------|
| re | Pattern matching for threat detection |
| json | Report generation |
| argparse | Command-line interface |
| pathlib | File handling |
| collections | Tracking IP-based statistics |
| datetime | Timestamp generation |

## Key Takeaways
- **Run daily** – Analyze logs overnight to catch attacks from the previous day
- **Critical alerts first** – Focus on SQL injection, XSS, and brute force attempts immediately
- **Baseline your environment** – Understand normal web traffic and login patterns before interpreting findings
- **Archive reports** – Store JSON reports for compliance audits and incident investigations
- **Tune thresholds** – Adjust BRUTE_FORCE_THRESHOLD and WEB_SCAN_THRESHOLD based on your environment

## Author
Aadharsh Anbuchezhian
