#!/usr/bin/env python3
"""
Log Analyzer - SOC Edition
---------------------------
Scans common log formats for suspicious activity:
  - Linux auth logs  (SSH brute force, failed logins, privilege escalation)
  - Web server logs  (scanning, SQL injection, XSS attempts)
  - Syslog           (anomalous system events)

Author: Aadharsh Anbuchezhian
"""

import re
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter


# ── Terminal colours ──────────────────────────────────────────────────────────
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def alert(msg): print(f"  {Color.RED}[ALERT]{Color.RESET} {msg}")
def warn(msg):  print(f"  {Color.YELLOW}[ WARN]{Color.RESET} {msg}")
def good(msg):  print(f"  {Color.GREEN}[  OK ]{Color.RESET} {msg}")
def info(msg):  print(f"  {Color.BLUE}[ INFO]{Color.RESET} {msg}")

def section(title):
    print(f"\n{Color.BOLD}{'─' * 60}\n {title}\n{'─' * 60}{Color.RESET}")


# ── Finding tracker ───────────────────────────────────────────────────────────
all_findings = []

def record_finding(severity, category, detail, raw_line=None):
    """Save a finding so it can be included in the final report."""
    all_findings.append({
        "severity": severity,
        "category": category,
        "detail":   detail,
        "raw_line": raw_line,
    })


# ── Detection thresholds ──────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5    # failed SSH logins from one IP before we call it a brute force
PORT_SCAN_THRESHOLD   = 10   # connection attempts that suggest a port scan
WEB_SCAN_THRESHOLD    = 20   # HTTP requests from one IP that suggest automated scanning


# ── Auth log analysis ─────────────────────────────────────────────────────────
def analyse_auth_log(filepath):
    section(f"Auth Log  →  {filepath}")

    failed_by_ip   = defaultdict(list)   # ip → list of (username, raw line)
    successful     = []                  # (username, ip, raw line)
    sudo_commands  = []                  # (command, raw line)
    invalid_users  = defaultdict(int)    # ip → count of invalid-username attempts
    root_logins    = []                  # (ip, raw line)

    patterns = {
        "failed":       re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"),
        "accepted":     re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"),
        "invalid_user": re.compile(r"Invalid user \S+ from ([\d.]+)"),
        "sudo":         re.compile(r"sudo:.*COMMAND=(.+)"),
        "root_login":   re.compile(r"Accepted .+ for root from ([\d.]+)"),
    }

    try:
        with open(filepath, "r", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()

                match = patterns["failed"].search(line)
                if match:
                    username, ip = match.group(1), match.group(2)
                    failed_by_ip[ip].append((username, line))

                match = patterns["accepted"].search(line)
                if match:
                    successful.append((match.group(1), match.group(2), line))

                match = patterns["invalid_user"].search(line)
                if match:
                    invalid_users[match.group(1)] += 1

                match = patterns["sudo"].search(line)
                if match:
                    sudo_commands.append((match.group(1).strip(), line))

                match = patterns["root_login"].search(line)
                if match:
                    root_logins.append((match.group(1), line))

    except FileNotFoundError:
        alert(f"Couldn't find the file: {filepath}")
        return

    # ── SSH brute force check ──────────────────────────────────────────────────
    info(f"Looking for SSH brute force attacks (trigger: {BRUTE_FORCE_THRESHOLD}+ failures from one IP)")
    brute_force_count = 0

    for ip, attempts in sorted(failed_by_ip.items(), key=lambda x: -len(x[1])):
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            alert(f"Brute force from {ip} — {len(attempts)} failed attempts")
            record_finding("alert", "SSH Brute Force", f"{ip} made {len(attempts)} failed login attempts")
            brute_force_count += 1
        else:
            warn(f"A few failed logins from {ip} ({len(attempts)} attempts)")
            record_finding("warn", "Failed Login", f"{ip}: {len(attempts)} failures")

    if brute_force_count == 0:
        good("No brute force activity found")

    # ── Invalid usernames ──────────────────────────────────────────────────────
    if invalid_users:
        info("IPs trying non-existent usernames:")
        for ip, count in sorted(invalid_users.items(), key=lambda x: -x[1])[:10]:
            warn(f"{ip} tried {count} invalid usernames")
            record_finding("warn", "Invalid Username", f"{ip}: {count} attempts with usernames that don't exist")

    # ── Successful logins ──────────────────────────────────────────────────────
    if successful:
        info(f"{len(successful)} successful login(s) recorded:")
        for username, ip, line in successful[:10]:
            good(f"Logged in: {username} from {ip}")
            record_finding("info", "Successful Login", f"User '{username}' logged in from {ip}")

    # ── Direct root logins ─────────────────────────────────────────────────────
    for ip, line in root_logins:
        alert(f"Someone logged in directly as root from {ip}")
        record_finding("alert", "Root Login", f"Root account accessed directly from {ip}")

    # ── Sudo usage ─────────────────────────────────────────────────────────────
    if sudo_commands:
        info(f"{len(sudo_commands)} sudo command(s) run:")
        for command, line in sudo_commands[:10]:
            warn(f"sudo: {command[:80]}")
            record_finding("warn", "Sudo Command", command[:120])


# ── Web access log analysis ───────────────────────────────────────────────────
def analyse_web_log(filepath):
    section(f"Web Access Log  →  {filepath}")

    requests_by_ip  = defaultdict(int)
    sqli_hits       = []
    xss_hits        = []
    traversal_hits  = []
    scanner_hits    = []
    status_counts   = Counter()

    # Apache/Nginx combined log format
    log_line_pattern = re.compile(
        r'([\d.]+) .+ \[(.+?)\] "(\w+) (.+?) HTTP/.+?" (\d{3}) \d+ ".+?" "(.+?)"'
    )

    sqli_pattern     = re.compile(r"(union|select|insert|drop|or\s+1=1|--|;--|xp_|exec\()", re.I)
    xss_pattern      = re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.I)
    traversal_pattern = re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I)
    scanner_pattern  = re.compile(
        r"(nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|burpsuite|hydra|nessus)", re.I
    )

    try:
        with open(filepath, "r", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                match = log_line_pattern.match(line)
                if not match:
                    continue

                ip     = match.group(1)
                method = match.group(3)
                path   = match.group(4)
                status = match.group(5)
                ua     = match.group(6)

                requests_by_ip[ip] += 1
                status_counts[status] += 1

                if sqli_pattern.search(path):
                    sqli_hits.append((ip, path, line))
                    alert(f"SQL injection attempt — {ip}  →  {path[:80]}")
                    record_finding("alert", "SQL Injection", f"{ip} tried: {path[:100]}", line)

                if xss_pattern.search(path):
                    xss_hits.append((ip, path, line))
                    alert(f"XSS attempt — {ip}  →  {path[:80]}")
                    record_finding("alert", "XSS Attempt", f"{ip} tried: {path[:100]}", line)

                if traversal_pattern.search(path):
                    traversal_hits.append((ip, path, line))
                    alert(f"Path traversal attempt — {ip}  →  {path[:80]}")
                    record_finding("alert", "Path Traversal", f"{ip} tried: {path[:100]}", line)

                if scanner_pattern.search(ua):
                    scanner_hits.append((ip, ua, line))
                    warn(f"Scanning tool detected from {ip}  (UA: {ua[:60]})")
                    record_finding("warn", "Scanner Detected", f"{ip} — tool: {ua[:80]}")

    except FileNotFoundError:
        alert(f"Couldn't find the file: {filepath}")
        return

    # ── Top talkers ────────────────────────────────────────────────────────────
    info("Most active IPs:")
    for ip, count in sorted(requests_by_ip.items(), key=lambda x: -x[1])[:5]:
        if count >= WEB_SCAN_THRESHOLD:
            warn(f"{ip} made {count} requests — possible automated scan")
            record_finding("warn", "High Request Volume", f"{ip}: {count} requests")
        else:
            good(f"{ip}: {count} requests")

    # ── HTTP status summary ────────────────────────────────────────────────────
    info("HTTP response codes seen:")
    for code, count in sorted(status_counts.items()):
        print(f"    {code}  ×{count}")

    if not sqli_hits:
        good("No SQL injection patterns found")
    if not xss_hits:
        good("No XSS patterns found")
    if not traversal_hits:
        good("No path traversal patterns found")


# ── Syslog analysis ───────────────────────────────────────────────────────────
def analyse_syslog(filepath):
    section(f"Syslog  →  {filepath}")

    oom_events       = []
    segfaults        = []
    kernel_messages  = []
    cron_commands    = []
    service_failures = []

    patterns = {
        "oom":     re.compile(r"Out of memory|oom-killer|OOM"),
        "segfault":re.compile(r"segfault|SIGSEGV"),
        "kernel":  re.compile(r"kernel:\s+\[.+?\]\s+(.+)"),
        "cron":    re.compile(r"CRON.+CMD\s+\((.+)\)"),
        "failure": re.compile(r"(Failed|failed|error|Error).+service|service.+(failed|Failed)"),
    }

    try:
        with open(filepath, "r", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()

                if patterns["oom"].search(line):
                    oom_events.append(line)
                    alert(f"Out-of-memory event: {line[:100]}")
                    record_finding("alert", "OOM Killer", line[:150])

                if patterns["segfault"].search(line):
                    segfaults.append(line)
                    warn(f"Segfault detected: {line[:100]}")
                    record_finding("warn", "Segfault", line[:150])

                match = patterns["kernel"].search(line)
                if match:
                    kernel_messages.append(match.group(1))

                match = patterns["cron"].search(line)
                if match:
                    cron_commands.append(match.group(1).strip())

                if patterns["failure"].search(line):
                    service_failures.append(line)
                    warn(f"Service failure: {line[:100]}")
                    record_finding("warn", "Service Failure", line[:150])

    except FileNotFoundError:
        alert(f"Couldn't find the file: {filepath}")
        return

    info(f"Out-of-memory events : {len(oom_events)}")
    info(f"Segfaults            : {len(segfaults)}")
    info(f"Kernel messages      : {len(kernel_messages)}")
    info(f"Cron jobs seen       : {len(cron_commands)}")
    info(f"Service failures     : {len(service_failures)}")

    if cron_commands:
        info("Scheduled commands observed:")
        for command in list(set(cron_commands))[:10]:
            print(f"    {command}")


# ── Final report ──────────────────────────────────────────────────────────────
def save_report():
    section("Scan Summary")

    critical = [f for f in all_findings if f["severity"] == "alert"]
    warnings = [f for f in all_findings if f["severity"] == "warn"]
    notices  = [f for f in all_findings if f["severity"] == "info"]

    print(f"  Total findings : {len(all_findings)}")
    (alert if critical else good)(f"Critical : {len(critical)}")
    print(f"  {Color.YELLOW}Warnings : {len(warnings)}{Color.RESET}")
    print(f"  {Color.BLUE}Info     : {len(notices)}{Color.RESET}")

    if critical:
        print(f"\n  {Color.BOLD}{Color.RED}Things that need your attention:{Color.RESET}")
        for finding in critical:
            print(f"    • [{finding['category']}] {finding['detail']}")

    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"log_analysis_{timestamp}.json"

    with open(report_path, "w") as f:
        json.dump({
            "scanned_at": timestamp,
            "summary": {
                "critical": len(critical),
                "warnings": len(warnings),
                "info":     len(notices),
            },
            "findings": all_findings,
        }, f, indent=2)

    print(f"\n  {Color.BLUE}Full report saved to:{Color.RESET} {report_path}\n")


# ── Sample log generator ──────────────────────────────────────────────────────
def generate_sample_logs():
    """Creates a small set of realistic-looking sample logs for testing."""
    Path("samples").mkdir(exist_ok=True)

    with open("samples/auth.log", "w") as f:
        f.write(
            "Dec  1 10:01:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "Dec  1 10:01:03 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "Dec  1 10:01:05 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "Dec  1 10:01:07 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "Dec  1 10:01:09 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "Dec  1 10:01:11 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2\n"
            "Dec  1 10:05:00 server sshd[1235]: Accepted password for admin from 10.0.0.5 port 22 ssh2\n"
            "Dec  1 10:06:00 server sshd[1236]: Accepted password for root from 203.0.113.50 port 22 ssh2\n"
            "Dec  1 10:07:00 server sudo:  admin : COMMAND=/bin/bash\n"
            "Dec  1 10:08:00 server sshd[1237]: Invalid user testuser from 192.168.1.200\n"
            "Dec  1 10:08:01 server sshd[1237]: Invalid user admin123 from 192.168.1.200\n"
        )

    with open("samples/access.log", "w") as f:
        f.write(
            '192.168.1.50 - - [01/Dec/2025:10:00:01 +0000] "GET /index.php?id=1 union select 1,2,3-- HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
            '10.0.0.20 - - [01/Dec/2025:10:00:05 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 0 "-" "Mozilla/5.0"\n'
            '172.16.0.5 - - [01/Dec/2025:10:00:10 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 0 "-" "Mozilla/5.0"\n'
            '203.0.113.99 - - [01/Dec/2025:10:01:00 +0000] "GET /login HTTP/1.1" 200 1024 "-" "sqlmap/1.7"\n'
            '192.168.1.1 - - [01/Dec/2025:10:02:00 +0000] "GET /home HTTP/1.1" 200 2048 "-" "Mozilla/5.0"\n'
        )

    with open("samples/syslog", "w") as f:
        f.write(
            "Dec  1 10:00:01 server kernel: [12345.678] Out of memory: Kill process 4321 (python3) score 900\n"
            "Dec  1 10:00:05 server kernel: [12346.000] python3[4321]: segfault at 0 ip 00007f rsp 00007f error 4\n"
            "Dec  1 10:01:00 server CRON[5678]: (root) CMD (/usr/bin/backup.sh)\n"
            "Dec  1 10:02:00 server systemd[1]: nginx.service: Failed with result 'exit-code'\n"
        )

    print(f"\n  {Color.GREEN}Sample logs created in ./samples/{Color.RESET}")
    print("  Try running:")
    print("    python log_analyzer.py --auth samples/auth.log --web samples/access.log --syslog samples/syslog\n")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SOC Log Analyzer — Aadharsh Anbuchezhian",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py --auth /var/log/auth.log
  python log_analyzer.py --web /var/log/nginx/access.log
  python log_analyzer.py --syslog /var/log/syslog
  python log_analyzer.py --auth auth.log --web access.log --syslog syslog
  python log_analyzer.py --sample       # generate sample logs to test with
        """,
    )
    parser.add_argument("--auth",   help="Path to auth.log or secure log")
    parser.add_argument("--web",    help="Path to web server access log (Apache/Nginx combined format)")
    parser.add_argument("--syslog", help="Path to syslog")
    parser.add_argument("--sample", action="store_true", help="Generate sample log files for testing")
    args = parser.parse_args()

    print(f"\n{Color.BOLD}{'═' * 60}")
    print("  SOC Log Analyzer")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 60}{Color.RESET}")

    if args.sample:
        generate_sample_logs()
        return

    if not any([args.auth, args.web, args.syslog]):
        parser.print_help()
        return

    if args.auth:
        analyse_auth_log(args.auth)
    if args.web:
        analyse_web_log(args.web)
    if args.syslog:
        analyse_syslog(args.syslog)

    save_report()


if __name__ == "__main__":
    main()
