# 🛡️ CyberSec Port Scanner

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![PyQt5](https://img.shields.io/badge/PyQt5-GUI-green?logo=qt)
![License](https://img.shields.io/badge/License-MIT-green)

> Advanced network security scanner with GUI, CVE detection, and AI-powered vulnerability recommendations.

## Overview
A full-featured port scanner with a desktop GUI that performs network reconnaissance, service identification, CVE lookups, and generates professional HTML reports. Integrates with NIST NVD for vulnerability data and OpenAI for intelligent security recommendations.

## Features
- **Multi-threaded Port Scanning** – Fast TCP/UDP scans across multiple hosts and ports
- **Service Detection** – Identifies running services and grabs banners for version detection
- **CVE Lookup** – Queries NIST National Vulnerability Database for known exploits (requires NVD API key)
- **AI Recommendations** – Uses OpenAI API to generate security remediation advice
- **Risk Assessment** – Automatically assigns risk levels (High/Medium/Low) based on detected services
- **HTML Reports** – Professional, interactive reports with filtering and expandable details
- **Real-time Progress** – Live scan updates with visual progress bars
- **Async Scanning** – Asynchronous operations for responsive UI during long scans
- **Logging** – Detailed scan logs saved to `scanner.log`

## Prerequisites
- Python 3.10+
- Qt 5.15+ (installed via PyQt5)

### Optional API Keys (for full functionality)
- **NIST NVD API Key** – Free from https://nvd.nist.gov/developers/request-an-api-key (recommended for CVE lookup)
- **OpenAI API Key** – From https://platform.openai.com/api-keys (for AI recommendations)

## Installation

```bash
git clone https://github.com/aadharsh99/Projects.git
cd Cybersecportscannerproject
pip install -r requirements.txt
```

## Configuration

### Setting up API Keys
Create two JSON files in the project directory:

**nvdapikey.json** (for CVE lookup)
```json
{
  "nvd_api_key": "YOUR_NIST_NVD_API_KEY"
}
```

**chatgptapikey.json** (for AI recommendations)
```json
{
  "openai_api_key": "YOUR_OPENAI_API_KEY"
}
```

The scanner will warn you if these files are missing—CVE and AI features will be disabled, but basic scanning still works.

## Usage

**Launch the GUI:**
```bash
python cybersecportscanner.py
```

### GUI Features
1. **Host Input** – Enter single IP or CIDR range (e.g., `192.168.1.0/24`)
2. **Port Range** – Specify ports to scan (e.g., `1-1000`, `22,80,443,3306`)
3. **Scan Type** – Choose between:
   - TCP Connect Scan
   - UDP Scan
   - Fast Scan (common ports only)
4. **Advanced Options**:
   - Timeout settings
   - Thread count (auto-detected by CPU)
   - Banner grabbing
5. **Real-time Results** – View open ports as they're discovered
6. **CVE Lookup** – Fetch vulnerability data for identified services
7. **AI Analysis** – Generate security recommendations
8. **Export** – Save results as HTML report with interactive filtering

### Example Workflow
1. Enter target: `192.168.1.0/24`
2. Port range: `1-1000`
3. Scan type: `TCP Connect Scan`
4. Click **Start Scan**
5. View results in real-time
6. Click **Lookup CVEs** for vulnerability data
7. Click **AI Analysis** for remediation steps
8. Click **Export Report** to save HTML file

## HTML Report Features
- **Summary Statistics** – Total hosts, ports, open ports, CVEs
- **Host Breakdown** – Per-host results with port details
- **Interactive Filtering** – Search by service, port, or risk level
- **Expandable Details** – Click rows to see full banner/vulnerability info
- **CVE Records** – Linked vulnerabilities with descriptions
- **AI Recommendations** – Security remediation suggestions
- **Risk Coloring** – Visual indicators (Red=High, Yellow=Medium, Green=Low)

### Example Report Output
```
🛡️ Network Security Scan Report
Date: January 15, 2024 14:32
Scan type: TCP Connect Scan
Hosts scanned: 5

Hosts: 5 | Ports Scanned: 45 | Open: 12 | Closed: 33 | CVEs: 8

📱 Host: 192.168.1.1
Scanned: 9 ports | Open: 3 | CVEs: 2

Port    Proto  Status   Service    Banner              Risk  CVEs
22      tcp    Open     SSH        OpenSSH 7.4p1       HIGH  2
80      tcp    Open     HTTP       Apache 2.4.6        MED   1
443     tcp    Closed   HTTPS      -                   N/A   0

[Click to expand for CVE details and vulnerabilities...]
```

## Technologies
| Library | Purpose |
|---------|---------|
| PyQt5 | Desktop GUI framework |
| requests | HTTP requests for API calls |
| aiohttp | Async HTTP for concurrent operations |
| scapy | Network packet crafting (optional) |
| socket | Low-level socket operations |
| asyncio | Asynchronous task handling |
| logging | Detailed event logging |

## Performance Notes
- **Threading** – Automatically scales to CPU count × 3 (max 50 threads)
- **Timeout** – Socket timeout defaults to 1 second
- **Banner Grab Timeout** – 2 seconds per port
- **Rate Limiting** – CVE lookups throttled to avoid API limits (0.6s delay per request)

## Logging
All scan events are logged to `scanner.log`:
- API key validation
- Scan start/completion
- Open ports discovered
- CVE lookup results
- Error messages

## Key Takeaways
- **Start with CIDR ranges carefully** – Don't scan /8 networks without reason (too slow)
- **API keys recommended** – Setup NIST API key for full CVE database access
- **Export for documentation** – Save HTML reports for compliance records
- **Test on your own networks first** – Ensure you have authorization before scanning others
- **Monitor logs** – Check scanner.log for detailed scan information
- **Use AI recommendations** – Generated advice helps prioritize remediation

## Legal Notice
⚠️ **This tool is for authorized security testing only.** Unauthorized network scanning may be illegal. Ensure you have explicit permission before scanning any network.

## Author
Aadharsh Anbuchezhian
