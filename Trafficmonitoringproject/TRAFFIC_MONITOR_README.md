# 📡 Network Traffic Monitoring Tool

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-green?logo=qt)
![Scapy](https://img.shields.io/badge/Scapy-packet--capture-purple)
![License](https://img.shields.io/badge/License-MIT-green)

> Real-time network traffic analyzer with threat detection, bandwidth monitoring, and interactive HTML reporting.

## Overview
Captures and analyzes live network packets from your local network interface. Detects security threats (SYN floods, port scans, etc.), monitors bandwidth usage, and generates detailed CSV and HTML reports. Built with PyQt6 for a responsive desktop GUI.

## Features
- **Real-time Packet Capture** – Multi-threaded live sniffing from any network interface
- **Threat Detection** – Identifies 8+ attack patterns:
  - TCP SYN Flood
  - ICMP Flood
  - UDP Port Sweep
  - TCP FIN Scan / XMAS Scan / Null Scan
  - DNS Amplification
  - SMB Attacks
- **Protocol Filtering** – Filter by TCP, UDP, ICMP, or view all traffic
- **IP & Port Filtering** – Custom filters for source/destination IPs and ports
- **Bandwidth Monitoring** – Real-time upload/download speed and total data transfer
- **CSV Export** – Save packet data and bandwidth history to CSV files
- **Interactive HTML Reports** – Professional reports with live filtering by IP, protocol, and risk level
- **Color-coded Alerts** – Visual threat severity indicators (Red=HIGH, Yellow=MEDIUM, Green=LOW)
- **Packet Details** – Click any packet to view full header information (TTL, flags, sequence numbers)

## Prerequisites
- Python 3.10+
- Windows, macOS, or Linux
- Administrator/root privileges (required for packet sniffing)
- Network interface access

## Installation

```bash
git clone https://github.com/aadharsh99/Projects.git
cd Trafficmonitoringproject
pip install -r requirements.txt
```

## Running the Tool

**Windows (requires admin):**
```bash
python cybersecportscanner.py
```

**macOS/Linux (requires sudo):**
```bash
sudo python3 cybersecportscanner.py
```

## Usage

### Starting a Capture
1. **Select Network Interface** – Choose from available adapters (Ethernet, Wi-Fi, etc.)
2. **Set Filters (optional)**:
   - **Protocol** – TCP, UDP, ICMP, or ALL
   - **IP** – Comma-separated source IPs (e.g., `192.168.1.1,10.0.0.5`)
   - **Port(s)** – Single ports or ranges (e.g., `22,80,443` or `1-1000`)
3. **Click Start** – Begin capturing packets (or press `Ctrl+S`)
4. **Monitor in Real-time** – Watch threats and bandwidth appear live in the table

### Stopping a Capture
- Click **Stop** button or press `Ctrl+X`

### Viewing Packet Details
- Click any row in the packet table to see full packet information in the details pane

### Exporting Data

**Save Packet CSV:**
- Menu → File → Save Traffic CSV
- Exports timestamp, source, destination, protocol, detected threats, and severity

**Save Bandwidth CSV:**
- Menu → File → Save Bandwidth CSV
- Exports real-time bandwidth history with upload/download speeds

**Generate HTML Report:**
- Menu → Reports → Traffic Report
- Interactive report with live filters by source IP, destination IP, protocol, and risk level
- Option to include detailed packet data (TTL, flags, etc.)
- Option to include bandwidth statistics

**Bandwidth Report:**
- Menu → Reports → Bandwidth Report
- Shows upload/download speeds over time in a formatted table

## Example Workflow

```
1. Launch tool → Select Wi-Fi interface
2. Set Protocol filter to "TCP"
3. Click Start (Ctrl+S)
4. Monitor for threats in real-time
   [Alert] TCP SYN Flood (HIGH): 192.168.1.50 → 10.0.0.1
   [Alert] TCP FIN Scan (HIGH): 203.0.113.99 → 192.168.1.100
5. Stop capture (Ctrl+X)
6. Generate HTML report → Open in browser
7. Filter by risk level → Review HIGH severity threats
```

## Threat Detection Details

| Threat | Protocol | Trigger | Risk |
|--------|----------|---------|------|
| TCP SYN Flood | TCP | SYN flag (S) set repeatedly | HIGH |
| TCP FIN Scan | TCP | FIN flag (F) set | HIGH |
| TCP XMAS Scan | TCP | FIN+PSH+URG flags | HIGH |
| Null Scan | TCP | No flags set | HIGH |
| ICMP Flood | ICMP | Rapid ICMP requests | MEDIUM |
| UDP Port Sweep | UDP | Multiple ports, same source | MEDIUM |
| DNS Amplification | UDP | Port 53 traffic patterns | HIGH |
| SMB Attack | TCP | Port 445 activity | HIGH |

## HTML Report Features

### Interactive Filtering
- **Source IP dropdown** – Filter by attacker/sender
- **Destination IP dropdown** – Filter by target
- **Protocol selector** – View only TCP, UDP, ICMP, etc.
- **Risk Level filter** – Show only HIGH/MEDIUM/LOW threats
- **Live counter** – Shows matching packets vs. total

### Color-coded Rows
- **Red (HIGH)** – Critical security threat requiring immediate action
- **Yellow (MEDIUM)** – Suspicious activity worth investigating
- **Green (LOW)** – Normal traffic, informational only
- **Neutral** – Non-threatening traffic

### Expandable Details
- Click a row to see full packet analysis
- Detailed packet information when "Include detailed packet data" is checked

## Configuration

**Bandwidth Update Interval** (edit script):
```python
UI_UPDATE_INTERVAL = 20  # milliseconds between GUI updates
```

**Max Packets Displayed** (edit script):
```python
MAX_PACKETS = 2000  # maximum rows in table (older packets auto-removed)
```

**Socket Timeout** (for banner grabbing):
```python
socket.settimeout(1)  # 1 second timeout per port
```

## Keyboard Shortcuts
- `Ctrl+S` – Start packet capture
- `Ctrl+X` – Stop packet capture

## Technologies
| Library | Purpose |
|---------|---------|
| PyQt6 | Desktop GUI framework |
| Scapy | Live packet capture & analysis |
| socket | Network operations |
| csv | Data export |
| re | Port range parsing |
| subprocess | Interface enumeration |
| collections | Packet history management |
| datetime | Timestamps |

## Performance Notes
- **Thread Count** – Auto-scales to CPU cores × 3 (max 50)
- **Max Displayed Rows** – 2,000 packets (older rows auto-removed)
- **Update Rate** – GUI refreshes every 20ms for smooth updates
- **Bandwidth History** – Last 300 samples retained (5 minutes at 1-second intervals)

## Logging
All events logged to `scanner.log`:
- Capture start/stop
- Interface enumeration
- Error messages
- Report generation

## Limitations
- Requires admin/root privileges for packet sniffing
- UDP port detection requires banner grabbing (slower)
- Bandwidth tracking only on captured interface
- Report generation time scales with packet count

## Key Takeaways
- **Run with admin privileges** – Packet capture requires elevated permissions
- **Start with focused filters** – Scanning all traffic is data-heavy
- **Archive HTML reports** – Save for compliance and incident analysis
- **Monitor threats immediately** – HIGH severity alerts need fast response
- **Use CSV exports** – Import to Excel/Python for deeper analysis
- **Check logs regularly** – `scanner.log` contains important diagnostic info

## Legal Notice
⚠️ **Network monitoring is only legal on networks you own or have explicit permission to monitor.** Unauthorized packet capture may violate laws including the Computer Fraud and Abuse Act. Use responsibly and ethically.

## Authors
Aadharsh Anbuchezhian, Destiny Eko, Maksim Gurzhiy (May 2025)
