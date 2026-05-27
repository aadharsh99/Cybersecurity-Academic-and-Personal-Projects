##########################Network Traffic Monitoring Tool#################################################################################
#***********Developed by Aadharsh Anbuchezhian, Destiny Eko, Maksim Gurzhiy, May 2025***************************************************

#....Code below imports required libraries....
import sys, csv, os, re, subprocess, time
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from PyQt6.QtWidgets import *
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, QMutex
from PyQt6.QtGui import QColor
from datetime import datetime
from collections import deque

#..Setting the maximum threshold for packets and GUI update interval
MAX_PACKETS, UI_UPDATE_INTERVAL = 2000, 20
#....Code for getting the list of interfaces...
def get_interfaces():
    
    interfaces = []
    try:
        if sys.platform.startswith('win'): result = subprocess.run(["ipconfig"], capture_output=True, text=True, encoding='mbcs'); interfaces = [name.strip() for name in re.findall(r"(?:Ethernet|Wireless|Wi-Fi)[^:]*adapter ([^:]+):", result.stdout) 
        if name.strip()] if result.returncode == 0 else []
        elif sys.platform.startswith(('linux', 'darwin')): result = subprocess.run(["ifconfig"], capture_output=True, text=True); interfaces = re.findall(r'^(\w+):', result.stdout, re.MULTILINE) if result.returncode == 0 else []
    except: pass
    return interfaces or list(conf.ifaces.keys()) if hasattr(conf, 'ifaces') else ["Ethernet", "Wi-Fi"]


#Code module for capturing network packets
class packetsniff(QThread):
    packet_captured, error_occurred = pyqtSignal(object), pyqtSignal(str)
    
    def __init__(self, iface=None):
        super().__init__(); self._running, self.iface = False, iface; conf.use_pcap, conf.verb, conf.promisc = True, 0, True
    def run(self):
        self._running = True
        try:
            sniff(prn=self.process_packet, store=False, iface=self.iface, stop_filter=lambda _: not self._running)
        except Exception as e:
            self.error_occurred.emit(f"Error: {str(e)}")
    
    def process_packet(self, p):
        if self._running:
            try: self.packet_captured.emit(p)
            except Exception as e: print(f"Emit error: {e}")
    def stop(self):
        self._running = False; self.quit()

#.....Module for tracking Bandwidth usage metrics
class bandwidthmonitor:
    
    def __init__(self): self.upload_bytes, self.download_bytes, self.total_bytes, self.last_update_time = 0, 0, 0, time.time(); self.upload_speed, self.download_speed = 0, 0; self.history = deque(maxlen=300); self.mutex = QMutex()
    def update(self, p, local_ip):
        self.mutex.lock()
        try:
            if IP in p: size = len(p); self.total_bytes += size; self.upload_bytes += size if p[IP].src == local_ip else 0; self.download_bytes += size if p[IP].src != local_ip else 0
        finally: self.mutex.unlock()
    def calculate_speeds(self):
        self.mutex.lock()
        try:
            now, diff = time.time(), time.time() - self.last_update_time
            if diff > 0:
                self.upload_speed, self.download_speed = self.upload_bytes / diff, self.download_bytes / diff; self.history.append({"time": datetime.now(), "upload_speed": self.upload_speed, "download_speed": self.download_speed, "total": self.total_bytes}); self.upload_bytes, self.download_bytes, self.last_update_time = 0, 0, now
        finally: self.mutex.unlock()
    
    def get_formatted_speeds(self):
        self.mutex.lock()
        try:
            format_speed = lambda bps: f"{bps:.1f} B/s" if bps < 1024 else f"{bps/1024:.1f} KB/s" if bps < 1024 * 1024 else f"{bps/(1024*1024):.2f} MB/s"
            format_size = lambda b: f"{b} B" if b < 1024 else f"{b/1024:.1f} KB" if b < 1024 * 1024 else f"{b/(1024*1024):.2f} MB" if b < 1024 * 1024 * 1024 else f"{b/(1024*1024*1024):.2f} GB"
            return format_speed(self.upload_speed), format_speed(self.download_speed), format_size(self.total_bytes)
        finally: self.mutex.unlock()


#...Main and core module of the tool for integrating ui, packet analyser, display and reporting....
class analysernetwork(QMainWindow):
        
    TCP_FLAG_SET = {"S": 0x02, "F": 0x01, "FPU": 0x29, "": 0x00}
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Monitoring"); self.setGeometry(100, 100, 950, 600)
        widget_main, layout_main, filter_layout, layout_button = QWidget(), QVBoxLayout(), QHBoxLayout(), QHBoxLayout()
        self.setCentralWidget(widget_main); widget_main.setLayout(layout_main)

        self.combo_iface, self.type_select, self.ip_input, self.port_input = QComboBox(), QComboBox(), QLineEdit(), QLineEdit()
        self.ifaces = get_interfaces(); self.combo_iface.addItems(self.ifaces); self.type_select.addItems(["ALL", "TCP", "UDP", "ICMP"])
        filter_layout.addWidget(QLabel("Interface:")); filter_layout.addWidget(self.combo_iface); filter_layout.addWidget(QLabel("Protocol:")); filter_layout.addWidget(self.type_select);
        filter_layout.addWidget(QLabel("IP:")); filter_layout.addWidget(self.ip_input); filter_layout.addWidget(QLabel("Port(s):")); filter_layout.addWidget(self.port_input)

        self.startbtn, self.stopbtn, self.saveCSV, self.webSave = QPushButton("Start (Ctrl+S)"), QPushButton("Stop (Ctrl+X)"), QPushButton("Save CSV"), QPushButton("Save HTML")
        self.startbtn.setShortcut("Ctrl+S"); self.stopbtn.setShortcut("Ctrl+X"); self.stopbtn.setEnabled(False)
        for btn in (self.startbtn, self.stopbtn, self.saveCSV, self.webSave): layout_button.addWidget(btn)

        self.table = QTableWidget(0, 5); self.table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Threat"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents); self.data = QTextEdit(); self.data.setReadOnly(True)

        bwidth_group = QGroupBox("Bandwidth Monitor"); bwidth_layout = QGridLayout(); bwidth_group.setLayout(bwidth_layout)
        self.upld_label, self.downld_label, self.total_label = QLabel("Upload: 0 B/s"), QLabel("Download: 0 B/s"), QLabel("Total: 0 B")
        bwidth_layout.addWidget(QLabel("Upload:"), 0, 0); bwidth_layout.addWidget(self.upld_label, 0, 1)
        bwidth_layout.addWidget(QLabel("Download:"), 1, 0); bwidth_layout.addWidget(self.downld_label, 1, 1)
        bwidth_layout.addWidget(QLabel("Total:"), 2, 0); bwidth_layout.addWidget(self.total_label, 2, 1)

        self.pkt_label, self.rsk_label = QLabel("Packets: 0"), QLabel("Threats: 0")
        status_layout = QHBoxLayout(); status_layout.addWidget(self.pkt_label); status_layout.addWidget(self.rsk_label)

        layout_main.addLayout(filter_layout); layout_main.addLayout(layout_button); layout_main.addWidget(bwidth_group)
        layout_main.addWidget(self.table); layout_main.addLayout(status_layout); layout_main.addWidget(self.data)

        self.startbtn.clicked.connect(self.start_capture); self.stopbtn.clicked.connect(self.stop_capture); self.saveCSV.clicked.connect(lambda: self.save_data(False)); self.webSave.clicked.connect(lambda: self.gen_report(False))
        self.table.cellClicked.connect(self.display_packet_info)

        self.packet_list, self.pending_packets, self.count = deque(maxlen=MAX_PACKETS), [], {"packets": 0, "threats": 0}
        self.protocol_styles = {"TCP": QColor(138, 43, 226), "UDP": QColor(127, 255, 0), "ICMP": QColor(255, 240, 220), "OTHER": QColor(245, 245, 245)}
        self.alert_styling = {"HIGH": QColor(220, 20, 60), "MEDIUM": QColor(255, 140, 0), "LOW": QColor(255, 255, 200), "NONE": QColor(255, 255, 0)}
        self.threat_patterns = [
        {"name": "TCP SYN Flood", "protocol": "TCP", "flag": "S", "risk_lvl": "HIGH"},
        {"name": "ICMP Flood", "protocol": "ICMP", "risk_lvl": "MEDIUM"},
        {"name": "UDP Port Sweep", "protocol": "UDP", "risk_lvl": "MEDIUM"},
        {"name": "TCP FIN Scan", "protocol": "TCP", "flag": "F", "risk_lvl": "HIGH"},
        {"name": "TCP XMAS", "protocol": "TCP", "flag": "FPU", "risk_lvl": "HIGH"},
        {"name": "Null Scan", "protocol": "TCP", "flag": "", "risk_lvl": "HIGH"},
        {"name": "DNS Amp", "protocol": "UDP", "dst_port": 53, "risk_lvl": "HIGH"},
        {"name": "SMB Attack", "protocol": "TCP", "dst_port": 445, "risk_lvl": "HIGH"}
        ]



        self.sniffer, self.sniffing, self.mutex = None, False, QMutex()
        self.timer_ui, self.bwidth_monitor = QTimer(self), bandwidthmonitor(); self.timer_ui.timeout.connect(self.update_ui); self.timer_ui.setInterval(UI_UPDATE_INTERVAL)
        self.bwidth_timer = QTimer(self); self.bwidth_timer.timeout.connect(self.update_bandwidth); self.bwidth_timer.setInterval(1000)
        self.status_bar = self.statusBar(); self.status_msg = QLabel("Ready"); self.status_bar.addWidget(self.status_msg)
        self.local_ip = self.get_ip()

        menu_bar = self.menuBar(); file_menu = menu_bar.addMenu("File"); reports_menu = menu_bar.addMenu("Reports")
        start_action, stop_action = file_menu.addAction("Start Capture"), file_menu.addAction("Stop Capture")
        start_action.triggered.connect(self.start_capture); stop_action.triggered.connect(self.stop_capture)
        
        file_menu.addSeparator()
        save_csv_action, save_bw_csv_action = file_menu.addAction("Save Traffic CSV"), file_menu.addAction("Save Bandwidth CSV")
        save_csv_action.triggered.connect(lambda: self.save_data(False)); save_bw_csv_action.triggered.connect(lambda: self.save_data(True))
        file_menu.addSeparator(); file_menu.addAction("Exit").triggered.connect(self.close)
        
        reports_menu.addAction("Traffic Report").triggered.connect(lambda: self.gen_report(False))
        reports_menu.addAction("Bandwidth Report").triggered.connect(lambda: self.gen_report(True))

    def get_ip(self):
        
        try: import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); local_ip = s.getsockname()[0]; s.close(); return local_ip
        except: return ""

    def update_bandwidth(self): self.bwidth_monitor.calculate_speeds(); u, d, t = self.bwidth_monitor.get_formatted_speeds(); self.upld_label.setText(u); self.downld_label.setText(d); self.total_label.setText(t)

#code for start packet capture selection
    def start_capture(self):
        try:
            for ctrl in (self.startbtn, self.combo_iface, self.type_select, self.ip_input, self.port_input): ctrl.setEnabled(False)
            self.stopbtn.setEnabled(True); self.table.setRowCount(0); self.packet_list.clear(); self.pending_packets = []; self.count = {"packets": 0, "threats": 0}
            self.pkt_label.setText("Packets: 0"); self.rsk_label.setText("Threats: 0"); self.data.clear(); self.bwidth_monitor = bandwidthmonitor()
            self.upld_label.setText("Upload: 0 B/s"); self.downld_label.setText("Download: 0 B/s"); self.total_label.setText("Total: 0 B")

            iface = self.combo_iface.currentText(); self.status_msg.setText(f"Starting capture on {iface}...")
            self.sniffer = packetsniff(iface=iface); self.sniffer.packet_captured.connect(self.handle_packet)
            self.sniffer.error_occurred.connect(lambda msg: [self.status_msg.setText(msg), QMessageBox.warning(self, "Error", msg), self.stop_capture()])
            self.sniffer.start(); self.sniffing = True; self.timer_ui.start(); self.bwidth_timer.start(); self.status_msg.setText(f"Capturing on {iface}")
        except Exception as e: self.status_msg.setText(f"Error: {str(e)}"); QMessageBox.critical(self, "Error", f"Failed: {str(e)}"); self.stop_capture()

#code for stop packet capture
    def stop_capture(self):
        self.status_msg.setText("Stopping..."); self.stopbtn.setEnabled(False); self.timer_ui.stop(); self.bwidth_timer.stop(); self.sniffing = False
        if self.sniffer:
            try: self.sniffer.packet_captured.disconnect(); self.sniffer.stop(); self.sniffer.wait(500)
            except: pass
            self.sniffer = None
        for ctrl in (self.startbtn, self.combo_iface, self.type_select, self.ip_input, self.port_input): ctrl.setEnabled(True)
        self.status_msg.setText("Ready")

    def check_data(self, bw_only=False):
        if (bw_only and self.bwidth_monitor.history) or (not bw_only and self.packet_list): return True
        QMessageBox.warning(self, "No Data", f"No {'bandwidth' if bw_only else 'packet'} data available."); return False

#..Code for processing packets and identifying threats
    def match_threat(self, pkt):
        matches = []
        
        try:
            for p in self.threat_patterns:
                if p["protocol"] == "TCP" and TCP in pkt and ("flag" in p and self.TCP_FLAG_SET.get(p["flag"]) == pkt[TCP].flags or "dst_port" in p and pkt[TCP].dport == p.get("dst_port")): matches.append(p)
                elif p["protocol"] == "UDP" and UDP in pkt and ("dst_port" not in p or pkt[UDP].dport == p.get("dst_port")): matches.append(p)
                elif p["protocol"] == "ICMP" and ICMP in pkt: matches.append(p)
        except: pass
        return matches

    def packet_meets_criteria(self, ptype, src_ip, dst_ip, sport="", dport=""):
        sel_type, ip_filter, port_filter = self.type_select.currentText(), self.ip_input.text().strip(), self.port_input.text().strip()
        if sel_type != "ALL" and ptype != sel_type: return False
        if ip_filter and not any(f in src_ip or f in dst_ip for f in ip_filter.split(',')): return False
        if port_filter and ptype != "ICMP":
            for spec in (s.strip() for s in port_filter.split(',') if s.strip()):
                try:
                    if '-' in spec:
                        low, high = map(int, spec.split('-'));
                        if (sport and low <= int(sport) <= high) or (dport and low <= int(dport) <= high): return True
                    elif spec and ((sport and int(sport) == int(spec)) or (dport and int(dport) == int(spec))): return True
                except ValueError: continue
            return False
        return True

    def handle_packet(self, p):
        if not self.sniffing or not IP in p: return
        
        try:
            self.bwidth_monitor.update(p, self.local_ip)
            ptype, src_port, dst_port = "OTHER", "", ""; src_ip, dst_ip = p[IP].src, p[IP].dst
            if TCP in p: ptype, src_port, dst_port = "TCP", str(p[TCP].sport), str(p[TCP].dport)
            elif UDP in p: ptype, src_port, dst_port = "UDP", str(p[UDP].sport), str(p[UDP].dport)
            elif ICMP in p: ptype = "ICMP"

            if not self.packet_meets_criteria(ptype, src_ip, dst_ip, src_port, dst_port): return

            threats = self.match_threat(p)
            risk_lvl = max((t.get('risk_lvl', "NONE") for t in threats), key=lambda x: {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}.get(x, 0)) if threats else "NONE"

            self.mutex.lock(); self.pending_packets.append({
            "timestamp": datetime.fromtimestamp(float(p.time)).strftime('%H:%M:%S'),
            "src": src_ip, "dst": dst_ip, "protocol": ptype, "sport": src_port, "dport": dst_port,
            "threat": threats, "risk_lvl": risk_lvl, "raw_pkt": p
            }); self.count["packets"] += 1; self.count["threats"] += 1 if threats else 0; self.mutex.unlock()
        except Exception as e: print(f"Packet error: {e}")

    
   #....code for updating user interface with threat and bandwidth information..
    def update_ui(self):
        try:
            self.mutex.lock(); packets = self.pending_packets.copy(); self.pending_packets = []; self.mutex.unlock()
            if not packets: return
            self.pkt_label.setText(f"Packets: {self.count['packets']}"); self.rsk_label.setText(f"Threats: {self.count['threats']}"); self.table.setUpdatesEnabled(False)

            for data in packets:
                self.packet_list.append(data); row = self.table.rowCount(); self.table.insertRow(row)
                src_text, dst_text = f"{data['src']}{':'+data['sport'] if data['sport'] else ''}", f"{data['dst']}{':'+data['dport'] if data['dport'] else ''}"
                items = [QTableWidgetItem(data["timestamp"]), QTableWidgetItem(src_text), QTableWidgetItem(dst_text), QTableWidgetItem(data["protocol"]),
                QTableWidgetItem(", ".join(t['name'] for t in data["threat"]) if data["threat"] else "None")]

                style = self.alert_styling.get(data["risk_lvl"]) if data["risk_lvl"] != "NONE" else self.protocol_styles.get(data["protocol"], self.protocol_styles["OTHER"])
                for col, item in enumerate(items): item.setBackground(style); self.table.setItem(row, col, item)
                if data["threat"]: self.data.append(f"[!] {data['threat'][0]['name']} ({data['risk_lvl']}): {data['src']} -> {data['dst']}")

            while self.table.rowCount() > MAX_PACKETS: self.table.removeRow(0)
            self.table.scrollToBottom(); self.table.setUpdatesEnabled(True)
        except Exception as e: print(f"UI Error: {e}")

    def display_packet_info(self, idx, col):
        try:
            if idx < 0 or idx >= len(self.packet_list): return
            pkt = list(self.packet_list)[idx]; scapy_pkt = pkt.get("raw_pkt")
            src_text, dst_text = f"{pkt['src']}{':'+pkt['sport'] if pkt['sport'] else ''}", f"{pkt['dst']}{':'+pkt['dport'] if pkt['dport'] else ''}"
            data = f"Time: {pkt['timestamp']}\nSource: {src_text}\nDest: {dst_text}\nProto: {pkt['protocol']}\n"

            if scapy_pkt:
                if IP in scapy_pkt: data += f"TTL: {scapy_pkt[IP].ttl}, Length: {len(scapy_pkt)}\n"
                if TCP in scapy_pkt: data += f"TCP Flags: {scapy_pkt[TCP].flags}, Seq/Ack: {scapy_pkt[TCP].seq}/{scapy_pkt[TCP].ack}\n"
                if UDP in scapy_pkt: data += f"UDP Length: {scapy_pkt[UDP].len}\n"
                if ICMP in scapy_pkt: data += f"ICMP Type/Code: {scapy_pkt[ICMP].type}/{scapy_pkt[ICMP].code}\n"
            data += "\nThreats:\n" + ("\n".join(f" - {t['name']} ({t['risk_lvl']})" for t in pkt['threat']) if pkt['threat'] else "None")
            self.data.setText(data)
        except Exception as e: print(f"Display error: {e}")

#Code below saves the report as csv and html
    def save_data(self, bw_data=False):
        if not self.check_data(bw_data): return
        fpath = QFileDialog.getSaveFileName(self, f"Save {'Bandwidth' if bw_data else 'Packet'} CSV", f"{'bandwidth' if bw_data else 'packets'}.csv", "CSV (*.csv)")[0]
        if not fpath: return
        try:
            with open(fpath, "w", newline='') as f:
                writer = csv.writer(f)
                if bw_data:
                    writer.writerow(["Time", "Upload (B/s)", "Download (B/s)", "Total (B)"])
                    for entry in self.bwidth_monitor.history: writer.writerow([entry['time'].strftime('%Y-%m-%d %H:%M:%S'), f"{entry['upload_speed']:.2f}", f"{entry['download_speed']:.2f}", entry['total']])
                else:
                    writer.writerow(["Time", "Source", "Destination", "Protocol", "Threats", "Severity"])
                    for p in self.packet_list: writer.writerow([p["timestamp"], f"{p['src']}{':'+p['sport'] if p['sport'] else ''}", f"{p['dst']}{':'+p['dport'] if p['dport'] else ''}", p["protocol"],
                    ", ".join(t['name'] for t in p["threat"]) if p["threat"] else "None", p["risk_lvl"]])
            QMessageBox.information(self, "Success", f"Saved to {fpath}")
        except Exception as e: QMessageBox.critical(self, "Error", f"Save failed: {str(e)}")

    def gen_report(self, bw_report=False):
        if not self.check_data(bw_report): return

        if not bw_report:
            extras = QCheckBox("Include detailed packet data"); bandwidth_check = QCheckBox("Include bandwidth statistics"); bandwidth_check.setChecked(True)
            dlg = QDialog(self); dlg.setWindowTitle("HTML Report Options"); dlg_layout = QVBoxLayout(dlg); dlg_layout.addWidget(extras); dlg_layout.addWidget(bandwidth_check)
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dlg.accept); buttons.rejected.connect(dlg.reject); dlg_layout.addWidget(buttons)
            if dlg.exec() != QDialog.DialogCode.Accepted: return

        fpath = QFileDialog.getSaveFileName(self, f"Save {'Bandwidth' if bw_report else 'HTML'} Report", f"{'bandwidth_report' if bw_report else 'packets'}.html", "HTML Files (*.html)")[0]
        if not fpath: return

        try:
            if bw_report:
 
                upload, download, total = self.bwidth_monitor.get_formatted_speeds()
                css = """body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:0;color:#333;line-height:1.6}
                .header{background:linear-gradient(45deg,#3498db,#2980b9);color:#fff;padding:20px;text-align:center;box-shadow:0 2px 5px rgba(0,0,0,0.1)}
                .summary{background:#ecf0f1;padding:20px;margin:20px;border-radius:5px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
                h2,h3{margin-top:0}
                table{width:100%;border-collapse:collapse;margin:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);max-width:calc(100% - 40px)}
                th{background:linear-gradient(45deg,#2980b9,#2c3e50);color:#fff;padding:12px 15px;text-align:left}
                td{padding:10px 15px;border-bottom:1px solid #ddd}
                tr:nth-child(even){background-color:#f9f9f9}
                tr:hover{background-color:#f1f1f1}
                .footer{text-align:center;margin-top:20px;color:#7f8c8d;font-size:0.8em;padding-bottom:20px}"""
                
                html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Bandwidth Report</title>
                <style>{css}</style></head>
                <body>
                <div class="header"><h2>Network Bandwidth Usage Report</h2></div>
                <div class="summary"><h3>Summary</h3><p>
                <b>Upload:</b> {upload}<br><b>Download:</b> {download}<br>
                <b>Total:</b> {total}<br><b>Duration:</b> {len(self.bwidth_monitor.history)} seconds
                </p></div>
                <h3>History</h3>
                <table><tr><th>Time</th><th>Upload</th><th>Download</th><th>Total</th></tr>"""

                for entry in list(self.bwidth_monitor.history)[-60:]:
                    f_up = lambda up: f"{up:.1f} B/s" if up < 1024 else f"{up/1024:.1f} KB/s" if up < 1024 * 1024 else f"{up/(1024*1024):.2f} MB/s"
                    f_down = lambda down: f"{down:.1f} B/s" if down < 1024 else f"{down/1024:.1f} KB/s" if down < 1024 * 1024 else f"{down/(1024*1024):.2f} MB/s"
                    f_tot = lambda tot: f"{tot} B" if tot < 1024 else f"{tot/1024:.1f} KB" if tot < 1024 * 1024 else f"{tot/(1024*1024):.2f} MB" if tot < 1024 * 1024 * 1024 else f"{tot/(1024*1024*1024):.2f} GB"
                    html += f'<tr><td>{entry["time"].strftime("%H:%M:%S")}</td><td>{f_up(entry["upload_speed"])}</td><td>{f_down(entry["download_speed"])}</td><td>{f_tot(entry["total"])}</td></tr>'
            else:
                
                css = """body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:0;color:#333;line-height:1.6}
                .hdr{background:linear-gradient(45deg,#2c3e50,#34495e);color:#fff;padding:20px;text-align:center;box-shadow:0 2px 5px rgba(0,0,0,0.1)}
                .bw-summary{background:#f8fbff;padding:20px;margin:20px;border-radius:5px;box-shadow:0 1px 3px rgba(0,0,0,0.1);border-left:4px solid #3498db}
                .filter-panel{background:#f5f5f5;padding:15px;margin:20px;border-radius:5px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
                select{padding:5px;margin:0 10px 0 5px;border:1px solid #ddd;border-radius:4px}
                table{width:calc(100% - 40px);border-collapse:collapse;margin:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
                th{background:linear-gradient(45deg,#27ae60,#2ecc71);color:#fff;padding:12px 15px;text-align:left}
                td{padding:10px 15px;border-bottom:1px solid #ddd}
                .HIGH{background:#ffcccc;color:#333;border-left:4px solid #e74c3c}
                .MEDIUM{background:#fff2cc;color:#333;border-left:4px solid #f39c12}
                .LOW{background:#ffffcc;color:#333;border-left:4px solid #fdfd96}
                .footer{text-align:center;margin:20px;color:#7f8c8d;font-size:0.8em}"""
             
                js = """function filter(){
                    const src = document.getElementById("src").value;
                    const dst = document.getElementById("dst").value;
                    const proto = document.getElementById("proto").value;
                    const risk = document.getElementById("risk").value;
                    let matches = 0, total = 0;
                    
                    document.querySelectorAll("table tr:not(.head)").forEach(row => {
                        total++;
                        const srcVal = row.cells[1].textContent;
                        const dstVal = row.cells[2].textContent;
                        const protoVal = row.cells[3].textContent;
                        const riskVal = row.cells[6].textContent;
                        
                        const srcMatch = src === "all" || srcVal.includes(src);
                        const dstMatch = dst === "all" || dstVal.includes(dst);
                        const protoMatch = proto === "all" || protoVal === proto;
                        const riskMatch = risk === "all" || riskVal === risk;
                        
                        const visible = srcMatch && dstMatch && protoMatch && riskMatch;
                        row.style.display = visible ? "" : "none";
                        if(visible) matches++;
                    });
                    
                    document.getElementById("filter-count").textContent = `Showing ${matches} of ${total} packets`;
                }"""
                
                html = f"""<!DOCTYPE html>
                <html><head><meta charset="UTF-8">
                <title>Network Traffic Analysis</title>
                <style>{css}</style>
                <script>{js}</script>
                </head>
                <body>
                <div class="hdr"><h2>Network Traffic Analysis Report</h2></div>"""

                if bandwidth_check.isChecked() and self.bwidth_monitor.history:
                    upload, download, total = self.bwidth_monitor.get_formatted_speeds()
                    html += f"""<div class="bw-summary">
                    <h3>Bandwidth Summary</h3>
                    <p><b>Upload:</b> {upload} &nbsp; <b>Download:</b> {download} &nbsp; <b>Total:</b> {total}</p>
                    </div>"""
                
                src_ips = set(p["src"] for p in self.packet_list)
                src_options = ''.join(f'<option value="{ip}">{ip}</option>' for ip in src_ips)
                
                dst_ips = set(p["dst"] for p in self.packet_list)
                dst_options = ''.join(f'<option value="{ip}">{ip}</option>' for ip in dst_ips)
                
                protocols = set(p["protocol"] for p in self.packet_list)
                proto_options = ''.join(f'<option value="{p}">{p}</option>' for p in protocols)
                
                risk_levels = set(p["risk_lvl"] for p in self.packet_list)
                risk_options = ''.join(f'<option value="{r}">{r}</option>' for r in risk_levels)
                
                html += f"""<div class="filter-panel">
                <h3>Filter Traffic</h3>
                <div>
                    Source IP: <select id="src" onchange="filter()"><option value="all">All</option>{src_options}</select>
                    Destination IP: <select id="dst" onchange="filter()"><option value="all">All</option>{dst_options}</select>
                    Protocol: <select id="proto" onchange="filter()"><option value="all">All</option>{proto_options}</select>
                    Risk Level: <select id="risk" onchange="filter()"><option value="all">All</option>{risk_options}</select>
                </div>
                <div id="filter-count" style="margin-top:10px">Showing {len(self.packet_list)} of {len(self.packet_list)} packets</div>
                </div>
                <table>
                <tr class="head">
                    <th>Time</th><th>Source</th><th>Dest</th><th>Protocol</th><th>Port</th>
                    <th>Threat</th><th>Severity</th>{("<th>TTL</th><th>Len</th><th>Flags</th>") if extras.isChecked() else ""}
                </tr>"""
           
                for p in self.packet_list:
                    src_text = f"{p['src']}{':'+p['sport'] if p['sport'] else ''}"
                    dst_text = f"{p['dst']}{':'+p['dport'] if p['dport'] else ''}"
                    threat_text = ", ".join(t["name"] for t in p["threat"]) if p["threat"] else "None"
                    extra = ""
                    if extras.isChecked() and p.get("raw_pkt"):
                        pkt = p["raw_pkt"]
                        extra = f"<td>{getattr(pkt[IP], 'ttl', '') if IP in pkt else ''}</td><td>{len(pkt) if pkt else ''}</td><td>{getattr(pkt[TCP], 'flags', '') if TCP in pkt else ''}</td>"
                    html += f'<tr class="{p["risk_lvl"]}"><td>{p["timestamp"]}</td><td>{src_text}</td><td>{dst_text}</td><td>{p["protocol"]}</td><td>{p.get("sport", "-")}/{p.get("dport", "-")}</td><td>{threat_text}</td><td>{p["risk_lvl"]}</td>{extra}</tr>'
            
            html += f"""</table>
            <div class="footer">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Network Traffic Monitor</div>
            </body></html>"""
            
            with open(fpath, "w", encoding="utf-8") as f: f.write(html)
            QMessageBox.information(self, "Success", f"Report saved to {fpath}")
        except Exception as e: QMessageBox.critical(self, "Error", f"Report generation failed: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = analysernetwork()
    window.show()
    sys.exit(app.exec())