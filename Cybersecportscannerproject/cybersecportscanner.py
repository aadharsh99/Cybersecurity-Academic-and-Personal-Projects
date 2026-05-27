import sys, socket, os, re, json, logging, time, asyncio, html; from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional; from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QFormLayout, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox, QComboBox, QHBoxLayout, QGroupBox, QFileDialog, QProgressBar, QTabWidget, QSpinBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMutex; import requests, aiohttp

try:
    from scapy.all import IP, TCP, UDP, sr1, RandShort, ARP, Ether, srp; from scapy.layers.inet import ICMP
except Exception:
    IP = TCP = UDP = sr1 = RandShort = ARP = Ether = srp = ICMP = None
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(), logging.FileHandler(Path(__file__).resolve().parent / 'scanner.log', encoding='utf-8')])
logger = logging.getLogger(__name__); base_dir = Path(__file__).resolve().parent; logger.info('=' * 70)
logger.info(f' Base directory: {base_dir}')
logger.info('nvdapikey.json:     found' if (base_dir / 'nvdapikey.json').exists() else 'nvdapikey.json:     MISSING - CVE lookup disabled')
logger.info('chatgptapikey.json: found' if (base_dir / 'chatgptapikey.json').exists() else 'chatgptapikey.json: MISSING - AI features disabled')
logger.info('=' * 70)
# Final Year Project - CyberSec Port Scanner
# loads API key settings from local json files (kept local for convenience)

# loads saved settings / config values
def load_config():

    cfg = {'nvd_api_key': '', 'openai_api_key': ''}
    for file, key in [(base_dir / 'nvdapikey.json', 'nvd_api_key'), (base_dir / 'chatgptapikey.json', 'openai_api_key')]:
        if file.exists():
            try:
                data = json.load(open(file, 'r', encoding='utf-8'))
                if key == 'openai_api_key':
                    val = data.get('openai_api_key') or data.get('api_key') or data.get('chatgpt_api_key') or ''
                    if val and (not val.startswith('YOUR_')):
                        cfg[key] = val
                else:
                    cfg.update(data)
            except Exception as e:
                logger.error(f'{file.name}: {e}')
    return cfg


# shared config used across the scanner

# main config class
class Config:

    CONFIG = load_config()
    NVD_API_KEY, OPENAI_API_KEY = (CONFIG.get('nvd_api_key', ''), CONFIG.get('openai_api_key', ''))
    MAX_THREADS = min(50, (os.cpu_count() or 4) * 3); SOCKET_TIMEOUT, BANNER_TIMEOUT = (1, 2)
    CVE_RATE_LIMIT_DELAY, MAX_RETRIES, BACKOFF_FACTOR = (0.6, 3, 0.3)

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]

def parse_ai_text(text):

    p = re.search('Priority:\\s*(High|Medium|Low)', text, re.IGNORECASE)
    c = re.search('Confidence:\\s*(\\d{1,3})', text)
    return (p.group(1).upper() if p else 'UNKNOWN', c.group(1) if c else '0')

def extract_product_from_banner(banner):

    if not banner:
        return ''
    m = re.search('([A-Za-z0-9\\-_]+)[\\/\\s_](\\d+(\\.\\d+)*)', banner)
    if m and m.group(1).lower() not in ('http', 'https', 'ftp', 'ssh', 'ssl', 'tls'):
        return m.group(1)
    return ''

def validate_ip(ip):

    pattern = re.compile('^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$')
    for addr in [x.strip() for x in ip.split(',')]:
        if not pattern.match(addr):
            return False

        if not all((0 <= int(p) <= 255 for p in addr.split('.'))):
            return False
    return True

def parse_ports(text):

    ports = set()
    for part in text.split(','):
        part = part.strip()
        if not part:
            raise ValueError('Empty port entry')
        if part.count('-') > 1:
            raise ValueError(f'Invalid range: {part}')

        if '-' in part:
            s, e = map(int, part.split('-', 1))
            if not 1 <= s <= e <= 65535:
                raise ValueError(f'Invalid range: {part}')
            ports.update(range(s, e + 1))
        else:
            if not part.isdigit():
                raise ValueError(f'Invalid port: {part}')
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f'Port out of range: {p}')
            ports.add(p)
    return sorted(ports)


# handles AI risk summaries for discovered services
class RiskAnalyzer:


    def ai_risk_level(self, port, service, banner, cves, vuln, focus):

        if not Config.OPENAI_API_KEY:
            return 'Priority: Unknown\nConfidence: 0\nSummary:\nAI disabled.'



        prompt = f"You are a cybersecurity engineer. Return ONLY:\nPriority: High|Medium|Low\nConfidence: 0-100\nSummary:\n<2-3 sentences>\nTop Steps:\n1. ...\n2. ...\n3. ...\nEstimated time: <time>\nNote: <key note>\nData: Port:{port} Service:{service} Banner:{banner} CVEs:{(','.join(cves) if cves else 'None')} Vulnerability:{vuln} Focus:{focus}"
        try:
            r = requests.post('https://api.openai.com/v1/chat/completions', headers={'Authorization': f'Bearer {Config.OPENAI_API_KEY}', 'Content-Type': 'application/json'}, json={'model': 'gpt-4o-mini', 'messages': [{'role': 'system', 'content': 'You are a cybersecurity engineer.'}, {'role': 'user', 'content': prompt}], 'temperature': 0, 'max_tokens': 250}, timeout=30)
            r.raise_for_status(); return r.json()['choices'][0]['message']['content'].strip()
        except Exception as e:
            logger.error(f'[OpenAI] port {port}: {e}')
            return 'Priority: Unknown\nConfidence: 0\nSummary:\nAI unavailable.'
# handles NVD CVE lookup + caching
class CVELookup:


    def __init__(self, thread=None):

        self._cache, self._cache_max = ({}, 500); self.max_cves, self.thread = (5, thread)

    @staticmethod
    def _cache_key(service, tags, banner=''):

        import hashlib; bh = hashlib.md5(banner.encode()).hexdigest()[:16] if banner else 'no_banner'
        product = extract_product_from_banner(banner)
        tags = tuple(sorted(set((t.lower() for t in tags if t != 'unknown'))))
        return (service.lower(), product.lower(), bh, tags)

    def _cleanup(self):

        if len(self._cache) > self._cache_max:
            before = len(self._cache); self._cache = dict(list(self._cache.items())[-400:])
            logger.info(f'[CVE Cache] Cache cleanup: {before} -> {len(self._cache)} entries')

    async def _fetch_with_rate_limit(self, session, kw, sem):
        if self.thread and (not self.thread.running):
            raise asyncio.CancelledError('Scan stopped')
        await asyncio.sleep(Config.CVE_RATE_LIMIT_DELAY)
        async with sem:
            if self.thread and (not self.thread.running):
                raise asyncio.CancelledError('Scan stopped')
            hdrs = {'User-Agent': 'CyberSecPortScanner/1.0'}
            if Config.NVD_API_KEY:
                hdrs['apiKey'] = Config.NVD_API_KEY
            url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&resultsPerPage=5'
            async with session.get(url, headers=hdrs) as resp:
                return await resp.json()

    async def get_cves_async(self, service, tags, banner):
        if self.thread and (not self.thread.running) or service in ('unknown', 'N/A', ''):
            return []
        keywords = []; product = extract_product_from_banner(banner)
        if product and product.lower() not in ('http', 'https', 'ftp', 'ssh', 'smtp'):
            keywords.append(product.lower())
        elif service.lower() not in ('http', 'https', 'ftp', 'ssh', 'smtp', 'unknown'):
            keywords.append(service.lower())

        keywords.extend([t.lower() for t in tags])
        keywords = list(set((k for k in keywords if k not in ('unknown', ''))))[:2]
        if not keywords:
            return []
        try:
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(3)
                results = await asyncio.gather(*[self._fetch_with_rate_limit(session, kw, sem) for kw in keywords], return_exceptions=True)
        except asyncio.CancelledError:
            return []


        cves, seen = ([], set())
        for data in results:
            if isinstance(data, dict):
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {}); cid = cve.get('id', 'Unknown')
                    if cid in seen:
                        continue
                    seen.add(cid)

                    desc = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
                    cves.append(f'{cid} | {desc}')
                    if len(cves) >= self.max_cves:
                        break
        return cves



    def get_cves(self, service, tags, banner=''):

        if self.thread and (not self.thread.running):
            return []


        key = self._cache_key(service, tuple(tags), banner)
        if key in self._cache:
            product = extract_product_from_banner(banner); label = product if product else service
            logger.info(f"[CVE Cache] Cache HIT for '{label}' - skipping API call ({len(self._cache)} entries cached)")
            return self._cache[key]


        if self.thread and (not self.thread.running):
            return []
        try:
            cves = asyncio.run(self.get_cves_async(service, tags, banner))
        except (asyncio.CancelledError, Exception) as e:
            logger.error(f'CVE lookup error: {e}'); return []
        if self.thread and (not self.thread.running):
            return []
        self._cleanup(); product = extract_product_from_banner(banner)

        label = product if product else service
        logger.info(f"[CVE Cache] Cache MISS for '{label}' - stored {len(cves)} CVEs to cache")
        self._cache[key] = cves; return cves
# service detection + banner grabbing
class ServiceDetector:


    @staticmethod
    def get_banner(ip, port, timeout=Config.BANNER_TIMEOUT):

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout); s.connect((ip, port))
                if port in [80, 8080]:
                    s.send(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
                    raw = s.recv(2048).decode('utf-8', 'ignore')[:1024]
                    m = re.search('Server:\\s*([^\\r\\n]+)', raw, re.IGNORECASE)
                    return m.group(1).strip()[:250] if m else raw.split('\n')[0][:250]
                elif port == 21:
                    s.send(b'USER anonymous\r\n')
                elif port == 443:
                    return 'TLS/HTTPS (banner unavailable)'


                elif port == 25:
                    s.send(b'EHLO test\r\n')
                elif port == 110:
                    s.send(b'USER test\r\n')
                elif port == 143:
                    s.send(b'LOGIN test test\r\n')

                else:
                    s.send(b'\r\n')
                return s.recv(1024).decode('utf-8', 'ignore').strip()[:512].split('\n')[0][:250]
        except Exception as e:
            logger.debug(f'Banner grab {ip}:{port} - {e}'); return None



    @staticmethod
    def detect_service(port, proto='TCP'):

        try:
            return (socket.getservbyport(port, proto.lower()), 'unknown')
        except:

            return ('unknown', 'unknown')

    @staticmethod
    def check_vulnerabilities(ip, port, banner, service):

        vulns = []
        if port == 21:
            try:
                with socket.socket() as s:
                    s.settimeout(2); s.connect((ip, port))
                    if '220' in s.recv(1024).decode('utf-8', 'ignore'):
                        s.send(b'USER anonymous\r\n'); s.recv(1024); s.send(b'PASS guest\r\n')
                        if '230' in s.recv(1024).decode('utf-8', 'ignore'):
                            vulns.append('Anonymous FTP allowed')
            except:
                pass
        if banner and banner != 'N/A':
            bl = banner.lower()
            if 'apache/1.' in bl or 'apache/2.0' in bl or 'apache/2.2' in bl:
                vulns.append('Outdated Apache')
            if 'openssh' in bl:
                m = re.search('openssh[_\\s]*([\\d.]+)', bl)
                if m:
                    try:
                        if float('.'.join(m.group(1).split('.')[:2])) < 7.4:
                            vulns.append('Outdated OpenSSH')
                    except:
                        pass
            if 'lighttpd' in bl:
                m = re.search('lighttpd/([\\d.]+)', bl)
                if m:
                    try:
                        p = [int(x) for x in m.group(1).split('.')]
                        if p[0] == 1 and p[1] == 4 and (p[2] < 50):
                            vulns.append('Outdated lighttpd')

                    except:
                        pass
            if 'php/' in bl:
                vulns.append('PHP version disclosure')
        port_vulns = {23: 'Telnet (unencrypted)', 21: 'FTP (unencrypted)', 80: 'HTTP (unencrypted)', 3306: 'MySQL exposed', 5432: 'PostgreSQL exposed', 3389: 'RDP exposed', 445: 'SMB exposed'}
        if port in port_vulns and port_vulns[port] not in ' '.join(vulns):
            vulns.append(port_vulns[port])
        return '; '.join(vulns) if vulns else 'None detected'


# thread for one AI risk response
class AIThread(QThread):

    finished_signal = pyqtSignal(str)

    def __init__(self, port, service, banner, cves, vuln, focus):


        super().__init__()

        self.port, self.service, self.banner, self.cves, self.vuln, self.focus, self.running = (port, service, banner, cves, vuln, focus, True)


    def run(self):

        
        if self.running:
            risk = RiskAnalyzer().ai_risk_level(self.port, self.service, self.banner, self.cves, self.vuln, self.focus)
            if self.running:
                self.finished_signal.emit(risk)

    def stop(self):
        self.running = False
# thread for AI risk on all open ports
class AIRiskAllThread(QThread):

    finished_signal = pyqtSignal(list)

    def __init__(self, scan_results, focus):


        super().__init__(); self.scan_results = scan_results; self.focus = focus; self.running = True

    def run(self):

        try:
            if not self.running:
                return
            ra, open_ports = (RiskAnalyzer(), [r for r in self.scan_results if r['status'] != 'Closed'])


            async def gather():
                loop = asyncio.get_running_loop()
                tasks = [loop.run_in_executor(None, ra.ai_risk_level, r['port'], r['service'], r['banner'], r['cves'], r['vulnerability'], self.focus) for r in open_ports if self.running]
                return await asyncio.gather(*tasks) if self.running else []
            results = asyncio.run(gather())
            if self.running:
                self.finished_signal.emit([(open_ports[i]['port'], results[i]) for i in range(len(open_ports))])
        except Exception as e:
            logger.error(f'AI risk failed: {e}'); self.finished_signal.emit([])

    def stop(self):

        self.running = False
# main scan thread so the GUI does not freeze
class PortScannerThread(QThread):

    update_output = pyqtSignal(str); scan_finished = pyqtSignal(); scan_stopped = pyqtSignal()
    progress_update = pyqtSignal()

    def __init__(self, ip, ports, scan_type, multi_ip=False):

        super().__init__(); self.ip, self.ports, self.scan_type = (ip, ports, scan_type)
        self.cve, self.svc = (CVELookup(thread=self), ServiceDetector())
        self.running, self.results, self.mutex, self._buffer = (True, [], QMutex(), [])
        self.multi_ip = multi_ip

    def get_results(self):

        try:
            self.mutex.lock(); return list(self.results)
        finally:
            self.mutex.unlock()
    def run(self):
        self.update_output.emit(f"\n{'═' * 70}\n  Scanning {self.ip} - {len(self.ports)} ports ({self.scan_type})\n{'═' * 70}\n")
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as exe:
            futures = {exe.submit(self.scan_port, p): p for p in self.ports}
            for f in as_completed(futures):
                if not self.running:
                    exe.shutdown(wait=False, cancel_futures=True); self.update_output.emit('Stopped')
                    self.scan_stopped.emit(); return
                try:
                    f.result(); self.progress_update.emit()
                except Exception as e:
                    logger.error(f'Scan error: {e}')
        if self._buffer:
            self.update_output.emit('\n'.join(self._buffer)); self._buffer.clear()
        open_c = sum((1 for r in self.results if r['status'] != 'Closed'))
        logger.info(f'Scan done: {self.ip} | {time.time() - t0:.2f}s | Open: {open_c}/{len(self.ports)}')
        self.scan_finished.emit()
# actual scanning logic for the target
    def scan_port(self, port):
        if self.scan_type == 'TCP Connect':
            self.tcp_connect(port)
        elif self.scan_type == 'TCP FIN':
            self.tcp_fin(port)
        elif self.scan_type == 'TCP ACK':
            self.tcp_ack(port)
        elif self.scan_type == 'TCP XMAS':
            self.tcp_xmas(port)
        elif self.scan_type == 'UDP':
            self.udp_scan(port)
    def tcp_connect(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(Config.SOCKET_TIMEOUT)
                if s.connect_ex((self.ip, port)) == 0:
                    if not self.running:
                        return
                    svc, ver = self.svc.detect_service(port); banner = self.svc.get_banner(self.ip, port)
                    if not self.running:
                        return
                    vuln = self.svc.check_vulnerabilities(self.ip, port, banner or '', svc)
                    cves = self.cve.get_cves(svc, tuple([]), banner) if svc != 'unknown' else []
                    self.display_result(port, svc, ver, banner, vuln, cves)
                else:
                    self.display_closed(port)
        except Exception as e:
            logger.debug(f'TCP {self.ip}:{port}: {e}'); self.display_closed(port)
    def _scapy_tcp(self, port, flags):
        if not IP:
            return None
        try:
            return sr1(IP(dst=self.ip) / TCP(dport=port, flags=flags, sport=RandShort()), timeout=Config.SOCKET_TIMEOUT, verbose=0)
        except:
            return None
    def tcp_fin(self, port):
        resp = self._scapy_tcp(port, 'F')
        if resp and resp.haslayer(TCP) and (resp.getlayer(TCP).flags == 20):
            self.display_closed(port)
        else:
            self.display_result(port, 'unknown', 'unknown', 'N/A', 'N/A', [], status='Filtered')
    def tcp_ack(self, port):
        resp = self._scapy_tcp(port, 'A')
        if resp and resp.haslayer(TCP) and (resp.getlayer(TCP).flags == 4):
            self.display_closed(port)
        else:
            self.display_result(port, 'unknown', 'unknown', 'N/A', 'N/A', [], status='Filtered')
    def tcp_xmas(self, port):
        resp = self._scapy_tcp(port, 'FPU')
        if resp and resp.haslayer(TCP) and (resp.getlayer(TCP).flags == 20):
            self.display_closed(port)
        else:
            self.display_result(port, 'unknown', 'unknown', 'N/A', 'N/A', [], status='Filtered')
    def udp_scan(self, port):
        if not IP:
            self.display_closed(port, 'UDP'); return
        try:
            resp = sr1(IP(dst=self.ip) / UDP(dport=port), timeout=2, verbose=0)
            if resp is None:
                self.display_result(port, 'unknown', 'unknown', 'N/A', 'N/A', [], udp=True, status='Open|Filtered')
            elif resp.haslayer(UDP):
                self.display_result(port, 'unknown', 'unknown', 'N/A', 'N/A', [], udp=True, status='Open')
            elif resp.haslayer(ICMP):
                icmp = resp.getlayer(ICMP)
                if icmp.type == 3 and icmp.code == 3:
                    self.display_closed(port, 'UDP')
                else:
                    self.display_result(port, 'unknown', 'unknown', 'N/A', 'N/A', [], udp=True, status='Open|Filtered')
            else:
                self.display_closed(port, 'UDP')
        except Exception as e:
            logger.debug(f'UDP {self.ip}:{port}: {e}'); self.display_closed(port, 'UDP')
    def display_result(self, port, svc, ver, banner, vuln, cves, udp=False, status='Open'):
        proto = 'UDP' if udp else 'TCP'
        if cves:
            cve_lines = '\n'.join((f"     {i}. {c.split('|')[0].strip()}\n        {(c.split('|')[1].strip() if '|' in c else 'No description')}" for i, c in enumerate(cves, 1)))
            cve_display = f'{len(cves)} found:\n{cve_lines}'
        else:
            cve_display = 'None found'
        ip_label = f' [{self.ip}]' if self.multi_ip else ''
        msg = f"\n{'─' * 70}\n PORT {port}/{proto}{ip_label} - {status.upper()}\n{'─' * 70}\n  Service:        {svc} ({ver})\n  Banner:         {banner or 'N/A'}\n  Vulnerability:  {vuln}\n  CVEs:           {cve_display}\n"
        try:
            self.mutex.lock(); self._buffer.append(msg)
            if len(self._buffer) >= 5:
                self.update_output.emit('\n'.join(self._buffer)); self._buffer.clear()
            self.results.append({'host': self.ip, 'port': port, 'protocol': proto, 'status': status, 'service': svc, 'version': ver, 'banner': banner or 'N/A', 'risk': 'N/A', 'cves': cves, 'vulnerability': vuln})
        finally:
            self.mutex.unlock()
    def display_closed(self, port, proto='TCP'):
        try:
            self.mutex.lock()
            self.results.append({'host': self.ip, 'port': port, 'protocol': proto, 'status': 'Closed', 'service': 'N/A', 'version': 'N/A', 'banner': 'N/A', 'risk': 'N/A', 'cves': [], 'vulnerability': 'N/A'})
        finally:
            self.mutex.unlock()
# thread for local network discovery with ARP
class NetworkDiscoveryThread(QThread):
    update_output = pyqtSignal(str); discovery_finished = pyqtSignal()
    def __init__(self, ip):
        super().__init__(); self.ip = ip
    def run(self):
        if not ARP:
            self.update_output.emit('Scapy not available. Discovery disabled.')
            self.discovery_finished.emit(); return
        subnet = '.'.join(self.ip.split('.')[:-1]) + '.0/24'; self.update_output.emit(f'Discovering {subnet}')
        try:
            ans = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=subnet), timeout=3, verbose=0)[0]
            devices = [(r.psrc, r.hwsrc) for s, r in ans]
            if devices:
                self.update_output.emit(f'Found {len(devices)} devices')
                for ip, mac in devices:
                    self.update_output.emit(f'  • IP: {ip} | MAC: {mac}')
            else:
                self.update_output.emit('No devices found')
        except Exception as e:
            self.update_output.emit(f'Error: {e}')
        self.discovery_finished.emit()
# GUI includes scan controls, AI output and HTML report stuff
# main GUI window
class PortScannerGUI(QWidget):
    def __init__(self):
        super().__init__(); self.setWindowTitle('CyberSec Port Scanner'); self.setMinimumSize(1200, 900)
        self.setStyleSheet('\n            QWidget{background-color:#f5f7fa} QLabel{font-size:14px;color:#2c3e50}\n            QLineEdit,QComboBox,QSpinBox{padding:8px;font-size:13px;border:2px solid #bdc3c7;border-radius:4px;background:white}\n            QLineEdit:focus,QComboBox:focus{border-color:#3498db}\n            QPushButton{padding:10px 16px;font-size:13px;border-radius:4px;border:none;background:#3498db;color:white;font-weight:bold}\n            QPushButton:hover{background:#2980b9} QPushButton:disabled{background:#95a5a6}\n            QTextEdit{background:#ecf0f1;border:2px solid #bdc3c7;border-radius:4px;font-family:Consolas,monospace}\n            QGroupBox{font-weight:bold;border:2px solid #bdc3c7;border-radius:6px;margin-top:12px;padding-top:12px;background:white}\n            QProgressBar{border:2px solid #bdc3c7;border-radius:4px;text-align:center;background:white}\n            QProgressBar::chunk{background:#3498db}')
        self.scan_threads, self.ai_thread, self.ai_risk_thread, self.scan_results, self.target_ip = ([], [], None, [], '')
        self.warning_shown = False; self.init_ui()
        if os.name == 'nt':
            for scan in ['UDP', 'TCP FIN', 'TCP ACK', 'TCP XMAS']:
                idx = self.scan_combo.findText(scan)
                if idx != -1 and (not IP):
                    self.scan_combo.removeItem(idx)
    def init_ui(self):
        layout = QVBoxLayout(self); layout.setSpacing(15); title = QLabel('CyberSec Port Scanner')
        title.setAlignment(Qt.AlignCenter); title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        title.setStyleSheet('color:#2c3e50;margin:10px;'); layout.addWidget(title)
        self.status_label = QLabel('Ready to scan'); self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet('color:#7f8c8d;font-style:italic;font-size:13px;')
        layout.addWidget(self.status_label); self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False); layout.addWidget(self.progress_bar); self.tabs = QTabWidget()
        layout.addWidget(self.tabs); scan_tab = QWidget(); scan_layout = QVBoxLayout(scan_tab)
        scan_layout.setSpacing(12); ig = QGroupBox('Scan Configuration'); il = QFormLayout()
        self.input_ip = QLineEdit()
        self.input_ip.setPlaceholderText('e.g., 192.168.1.1 or 192.168.1.1,192.168.1.2')
        self.input_ports = QLineEdit()
        self.input_ports.setPlaceholderText("e.g., 21,22,80-90,443 or 'common'")
        self.scan_combo = QComboBox()
        self.scan_combo.addItems(['TCP Connect', 'TCP FIN', 'TCP ACK', 'TCP XMAS', 'UDP'])
        il.addRow(QLabel('Target IP(s):'), self.input_ip); il.addRow(QLabel('Ports:'), self.input_ports)
        il.addRow(QLabel('Scan Type:'), self.scan_combo); ig.setLayout(il); scan_layout.addWidget(ig)
        btn_layout = QHBoxLayout(); self.btn_scan = QPushButton('Start Scan')
        self.btn_scan.clicked.connect(self.start_scan); self.btn_stop = QPushButton('Stop')
        self.btn_stop.clicked.connect(self.stop_scan); self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet('QPushButton{background:#e74c3c}')
        self.btn_discover = QPushButton('Discovery'); self.btn_discover.clicked.connect(self.start_discovery)
        self.btn_html = QPushButton('HTML'); self.btn_html.clicked.connect(self.save_html)
        self.btn_html.setEnabled(False); self.btn_ai = QPushButton('AI Mitigation')
        self.btn_ai.clicked.connect(self.show_ai_tab); self.btn_ai.setEnabled(False)
        self.btn_risk = QPushButton('Calculate Risk (AI)')
        self.btn_risk.clicked.connect(self.calculate_ai_risk); self.btn_risk.setEnabled(False)
        self.btn_clear = QPushButton('Clear'); self.btn_clear.clicked.connect(self.clear_output)
        for btn in [self.btn_scan, self.btn_stop, self.btn_discover, self.btn_html, self.btn_ai, self.btn_risk, self.btn_clear]:
            btn_layout.addWidget(btn)
        scan_layout.addLayout(btn_layout); self.risk_label = QLabel('Risk: N/A')
        self.risk_label.setAlignment(Qt.AlignCenter)
        self.risk_label.setStyleSheet('font-weight:bold;font-size:14px;')
        scan_layout.addWidget(self.risk_label); self.output = QTextEdit(); self.output.setReadOnly(True)
        self.output.setFont(QFont('Consolas', 10)); scan_layout.addWidget(self.output)
        self.tabs.addTab(scan_tab, 'Scan'); ai_tab = QWidget(); ai_layout = QVBoxLayout(ai_tab)
        ai_layout.setSpacing(10); self.ai_focus_combo = QComboBox()
        self.ai_focus_combo.addItems(['Patching', 'Firewall', 'Monitoring', 'Hardening'])
        self.ai_generate_btn = QPushButton('Generate AI Mitigation')
        self.ai_generate_btn.clicked.connect(self.generate_ai); self.ai_generate_btn.setEnabled(False)
        self.ai_output = QTextEdit(); self.ai_output.setReadOnly(True)
        self.ai_output.setFont(QFont('Consolas', 10)); ai_layout.addWidget(QLabel('Focus:'))
        ai_layout.addWidget(self.ai_focus_combo); ai_layout.addWidget(self.ai_generate_btn)
        ai_layout.addWidget(self.ai_output); self.tabs.addTab(ai_tab, 'AI Mitigation')
        self.input_ip.setFocus()
    def _reset_output(self):
        self.output.clear(); self.ai_output.clear(); self.scan_results = []
        self.status_label.setText('Ready to scan'); self.risk_label.setText('Risk: N/A')
    def clear_output(self):
        logger.info('[User Action] User clicked Clear - output and results reset'); self._reset_output()
    def set_ui_scanning(self, scanning):
        widgets = [self.btn_scan, self.btn_discover, self.btn_clear, self.input_ip, self.input_ports, self.scan_combo]
        for w in widgets:
            w.setEnabled(not scanning)
        self.btn_stop.setEnabled(scanning)
    def start_scan(self):
        if not self.warning_shown:
            reply = QMessageBox.question(self, 'Security Warning', 'You must only scan systems you own or have permission to test.\nContinue?', QMessageBox.Yes | QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
        self.warning_shown = True; ips = [x.strip() for x in self.input_ip.text().split(',')]
        ports_text, scan_type = (self.input_ports.text().strip(), self.scan_combo.currentText())
        if scan_type in ['TCP FIN', 'TCP ACK', 'TCP XMAS', 'UDP'] and (not IP):
            QMessageBox.warning(self, 'Dependencies', 'Scapy is required for this scan type.'); return
        if not validate_ip(self.input_ip.text().strip()):
            QMessageBox.warning(self, 'Invalid IP', 'Enter a valid IPv4 address or comma-separated list')
            return
        if not ports_text:
            QMessageBox.warning(self, 'Invalid Ports', 'Specify ports to scan'); return
        try:
            ports = Config.COMMON_PORTS if ports_text.lower() == 'common' else parse_ports(ports_text)
            if len(ports) > 10000 and QMessageBox.question(self, 'Large Scan', f'Scan {len(ports)} ports?') == QMessageBox.No:
                return
        except ValueError as e:
            QMessageBox.warning(self, 'Invalid Ports', str(e)); return
        self._reset_output(); self.target_ip = ', '.join(ips)
        logger.info(f"[User Action] Scan started | Targets: {', '.join(ips)} | Ports: {len(ports)} | Type: {scan_type}")
        self.status_label.setText(f'Scanning {self.target_ip} ...'); self.set_ui_scanning(True)
        self.progress_bar.setVisible(True); self.progress_bar.setValue(0); self.scan_results = []
        self.scan_threads = []; self.total_ports = len(ips) * len(ports); self.scanned_ports = 0
        def on_progress():
            self.scanned_ports += 1
            self.progress_bar.setValue(int(self.scanned_ports / self.total_ports * 100))
        for ip in ips:
            t = PortScannerThread(ip, ports, scan_type, multi_ip=len(ips) > 1); t.update_output.connect(self.output.append)
            t.progress_update.connect(on_progress); t.scan_finished.connect(self.on_single_host_finished)
            t.scan_stopped.connect(self.scan_stopped); self.scan_threads.append(t); t.start()
    def on_ai_finished(self, text):
        self.ai_output.clear(); self.ai_output.append(text); self.ai_generate_btn.setEnabled(True)
    def on_single_host_finished(self):
        self.scan_results = [r for t in self.scan_threads for r in t.get_results()]
        all_done = all((not t.isRunning() for t in self.scan_threads))
        if all_done:
            self.scan_finished()
    def stop_scan(self):
        logger.info('[User Action] Stop scan requested by user')
        for t in self.scan_threads:
            if t and t.isRunning():
                t.running = False
        for t in [self.ai_thread, self.ai_risk_thread]:
            if t and t.isRunning():
                t.stop()
        self.status_label.setText('Stopping...')
        self.progress_bar.setVisible(False)
        self.set_ui_scanning(False)
    def scan_finished(self):
        self.status_label.setText('Scan completed'); self.set_ui_scanning(False)
        self.progress_bar.setVisible(False)
        open_ports = [r for r in self.scan_results if r['status'] != 'Closed']
        closed_ports = [r for r in self.scan_results if r['status'] == 'Closed']
        self.output.append(f"\n{'═' * 70}\n  SCAN SUMMARY\n{'═' * 70}\n  Open ports:   {len(open_ports)}\n  Closed ports: {len(closed_ports)}\n  Total CVEs:   {sum((len(r.get('cves', [])) for r in open_ports))}\n{'═' * 70}")
        if closed_ports and len(closed_ports) <= 10:
            self.output.append('\nClosed ports:')
            multi_ip = len(set(r['host'] for r in self.scan_results)) > 1
            for c in closed_ports:
                ip_label = f" [{c['host']}]" if multi_ip else ''
                self.output.append(f"  • Port {c['port']}/{c['protocol']}{ip_label}")
        elif closed_ports:
            self.output.append(f'\n{len(closed_ports)} ports closed (not shown)')
        has_open = bool(open_ports)
        for btn in [self.btn_ai, self.btn_risk, self.btn_html, self.ai_generate_btn]:
            btn.setEnabled(has_open)
        self.tabs.setTabEnabled(1, has_open)
    def scan_stopped(self):
        self.status_label.setText('Stopped'); self.set_ui_scanning(False); self.progress_bar.setVisible(False)
        self.scan_results = [r for t in self.scan_threads for r in t.get_results()]
    def on_discovery_finished(self):
        self.status_label.setText('Discovery completed'); self.btn_discover.setEnabled(True)
    def start_discovery(self):
        logger.info(f"[User Action] Network discovery requested for: {self.input_ip.text().strip().split(',')[0]}")
        ip = self.input_ip.text().strip().split(',')[0]
        if not validate_ip(ip):
            QMessageBox.warning(self, 'Invalid IP', 'Enter a valid IPv4 address'); return
        self.output.clear(); self.status_label.setText('Discovering...'); self.btn_discover.setEnabled(False)
        self.disc_thread = NetworkDiscoveryThread(ip)
        self.disc_thread.update_output.connect(self.output.append)
        self.disc_thread.discovery_finished.connect(self.on_discovery_finished); self.disc_thread.start()
    def show_ai_tab(self):
        logger.info('[User Action] User switched to AI Mitigation tab'); self.tabs.setCurrentIndex(1)
# builds data for the report
    def generate_ai(self):
        if Config.OPENAI_API_KEY:
            logger.info(f'[User Action] AI mitigation requested | Focus: {self.ai_focus_combo.currentText()}')
        target = next((r for r in self.scan_results if r['status'] != 'Closed'), None)
        if not target:
            QMessageBox.information(self, 'AI', 'No open ports found.'); return
        self.ai_output.clear(); self.ai_output.append('Generating AI mitigation advice...')
        self.ai_generate_btn.setEnabled(False)
        self.ai_thread = AIThread(target['port'], target['service'], target['banner'], target['cves'], target['vulnerability'], self.ai_focus_combo.currentText().lower())
        self.ai_thread.finished_signal.connect(self.on_ai_finished); self.ai_thread.start()
    def calculate_ai_risk(self):
        if Config.OPENAI_API_KEY:
            logger.info(f'[User Action] AI risk calculation requested | Focus: {self.ai_focus_combo.currentText()}')
        if not any((r['status'] != 'Closed' for r in self.scan_results)):
            QMessageBox.information(self, 'AI Risk', 'No open ports found.'); return
        self.risk_label.setText('Risk: Calculating...'); self.btn_risk.setEnabled(False)
        self.ai_risk_thread = AIRiskAllThread(self.scan_results, self.ai_focus_combo.currentText().lower())
        self.ai_risk_thread.finished_signal.connect(self.on_ai_risk_finished); self.ai_risk_thread.start()
    def on_ai_risk_finished(self, results):
        for port, text in results:
            if 'AI unavailable' not in text:
                priority, confidence = parse_ai_text(text)
                for r in self.scan_results:
                    if r['port'] == port and r['status'] != 'Closed':
                        r['risk'] = f'{priority} ({confidence}%)'; break
        valid = [parse_ai_text(t)[0] for _, t in results if 'AI unavailable' not in t]
        top = 'HIGH' if 'HIGH' in valid else 'MEDIUM' if 'MEDIUM' in valid else 'LOW' if 'LOW' in valid else None
        label = f'Risk: {top} (calculated)' if top else 'Risk: Unknown (AI unavailable)'
        self.risk_label.setText(label); self.btn_risk.setEnabled(True)
# saves report/settings for later use
    def save_html(self):
        if not self.scan_results:
            QMessageBox.warning(self, 'No Data', 'No scan results to save'); return
        filepath, _ = QFileDialog.getSaveFileName(self, 'Save HTML Report', '', 'HTML (*.html)')
        if not filepath:
            return
        def esc(t):
            return html.escape(str(t or 'N/A'), quote=True)
        def risk_class(risk):
            r = str(risk).upper()
            if 'HIGH' in r:
                return 'high'
            if 'MEDIUM' in r:
                return 'medium'
            if 'LOW' in r:
                return 'low'
            return 'na'
        hosts = {}
        for r in self.scan_results:
            h = r.get('host', 'Unknown'); hosts.setdefault(h, []).append(r)
        total_open = sum((1 for r in self.scan_results if r['status'] != 'Closed'))
        total_cves = sum((len(r.get('cves', [])) for r in self.scan_results)); rows_html = ''
        for host, results in hosts.items():
            h_open = sum((1 for r in results if r['status'] != 'Closed'))
            h_cves = sum((len(r.get('cves', [])) for r in results))
            rows_html += f'\n<div class="host-card">\n  <div class="host-header">\n    <div class="host-title">&#x1F4BB; {esc(host)}</div>\n    <div class="host-meta">\n      <span class="meta-item">Scanned: <strong>{len(results)}</strong></span>\n      <span class="meta-item">Open: <strong>{h_open}</strong></span>\n      <span class="meta-item">CVEs: <strong>{h_cves}</strong></span>\n    </div>\n  </div>\n  <div class="filters">\n    <input class="search-box" placeholder="&#128269; Filter results..." oninput="filterTable(this)">\n    <select class="filter-sel" onchange="filterTable(this)">\n      <option value="">All Status</option>\n      <option value="open">Open</option>\n      <option value="closed">Closed</option>\n    </select>\n    <select class="filter-sel" onchange="filterTable(this)">\n      <option value="">All Risk</option>\n      <option value="high">High</option>\n      <option value="medium">Medium</option>\n      <option value="low">Low</option>\n      <option value="na">N/A</option>\n    </select>\n  </div>\n  <table class="results-table">\n    <thead>\n      <tr>\n        <th>Port</th><th>Proto</th><th>Status</th><th>Service</th>\n        <th>Banner</th><th>Risk</th><th>Vulnerability</th><th>CVEs</th>\n      </tr>\n    </thead>\n    <tbody>'
            for r in results:
                rc = risk_class(r['risk']); st = 'open' if r['status'] != 'Closed' else 'closed'
                banner_str = str(r['banner'] or 'N/A')
                banner_short = esc(banner_str[:57] + '...' if len(banner_str) > 60 else banner_str)
                cve_html = ''
                if r.get('cves'):
                    for cve in r['cves']:
                        parts = cve.split('|', 1); cid = esc(parts[0].strip()) if parts else ''
                        desc = esc(parts[1].strip()) if len(parts) > 1 else 'No description'
                        cve_html += f'<div class="cve-item"><span class="cve-id">{cid}</span><span class="cve-desc">{desc}</span></div>'
                else:
                    cve_html = '<span class="no-cve">None found</span>'
                rows_html += f'''\n      <tr class="data-row" data-status="{st}" data-risk="{rc}">\n        <td><strong>{esc(r['port'])}</strong></td>\n        <td>{esc(r['protocol'])}</td>\n        <td><span class="badge badge-{st}">{esc(r['status'])}</span></td>\n        <td>{esc(r['service'])}</td>\n        <td class="banner-cell" title="{esc(banner_str)}">{banner_short}</td>\n        <td><span class="badge badge-{rc}">{esc(r['risk'])}</span></td>\n        <td class="vuln-cell">{esc(r['vulnerability'])}</td>\n        <td>{len(r.get('cves', []))}</td>\n      </tr>\n      <tr class="detail-row" style="display:none">\n        <td colspan="8">\n          <div class="detail-panel">\n            <div class="detail-grid">\n              <div class="detail-block">\n                <h4>Port Details</h4>\n                <table class="detail-table">\n                  <tr><td>Host</td><td>{esc(r['host'])}</td></tr>\n                  <tr><td>Port</td><td>{esc(r['port'])}/{esc(r['protocol'])}</td></tr>\n                  <tr><td>Status</td><td>{esc(r['status'])}</td></tr>\n                  <tr><td>Service</td><td>{esc(r['service'])}</td></tr>\n                  <tr><td>Banner</td><td class="wrap">{esc(r['banner'])}</td></tr>\n                  <tr><td>Vulnerability</td><td class="wrap">{esc(r['vulnerability'])}</td></tr>\n                  <tr><td>Risk</td><td>{esc(r['risk'])}</td></tr>\n                </table>\n              </div>\n              <div class="detail-block">\n                <h4>CVE Records ({len(r.get('cves', []))} found)</h4>\n                <div class="cve-list">{cve_html}</div>\n              </div>\n            </div>\n          </div>\n        </td>\n      </tr>'''
            rows_html += '\n    </tbody>\n  </table>\n</div>'
        ai_text = self.ai_output.toPlainText() or 'No AI recommendations generated.'
        html_out = f"""<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>CyberSec Port Scanner &mdash; Report</title>\n<style>\n*{{margin:0;padding:0;box-sizing:border-box}}\nbody{{font-family:"Segoe UI",Arial,sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;min-height:100vh}}\n.container{{max-width:1400px;margin:0 auto}}\n.report-header{{background:linear-gradient(135deg,#16213e,#0f3460);border-radius:12px;padding:30px;margin-bottom:24px;border:1px solid #533483}}\n.report-title{{font-size:28px;font-weight:700;color:#e94560;margin-bottom:8px}}\n.report-meta{{display:flex;gap:24px;font-size:13px;color:#a0a0b0;flex-wrap:wrap}}\n.report-meta span strong{{color:#e0e0e0}}\n.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:16px;margin-bottom:24px}}\n.stat-card{{background:#16213e;border-radius:10px;padding:20px;text-align:center;border:1px solid #0f3460}}\n.stat-num{{font-size:36px;font-weight:700;background:linear-gradient(135deg,#e94560,#533483);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}\n.stat-label{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#808090;margin-top:4px}}\n.host-card{{background:#16213e;border-radius:12px;margin-bottom:24px;border:1px solid #0f3460;overflow:hidden}}\n.host-header{{background:#0f3460;padding:16px 20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}}\n.host-title{{font-size:16px;font-weight:600;color:#e94560}}\n.host-meta{{display:flex;gap:16px;font-size:12px;color:#a0a0b0}}\n.meta-item strong{{color:#e0e0e0}}\n.filters{{padding:12px 16px;background:#1a1a2e;display:flex;gap:10px;flex-wrap:wrap;border-bottom:1px solid #0f3460}}\n.search-box{{flex:1;min-width:200px;padding:8px 12px;background:#0f3460;border:1px solid #533483;border-radius:6px;color:#e0e0e0;font-size:13px}}\n.search-box::placeholder{{color:#606070}}\n.filter-sel{{padding:8px 12px;background:#0f3460;border:1px solid #533483;border-radius:6px;color:#e0e0e0;font-size:13px;cursor:pointer}}\n.results-table{{width:100%;border-collapse:collapse;font-size:13px}}\n.results-table thead{{background:#0f3460}}\n.results-table th{{padding:10px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:#a0a0b0;border-bottom:2px solid #533483}}\n.data-row{{border-bottom:1px solid #1e2a4a;cursor:pointer;transition:background 0.15s}}\n.data-row:hover{{background:#1e2a4a}}\n.data-row td{{padding:10px 12px;vertical-align:middle}}\n.banner-cell{{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#a0a0b0;font-size:12px}}\n.vuln-cell{{max-width:220px;font-size:12px;color:#d0a060;word-break:break-word}}\n.badge{{display:inline-block;padding:3px 10px;border-radius:20px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap}}\n.badge-open{{background:#1a4a2e;color:#4ade80;border:1px solid #166534}}\n.badge-closed{{background:#3a1a1a;color:#f87171;border:1px solid #991b1b}}\n.badge-high{{background:#4a1a1a;color:#f87171;border:1px solid #991b1b}}\n.badge-medium{{background:#4a3a1a;color:#fbbf24;border:1px solid #92400e}}\n.badge-low{{background:#1a3a2a;color:#4ade80;border:1px solid #166534}}\n.badge-na{{background:#2a2a3a;color:#808090;border:1px solid #404060}}\n.detail-row td{{padding:0}}\n.detail-panel{{background:#1a1a2e;padding:20px;border-top:1px solid #533483}}\n.detail-grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}\n@media(max-width:768px){{.detail-grid{{grid-template-columns:1fr}}}}\n.detail-block h4{{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#808090;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #2a2a4a}}\n.detail-table{{width:100%;border-collapse:collapse;font-size:12px}}\n.detail-table td{{padding:6px 8px;border-bottom:1px solid #1e2a4a;vertical-align:top}}\n.detail-table td:first-child{{color:#808090;width:100px;white-space:nowrap}}\n.detail-table td.wrap{{word-break:break-word;max-width:300px}}\n.cve-list{{display:flex;flex-direction:column;gap:8px;max-height:300px;overflow-y:auto}}\n.cve-item{{background:#0f3460;border-radius:6px;padding:10px;border-left:3px solid #e94560}}\n.cve-id{{display:block;font-weight:600;color:#e94560;font-size:12px;margin-bottom:4px}}\n.cve-desc{{display:block;font-size:11px;color:#a0a0b0;line-height:1.5;word-break:break-word}}\n.no-cve{{font-size:12px;color:#606070;font-style:italic}}\n.ai-section{{background:#16213e;border-radius:12px;padding:24px;margin-bottom:24px;border:1px solid #533483}}\n.ai-section h3{{font-size:16px;color:#e94560;margin-bottom:16px}}\n.ai-content{{background:#0f3460;border-radius:8px;padding:16px;font-size:13px;line-height:1.7;white-space:pre-wrap;color:#c0c0d0;border-left:4px solid #533483;word-break:break-word}}\n.report-footer{{text-align:center;padding:20px;color:#606070;font-size:12px}}\n.data-row.hidden{{display:none}}\n</style>\n</head>\n<body>\n<div class="container">\n  <div class="report-header">\n    <div class="report-title">&#x1F6E1; Network Security Scan Report</div>\n    <div class="report-meta">\n      <span>&#x1F4C5; <strong>{time.strftime('%B %d, %Y %H:%M')}</strong></span>\n      <span>&#x1F50D; Scan type: <strong>{esc(self.scan_combo.currentText())}</strong></span>\n      <span>&#x1F4BB; Hosts scanned: <strong>{len(hosts)}</strong></span>\n    </div>\n  </div>\n  <div class="stats-grid">\n    <div class="stat-card"><div class="stat-num">{len(hosts)}</div><div class="stat-label">Hosts</div></div>\n    <div class="stat-card"><div class="stat-num">{len(self.scan_results)}</div><div class="stat-label">Ports Scanned</div></div>\n    <div class="stat-card"><div class="stat-num">{total_open}</div><div class="stat-label">Open Ports</div></div>\n    <div class="stat-card"><div class="stat-num">{len(self.scan_results) - total_open}</div><div class="stat-label">Closed Ports</div></div>\n    <div class="stat-card"><div class="stat-num">{total_cves}</div><div class="stat-label">CVEs Found</div></div>\n  </div>\n  {rows_html}\n  <div class="ai-section">\n    <h3>&#x1F916; AI Security Recommendations</h3>\n    <div class="ai-content">{esc(ai_text)}</div>\n  </div>\n  <div class="report-footer">\n    CyberSec Port Scanner &bull; Report generated {time.strftime('%Y-%m-%d %H:%M:%S')}\n  </div>\n</div>\n<script>\ndocument.querySelectorAll('.data-row').forEach(row => {{\n  row.addEventListener('click', () => {{\n    const detail = row.nextElementSibling;\n    if (detail && detail.classList.contains('detail-row')) {{\n      detail.style.display = detail.style.display === 'table-row' ? 'none' : 'table-row';\n    }}\n  }});\n}});\n\nfunction filterTable(el) {{\n  const card = el.closest('.host-card');\n  const searchBox = card.querySelector('.search-box');\n  const selects = card.querySelectorAll('.filter-sel');\n  const statusFilter = selects[0].value.toLowerCase();\n  const riskFilter = selects[1].value.toLowerCase();\n  const searchTerm = searchBox.value.toLowerCase();\n  card.querySelectorAll('.data-row').forEach(row => {{\n    const matchStatus = !statusFilter || row.dataset.status === statusFilter;\n    const matchRisk = !riskFilter || row.dataset.risk === riskFilter;\n    const matchSearch = !searchTerm || row.textContent.toLowerCase().includes(searchTerm);\n    const visible = matchStatus && matchRisk && matchSearch;\n    row.classList.toggle('hidden', !visible);\n    const detail = row.nextElementSibling;\n    if (detail && detail.classList.contains('detail-row') && !visible) {{\n      detail.style.display = 'none';\n    }}\n  }});\n}}\n</script>\n</body>\n</html>"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_out)
            logger.info(f'HTML report saved: {filepath}')
            QMessageBox.information(self, 'Success', f'Report saved to {filepath}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Failed to save report: {e}')
            logger.error(f'Save HTML error: {e}')
    def closeEvent(self, event):
        for t in self.scan_threads:
            if t and t.isRunning():
                t.running = False; t.wait(1000)
        for t in [self.ai_thread, self.ai_risk_thread]:
            if t and t.isRunning():
                t.stop(); t.wait(1000)
        event.accept()
if __name__ == '__main__':
    try:
        app = QApplication(sys.argv); gui = PortScannerGUI(); gui.show(); sys.exit(app.exec_())
    except Exception as e:
        logger.critical(f'Fatal error: {e}', exc_info=True); sys.exit(1)