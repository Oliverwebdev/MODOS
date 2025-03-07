import time
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class AttackStats:
    start_time: float = field(default_factory=time.time)
    packets_sent: int = 0
    bytes_sent: int = 0
    connection_attempts: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    last_update: float = field(default_factory=time.time)
    attack_type: str = "unknown"
    response_times: List[float] = field(default_factory=list)
    status_codes: Dict[int, int] = field(default_factory=dict)
    blocks_detected: int = 0
    rate_limiting_detected: int = 0
    waf_detected: bool = False
    history: List[Dict[str, Any]] = field(default_factory=list)

    def update_sent(self, packets: int = 1, bytes_size: int = 0):
        self.packets_sent += packets
        self.bytes_sent += bytes_size

    def update_connections(self, success: bool = True):
        self.connection_attempts += 1
        if success:
            self.successful_connections += 1
        else:
            self.failed_connections += 1

    def add_response_time(self, time_ms: float):
        self.response_times.append(time_ms)
        if len(self.response_times) > 1000:
            self.response_times.pop(0)

    def add_status_code(self, code: int):
        self.status_codes[code] = self.status_codes.get(code, 0) + 1

    def detect_protection(self, status_code: int = None, response_time: float = None, response_body: str = None):
        if status_code in (403, 429) or (response_body and any(x in response_body.lower() for x in ['waf', 'firewall', 'security', 'blocked', 'rate limit'])):
            self.waf_detected = True
        if status_code == 429 or (response_time and response_time > 2000):
            self.rate_limiting_detected += 1
        if status_code in (403, 406, 429, 503):
            self.blocks_detected += 1

    def record_history(self):
        current_time = time.time()
        if not self.history or current_time - self.history[-1].get('timestamp', 0) >= 1.0:
            self.history.append({
                'timestamp': current_time,
                'packets_sent': self.packets_sent,
                'bytes_sent': self.bytes_sent,
                'pps': self.get_pps(),
                'bps': self.get_bps(),
                'success_rate': self.get_success_rate(),
                'blocks': self.blocks_detected,
                'rate_limits': self.rate_limiting_detected
            })
            if len(self.history) > 300:
                self.history.pop(0)

    def get_pps(self) -> float:
        elapsed = max(0.001, time.time() - self.start_time)
        return self.packets_sent / elapsed

    def get_bps(self) -> float:
        elapsed = max(0.001, time.time() - self.start_time)
        return self.bytes_sent / elapsed

    def get_elapsed(self) -> float:
        return time.time() - self.start_time

    def get_success_rate(self) -> float:
        if self.connection_attempts == 0:
            return 0
        return (self.successful_connections / self.connection_attempts) * 100

    def get_avg_response_time(self) -> float:
        if not self.response_times:
            return 0
        return sum(self.response_times) / len(self.response_times)

    def reset(self):
        old_history = self.history.copy()
        old_start = self.start_time
        self.packets_sent = 0
        self.bytes_sent = 0
        self.connection_attempts = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.response_times = []
        self.status_codes = {}
        self.blocks_detected = 0
        self.rate_limiting_detected = 0
        self.waf_detected = False
        self.history = old_history
        self.start_time = old_start

    def print_stats(self):
        current_time = time.time()
        if current_time - self.last_update < 1.0:
            return
        self.last_update = current_time
        print(f"[{self.attack_type}] Laufzeit: {self.get_elapsed():.1f}s | Pakete: {self.packets_sent} ({self.get_pps():.0f}/s) | Daten: {self.bytes_sent/1024/1024:.2f} MB ({self.get_bps()/1024/1024:.2f} MB/s)")
        if self.connection_attempts > 0:
            print(f"Verbindungen: {self.connection_attempts} | Erfolg: {self.successful_connections} | Fehlgeschlagen: {self.failed_connections} | Erfolgsrate: {self.get_success_rate():.1f}%")
        if self.waf_detected or self.blocks_detected > 0 or self.rate_limiting_detected > 0:
            protections = []
            if self.waf_detected:
                protections.append("WAF")
            if self.blocks_detected > 0:
                protections.append(f"Blockierungen({self.blocks_detected})")
            if self.rate_limiting_detected > 0:
                protections.append(f"Rate-Limit({self.rate_limiting_detected})")
            print(f"Erkannte Schutzmaßnahmen: {', '.join(protections)}")
        self.record_history()

    def export_stats(self, format: str = "json") -> str:
        if format == "json":
            data = {
                "timestamp": time.time(),
                "elapsed": self.get_elapsed(),
                "attack_type": self.attack_type,
                "packets_sent": self.packets_sent,
                "bytes_sent": self.bytes_sent,
                "pps": self.get_pps(),
                "bps": self.get_bps(),
                "connection_attempts": self.connection_attempts,
                "successful_connections": self.successful_connections,
                "failed_connections": self.failed_connections,
                "success_rate": self.get_success_rate(),
                "avg_response_time": self.get_avg_response_time(),
                "status_codes": self.status_codes,
                "waf_detected": self.waf_detected,
                "blocks_detected": self.blocks_detected,
                "rate_limiting_detected": self.rate_limiting_detected
            }
            return json.dumps(data)
        return json.dumps(data)

# Weitere Dataclasses für Port- und Zielinformationen
@dataclass
class PortInfo:
    port: int
    status: str = "closed"
    service: str = "unknown"
    version: Optional[str] = None
    banner: Optional[str] = None

@dataclass
class TargetInfo:
    ip: str
    hostname: Optional[str] = None
    os_fingerprint: Optional[str] = None
    is_waf_protected: bool = False
    waf_type: Optional[str] = None
    open_ports: Dict[int, PortInfo] = field(default_factory=dict)
    http_server: Optional[str] = None
    detected_frameworks: List[str] = field(default_factory=list)
    potential_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    captcha_detected: bool = False
    rate_limiting_detected: bool = False
    cloudflare_protected: bool = False
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    scan_time: float = field(default_factory=time.time)

@dataclass
class CVEInfo:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    affected_software: str
    exploit_available: bool = False
    exploit_script: Optional[str] = None

@dataclass
class SystemResourceInfo:
    cpu_count: int = 4
    cpu_usage: float = 0.0
    memory_total: int = 0
    memory_available: int = 0
    network_interfaces: List[str] = field(default_factory=list)
    network_speed: Optional[Dict[str, float]] = None
    public_ip: Optional[str] = None
    is_behind_proxy: bool = False
    is_vpn_active: bool = False

# SharedStats-Klasse zur prozessübergreifenden Statistik (vereinfachte Version)
import multiprocessing
from multiprocessing import shared_memory, Lock

class SharedStats:
    def __init__(self, name: str, size: int = 4096):
        self.name = name
        self.size = size
        self.lock = Lock()
        try:
            self.shm = shared_memory.SharedMemory(name=self.name)
        except:
            self.shm = shared_memory.SharedMemory(name=self.name, create=True, size=self.size)
            initial_data = {"timestamp": time.time(), "attacks": {}, "global_packets": 0, "global_bytes": 0}
            self._write_data(initial_data)

    def close(self):
        if self.shm:
            self.shm.close()
            try:
                self.shm.unlink()
            except:
                pass

    def _write_data(self, data: Dict):
        with self.lock:
            json_data = json.dumps(data).encode()
            if len(json_data) > self.size:
                json_data = json_data[:self.size-1] + b'}'
            length = len(json_data)
            length_bytes = length.to_bytes(4, byteorder='little')
            self.shm.buf[:4] = length_bytes
            self.shm.buf[4:4+length] = json_data

    def _read_data(self) -> Dict:
        with self.lock:
            length_bytes = bytes(self.shm.buf[:4])
            length = int.from_bytes(length_bytes, byteorder='little')
            if length <= 0 or length > self.size - 4:
                return {}
            json_data = bytes(self.shm.buf[4:4+length])
            try:
                return json.loads(json_data)
            except json.JSONDecodeError:
                return {}

    def update_stats(self, attack_name: str, stats: AttackStats):
        data = self._read_data()
        data["timestamp"] = time.time()
        if "attacks" not in data:
            data["attacks"] = {}
        data["attacks"][attack_name] = {
            "packets_sent": stats.packets_sent,
            "bytes_sent": stats.bytes_sent,
            "pps": stats.get_pps(),
            "bps": stats.get_bps(),
            "success_rate": stats.get_success_rate(),
            "blocks_detected": stats.blocks_detected,
            "rate_limiting_detected": stats.rate_limiting_detected,
            "waf_detected": stats.waf_detected
        }
        data["global_packets"] = sum(a.get("packets_sent", 0) for a in data["attacks"].values())
        data["global_bytes"] = sum(a.get("bytes_sent", 0) for a in data["attacks"].values())
        self._write_data(data)

    def get_stats(self) -> Dict:
        return self._read_data()
