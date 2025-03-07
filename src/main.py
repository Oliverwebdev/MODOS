#!/usr/bin/env python3
import argparse
import asyncio

from src.config import AttackConfig
# Importiere die benötigten Angriffsmethoden – hier als Beispiel SynFlood und UDP-Flood
from src.attacks.syn_flood import SynFlood
from src.attacks.udp_flood import UdpFlood
# Weitere Angriffsmethoden können hier hinzugefügt werden

def main():
    parser = argparse.ArgumentParser(description="DoS-Test-Framework")
    parser.add_argument("--attack", type=str, required=True, help="Angriffsmethode (z.B. syn_flood, udp_flood, etc.)")
    parser.add_argument("--target", type=str, required=True, help="Zieladresse")
    parser.add_argument("--duration", type=int, default=30, help="Angriffsdauer in Sekunden")
    args = parser.parse_args()

    config = AttackConfig(target=args.target, duration=args.duration)
    
    # Auswahl der Angriffsmethode
    attack = None
    if args.attack.lower() == "syn_flood":
        attack = SynFlood(config)
    elif args.attack.lower() == "udp_flood":
        attack = UdpFlood(config)
    else:
        print(f"Unbekannte Angriffsmethode: {args.attack}")
        exit(1)
    
    asyncio.run(attack.run())

if __name__ == "__main__":
    main()
