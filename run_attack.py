#!/usr/bin/env python3
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import AttackConfig
from src.attacks.syn_flood import SynFlood
from src.attacks.udp_flood import UdpFlood
from src.attacks.http_flood import HttpFlood
from src.attacks.icmp_flood import IcmpFlood
from src.attacks.slowloris import Slowloris
from src.attacks.dns_amplification import DnsAmplification
from src.attacks.dns_water_torture import DnsWaterTorture
from src.attacks.ntp_amplification import NtpAmplification
from src.attacks.tcp_reset import TcpReset

import argparse
import asyncio

def main():
    parser = argparse.ArgumentParser(description="DoS Test Framework")
    parser.add_argument("--attack", type=str, required=True, 
                        help="Attack type: syn_flood, udp_flood, http_flood, icmp_flood, slowloris, dns_amplification, ntp_amplification, dns_water_torture, tcp_reset")
    parser.add_argument("--target", type=str, required=True, 
                        help="Target address (IP or domain)")
    parser.add_argument("--port", type=int, default=80,
                        help="Target port (default: 80)")
    parser.add_argument("--duration", type=int, default=30, 
                        help="Attack duration in seconds (default: 30)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of threads to use (default: 10)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Connection timeout in seconds (default: 5.0)")
    
    args = parser.parse_args()
    
    # Create attack configuration
    config = AttackConfig(
        target=args.target, 
        port=args.port,
        duration=args.duration,
        threads=args.threads,
        timeout=args.timeout
    )
    
    # Initialize the appropriate attack
    attack = None
    if args.attack.lower() == "syn_flood":
        attack = SynFlood(config)
    elif args.attack.lower() == "udp_flood":
        attack = UdpFlood(config)
    elif args.attack.lower() == "http_flood":
        attack = HttpFlood(config)
    elif args.attack.lower() == "icmp_flood":
        attack = IcmpFlood(config)
    elif args.attack.lower() == "slowloris":
        attack = Slowloris(config)
    elif args.attack.lower() == "dns_amplification":
        attack = DnsAmplification(config)
    elif args.attack.lower() == "dns_water_torture":
        attack = DnsWaterTorture(config)
    elif args.attack.lower() == "ntp_amplification":
        attack = NtpAmplification(config)
    elif args.attack.lower() == "tcp_reset":
        attack = TcpReset(config)
    else:
        print(f"Unknown attack type: {args.attack}")
        print("Available attacks: syn_flood, udp_flood, http_flood, icmp_flood, slowloris, dns_amplification, ntp_amplification, dns_water_torture, tcp_reset")
        return 1
    
    # Run the attack
    try:
        asyncio.run(attack.run())
        return 0
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
        return 0
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())