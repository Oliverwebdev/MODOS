# DoS-Test-Framework

An advanced DoS Testing Framework for authorized security assessments and research. This tool provides various attack methods to conduct penetration tests and verify the resilience of network infrastructures against denial-of-service attacks.

## ⚠️ Important Notice

**This tool may only be used for the following purposes:**
- Authorized security testing
- Research and education
- Tests on your own networks

**Unauthorized use of this tool against non-authorized targets is illegal and may have criminal consequences.**

## 📋 Features

The framework offers various attack methods:

| Attack Type | Description |
|-------------|------------|
| `syn_flood` | TCP SYN flood attack |
| `udp_flood` | UDP packet flood |
| `http_flood` | HTTP request flood |
| `icmp_flood` | ICMP/Ping flood |
| `slowloris` | Slowloris connection exhaustion |
| `dns_amplification` | DNS amplification attack |
| `ntp_amplification` | NTP amplification attack |
| `dns_water_torture` | DNS water torture attack with random subdomains |
| `tcp_reset` | TCP reset packet flood |

## 🔧 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Root/Administrator privileges (for some attack methods)

### Installing Dependencies

```bash
# Clone the repository
git clone https://github.com/username/dos-framework.git
cd dos-framework

# Install dependencies
pip install -r requirements.txt

# Optional: Install the package in development mode
pip install -e .
```

## 🚀 Usage

### Basic Usage

We recommend using the provided wrapper script `run_attack.py`:

```bash
# Make the script executable
chmod +x run_attack.py

# Run an attack
./run_attack.py --attack <attack_type> --target <target> --duration <duration_in_seconds>
```

### Available Parameters

| Parameter | Description | Default Value |
|-----------|------------|--------------|
| `--attack` | Attack type (required) | - |
| `--target` | Target address (IP or domain, required) | - |
| `--port` | Target port | 80 |
| `--duration` | Attack duration in seconds | 30 |
| `--threads` | Number of threads to use | 10 |
| `--timeout` | Connection timeout in seconds | 5.0 |

### Examples

```bash
# SYN flood against a web server
./run_attack.py --attack syn_flood --target example.com --duration 20

# UDP flood with more threads
./run_attack.py --attack udp_flood --target 192.168.1.1 --threads 50 --duration 15

# DNS amplification attack
./run_attack.py --attack dns_amplification --target example.com --duration 10

# Slowloris attack against a non-standard port
./run_attack.py --attack slowloris --target example.com --port 8080 --duration 30
```

## 🔍 How the Attack Methods Work

### SYN Flood
Sends a large number of TCP SYN packets to the target without completing the handshake, filling up the connection queue.

### UDP Flood
Floods the target with UDP packets, potentially leading to bandwidth exhaustion.

### HTTP Flood
Sends numerous HTTP GET or POST requests to a web server to overload it.

### Slowloris
Keeps HTTP connections open by sending incomplete requests that are slowly completed.

### DNS Amplification
Uses public DNS servers to forward amplified DNS requests to the target, with spoofed source IP.

### NTP Amplification
Uses NTP servers for amplified responses through the MONLIST command, with spoofed source IP.

### DNS Water Torture
Sends requests for non-existent subdomains to overload DNS resolvers.

### ICMP Flood
Sends a large number of ICMP echo requests (ping) to exhaust network bandwidth.

### TCP Reset
Sends TCP reset packets to interrupt existing connections.

## ⚙️ Advanced Configuration

The framework offers advanced configuration options by customizing the `config.py` file:

- IP spoofing settings
- Packet size variations
- Custom HTTP headers and user agents
- DNS server lists for amplification attacks
- TTL variations for packet manipulation
- And much more...

## 📊 Statistics and Monitoring

The framework includes a built-in statistics function that displays information during the attack:

- Packets per second (PPS)
- Transferred data (MB/s)
- Connection success rate
- Detected protection measures (WAF, rate limiting)

## 📂 Project Structure

```
dos-framework/
├── src/
│   ├── attacks/         # Attack methods
│   ├── core/            # Core functionality
│   ├── utils/           # Helper functions
│   ├── web/             # Web UI (optional)
│   ├── config.py        # Configuration file
│   └── main.py          # Main entry point
├── requirements.txt     # Dependencies
├── setup.py             # Installation script
└── run_attack.py        # Wrapper script for easy use
```

## 🛡️ Defense Against DoS Attacks

Here are some measures to defend against DoS attacks:

- Implementing rate limiting
- Using load balancers
- Configuring firewall rules
- Deploying specialized anti-DDoS services
- Configuring SYN cookies
- Monitoring and filtering network traffic

## 🔄 Future Development

Possible extensions for future versions:

- Web-based user interface for easier control
- Automatic target analysis and adaptation of attack methods
- Enhanced reporting and logging
- Integration with monitoring tools

## 📜 License

This project is released under the terms of the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Disclaimer:** The authors assume no responsibility for damages or legal consequences arising from the use of this tool. Use at your own risk and responsibility.