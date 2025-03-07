# DoS-Test-Framework

Ein fortgeschrittenes DoS-Test-Framework für autorisierte Sicherheits- und Forschungstests. Dieses Tool bietet verschiedene Angriffsmethoden zur Durchführung von Penetrationstests und zur Überprüfung der Widerstandsfähigkeit von Netzwerkinfrastrukturen gegen Denial-of-Service-Angriffe.

## ⚠️ Wichtiger Hinweis

**Dieses Tool darf ausschließlich für folgende Zwecke verwendet werden:**
- Autorisierte Sicherheitstests
- Forschung und Bildung
- Tests in eigenen Netzwerken

**Die unbefugte Verwendung dieses Tools gegen nicht autorisierte Ziele ist illegal und kann strafrechtliche Konsequenzen haben.**

## 📋 Funktionen

Das Framework bietet verschiedene Angriffsmethoden:

| Angriffstyp | Beschreibung |
|-------------|--------------|
| `syn_flood` | TCP SYN-Flood-Angriff |
| `udp_flood` | UDP-Paketflut |
| `http_flood` | HTTP-Request-Flood |
| `icmp_flood` | ICMP/Ping-Flood |
| `slowloris` | Slowloris-Verbindungserschöpfung |
| `dns_amplification` | DNS-Amplification-Angriff |
| `ntp_amplification` | NTP-Amplification-Angriff |
| `dns_water_torture` | DNS Water Torture Angriff mit zufälligen Subdomains |
| `tcp_reset` | TCP-Reset-Paketflut |

## 🔧 Installation

### Voraussetzungen

- Python 3.8 oder höher
- pip (Python-Paketmanager)
- Root-/Administrator-Rechte (für einige Angriffsmethoden)

### Installation der Abhängigkeiten

```bash
# Klonen des Repositories
git clone https://github.com/username/dos-framework.git
cd dos-framework

# Installation der Abhängigkeiten
pip install -r requirements.txt

# Optional: Installation des Pakets im Entwicklungsmodus
pip install -e .
```

## 🚀 Verwendung

### Grundlegende Verwendung

Wir empfehlen die Verwendung des bereitgestellten Wrapper-Scripts `run_attack.py`:

```bash
# Ausführbares Script erstellen
chmod +x run_attack.py

# Ausführen eines Angriffs
./run_attack.py --attack <angriffstyp> --target <ziel> --duration <dauer_in_sekunden>
```

### Verfügbare Parameter

| Parameter | Beschreibung | Standardwert |
|-----------|--------------|--------------|
| `--attack` | Angriffstyp (erforderlich) | - |
| `--target` | Zieladresse (IP oder Domain, erforderlich) | - |
| `--port` | Zielport | 80 |
| `--duration` | Angriffsdauer in Sekunden | 30 |
| `--threads` | Anzahl der zu verwendenden Threads | 10 |
| `--timeout` | Verbindungs-Timeout in Sekunden | 5.0 |

### Beispiele

```bash
# SYN-Flood gegen einen Webserver
./run_attack.py --attack syn_flood --target beispiel.de --duration 20

# UDP-Flood mit mehr Threads
./run_attack.py --attack udp_flood --target 192.168.1.1 --threads 50 --duration 15

# DNS-Amplification-Angriff
./run_attack.py --attack dns_amplification --target beispiel.de --duration 10

# Slowloris-Angriff gegen einen nicht-Standard-Port
./run_attack.py --attack slowloris --target beispiel.de --port 8080 --duration 30
```

## 🔍 Funktionsweise der Angriffsmethoden

### SYN-Flood
Sendet eine große Anzahl von TCP-SYN-Paketen an das Ziel, ohne den Handshake abzuschließen, um die Verbindungs-Warteschlange zu füllen.

### UDP-Flood
Überschwemmt das Ziel mit UDP-Paketen, was zu einer Bandbreitenerschöpfung führen kann.

### HTTP-Flood
Sendet zahlreiche HTTP-GET- oder POST-Anfragen an einen Webserver, um ihn zu überlasten.

### Slowloris
Hält HTTP-Verbindungen offen, indem unvollständige Anfragen gesendet werden, die langsam ergänzt werden.

### DNS-Amplification
Nutzt öffentliche DNS-Server, um verstärkte DNS-Anfragen an das Ziel weiterzuleiten, mit gefälschter Quell-IP.

### NTP-Amplification
Nutzt NTP-Server für verstärkte Antworten durch den MONLIST-Befehl, mit gefälschter Quell-IP.

### DNS Water Torture
Sendet Anfragen für nicht existierende Subdomains, um DNS-Resolver zu überlasten.

### ICMP-Flood
Sendet eine große Anzahl von ICMP-Echo-Anfragen (Ping), um die Netzwerkbandbreite zu erschöpfen.

### TCP-Reset
Sendet TCP-Reset-Pakete, um bestehende Verbindungen zu unterbrechen.

## ⚙️ Erweiterte Konfiguration

Das Framework bietet erweiterte Konfigurationsoptionen durch die Anpassung der `config.py`-Datei:

- IP-Spoofing-Einstellungen
- Paketgrößenvariationen
- Benutzerdefinierte HTTP-Header und User-Agents
- DNS-Server-Listen für Amplification-Angriffe
- TTL-Variationen für Paketmanipulation
- Und vieles mehr...

## 📊 Statistiken und Überwachung

Das Framework enthält eine integrierte Statistikfunktion, die während des Angriffs Informationen anzeigt:

- Pakete pro Sekunde (PPS)
- Übertragene Daten (MB/s)
- Erfolgsrate der Verbindungen
- Erkannte Schutzmaßnahmen (WAF, Rate-Limiting)

## 📂 Projektstruktur

```
dos-framework/
├── src/
│   ├── attacks/         # Angriffsmethoden
│   ├── core/            # Kernfunktionalität
│   ├── utils/           # Hilfsfunktionen
│   ├── web/             # Web-UI (optional)
│   ├── config.py        # Konfigurationsdatei
│   └── main.py          # Haupt-Einstiegspunkt
├── requirements.txt     # Abhängigkeiten
├── setup.py             # Installationsskript
└── run_attack.py        # Wrapper-Script für einfache Nutzung
```

## 🛡️ Verteidigung gegen DoS-Angriffe

Hier sind einige Maßnahmen zur Abwehr von DoS-Angriffen:

- Implementierung von Rate-Limiting
- Verwendung von Load-Balancern
- Konfiguration von Firewall-Regeln
- Einsatz spezialisierter Anti-DDoS-Dienste
- Konfiguration von SYN-Cookies
- Überwachung und Filterung des Netzwerkverkehrs

## 🔄 Weiterentwicklung

Mögliche Erweiterungen für zukünftige Versionen:

- Web-Benutzeroberfläche zur einfacheren Steuerung
- Automatische Zielanalyse und Anpassung der Angriffsmethoden
- Erweiterte Berichterstattung und Protokollierung
- Integration mit Monitoring-Tools

## 📜 Lizenz

Dieses Projekt wird unter den Bedingungen der MIT-Lizenz veröffentlicht. Siehe die [LICENSE](LICENSE)-Datei für Details.

---

**Haftungsausschluss:** Die Autoren übernehmen keine Verantwortung für Schäden oder rechtliche Konsequenzen, die durch die Verwendung dieses Tools entstehen. Die Verwendung erfolgt auf eigene Gefahr und Verantwortung.