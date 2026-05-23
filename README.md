# 🔬 Smart Packet Inspector
**Educational Network Traffic Sniffer | Python + Scapy + Rich**

> ⚠️ For educational use only in a controlled local environment. Requires administrator/root privileges.

---

## 📁 Project Structure

```
smart_packet_inspector/
├── main.py            # Entry point — CLI, Live dashboard, orchestration
├── sniffer.py         # Packet capture engine (Scapy-based, threaded)
├── analyzer.py        # Traffic statistics + anomaly detection
├── logger.py          # CSV and TXT packet logger
├── requirements.txt   # Python dependencies
├── README.md          # This file
└── logs/              # Auto-created: session log files
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.10+
- **Windows:** Npcap (https://npcap.com/) — required for Scapy raw socket capture
- **Linux/macOS:** libpcap (`sudo apt install libpcap-dev`)

### Step 1 — Install Npcap (Windows only)
Download and install Npcap from https://npcap.com/dist/npcap-1.79.exe  
During installation, tick **"Install Npcap in WinPcap API-compatible Mode"**.

### Step 2 — Create virtual environment (recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### Step 3 — Install Python dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Tool

> **⚠ Must be run with Administrator privileges.**

### Windows (run cmd as Administrator)
```cmd
python main.py
```

### Linux / macOS
```bash
sudo python main.py
```

---

## 🎛 Command-Line Options

| Argument | Description | Example |
|---|---|---|
| `--protocol` | Filter by protocol | `--protocol TCP` |
| `--ip` | Filter by IP address | `--ip 192.168.1.1` |
| `--interface` | Specify NIC | `--interface eth0` |
| `--no-log` | Disable disk logging | `--no-log` |
| `--session` | Custom session name | `--session test1` |

---

## 💡 Example Commands

```bash
# Capture all traffic (default)
python main.py

# Capture only TCP packets
python main.py --protocol TCP

# Capture only ICMP packets (ping monitoring)
python main.py --protocol ICMP

# Monitor traffic from a specific IP
python main.py --ip 192.168.1.100

# Capture UDP on a specific interface, no disk logging
python main.py --protocol UDP --interface eth0 --no-log

# Named session
python main.py --session lab_test_01
```

---

## 📺 Sample Terminal Output

```
╭──────────────────────────────────────────────────────────────────────╮
│  🔬 SMART PACKET INSPECTOR                                           │
│  Educational Network Sniffer — Real-Time Traffic Analysis            │
╰──────────────────────────────────────────────────────────────────────╯

 📡 Live Packet Feed                    📊 Traffic Statistics
──────────────────────────────────────  ──────────────────────────────────
 Timestamp   Proto  Src IP   Dst IP     Total Packets:      1,247
 22:14:03    TCP    10.0.0.2  8.8.8.8   Total Bytes:      892,341
 22:14:03    UDP    10.0.0.2  1.1.1.1   Pkt/Second:          42.3
 22:14:03    ICMP   10.0.0.5  10.0.0.1  Alerts:                 2
 22:14:04    HTTP   10.0.0.2  93.184.x

 🚨 Anomaly Alerts
 [HIGH] ICMP_FLOOD — 10.0.0.5 — 17 pkts/10s
```

---

## 📖 How Packet Sniffing Works

A **network packet sniffer** places the network interface card (NIC) into **promiscuous mode**, allowing it to capture all frames passing the interface — not just those addressed to the host. Scapy constructs raw socket connections at Layer 2/3, decodes frame headers, and provides a structured Python object per packet. This tool adds a statistics layer, anomaly detection, and a real-time terminal dashboard on top.

---

## 🐛 Common Bugs & Fixes

| Problem | Cause | Fix |
|---|---|---|
| `PermissionError` / no packets captured | Not running as Administrator | Run as admin / sudo |
| `ImportError: No module named 'scapy'` | deps not installed | `pip install -r requirements.txt` |
| `OSError: [WinError 10013]` | Npcap not installed | Install Npcap from https://npcap.com |
| Display glitches | Terminal too narrow | Widen terminal window to ≥140 chars |
| No HTTP detected | HTTPS traffic is encrypted | HTTP only works on unencrypted port 80 |

---

## 🔮 Future Improvements

1. GeoIP lookup — display country flags next to source IPs
2. DNS resolution — show hostnames alongside IPs
3. PCAP export — write `.pcap` files for Wireshark analysis
4. Port scan detection — identify sequential port probing
5. Web dashboard — Flask/FastAPI live dashboard in browser
6. Email/Slack alert webhook integration
7. Machine learning anomaly detection baseline

---

## 🎓 Viva / Interview Q&A

**Q: What is promiscuous mode?**  
A: A NIC mode where the interface passes all received packets to the OS, regardless of destination MAC address, enabling packet capture of traffic not addressed to the host.

**Q: What is the difference between TCP and UDP?**  
A: TCP is connection-oriented with guaranteed delivery and ordering. UDP is connectionless, faster, with no delivery guarantee — used in streaming, DNS, VoIP.

**Q: Why does HTTPS traffic not show HTTP layer data?**  
A: TLS encryption wraps the HTTP payload; only the TCP layer is visible at the network level without the session keys.

**Q: What is an ICMP flood attack?**  
A: Sending a large volume of ICMP Echo Request (ping) packets to overwhelm a target — a type of Denial of Service attack.

**Q: What Python library is used for packet capture here?**  
A: Scapy — a powerful packet manipulation library that constructs, sends, captures, and decodes network packets at multiple OSI layers.

**Q: How does the anomaly detection work?**  
A: A rolling time-window deque tracks timestamps of packets per IP. If the count within the last N seconds exceeds a threshold, an alert fires.

**Q: Why is administrator privilege required?**  
A: Raw socket access (needed to intercept packets before the OS routing stack discards them) is a privileged operation restricted to administrator-level users.
