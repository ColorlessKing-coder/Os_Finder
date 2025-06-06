# 🧠 OsFinder - TCP/IP Based Operating System Detection Tool

**OsFinder** is a Python-based tool that attempts to guess the target system’s operating system (OS)
by sending and analyzing TCP/IP packets. It utilizes techniques such as TTL values, TCP window size, TCP flag responses, and TCP options analysis to determine if the target OS is Linux, Windows, Cisco, etc.

#### v1.0.0
- Initial release with TTL, Window Size, and TCP Flag OS detection.


## 🚀 Features

- 🧪 ICMP (Ping) TTL Value Detection
- 📏 TCP SYN Window Size Analysis
- 🧠 OS Detection via TTL + Window Size
- 🧱 OS Fingerprinting via TCP Flags (Open & Closed Ports)
- ⚙️ TCP Options Analysis
- 🌐 Basic Port Scanning (Open/Closed Port Info)
- 🕵️ OS Classification Based on TCP Flag Behaviors
- 🔬 OS Guessing via TCP Option Fingerprints

---

## 📦 Required Libraries

| Library     | Description                                                  |
|-------------|--------------------------------------------------------------|
| `scapy`     | For creating, sending, and analyzing network packets         |
| `rich`      | For beautiful and colored terminal output                    |
| `socket`    | To test TCP connections and scan ports                       |
| `random`    | To generate random source ports and sequence numbers         |
| `ast`       | To safely evaluate TCP options from user input               |
| `time`      | (For future use) Timing-based measurements                   |
| `os`        | (For future use) Interacting with the operating system       |

### 🔧 Installation

```bash
pip install scapy rich
```

### 🧪 Example Output
```bash
[ ✔ ] TTL Value: 128
[ ✔ ] Window Size: 8192
[ ✔ ] OS: Windows
```


⚠️ **Legal Warning**: Use this tool only on machines you own or are authorized to test.  
Unauthorized scanning is illegal and unethical.
