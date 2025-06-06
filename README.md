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




```
       [94m▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓[0m          [91m▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓[0m     

      [94m    ____          ____    [0m     [91m    ____          ____    [0m      
      [94m  _/__|__\____  _/__|__\____ [0m     [91m  _/__|__\____  _/__|__\____ [0m
      [94m |  _     _   ||  _     _   |[0m     [91m |  _     _   ||  _     _   |[0m
      [94m '-(_)-------(_)-' -(_)-------(_)-[0m     [91m '-(_)-------(_)-' -(_)-------(_)-[0m


      [İ][snow][/snow]Please Enter IPv4 Address : 192.168.1.146
[ ..+.. ] Detected Operating System With TCP Options...
[ ✔ ] Ports Status For TCP Info : {'Open_Ports': [139, 443, 445], 'Closed_Ports': [21, 22, 23, 25, 53, 80, 110, 143, 3306, 3389, 5900, 8080]} 
[ ✔ ] Sended Options Info :  [('MSS', 1460), ('WScale', 10), ('SAckOK', b''), ('Timestamp', (123, 0)), ('NOP', None), ('NOP', None)] 
[ ✔ ] 192.168.1.146:139 → TCP Opsiyonları: [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')]
[ ✔ ] Sended Options Info :  [('MSS', 1460), ('WScale', 10), ('SAckOK', b''), ('Timestamp', (123, 0)), ('NOP', None), ('NOP', None)] 
[ ✔ ] 192.168.1.146:443 → TCP Opsiyonları: [('MSS', 65495), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')]
[ ✔ ] Sended Options Info :  [('MSS', 1460), ('WScale', 10), ('SAckOK', b''), ('Timestamp', (123, 0)), ('NOP', None), ('NOP', None)] 
[ ✔ ] 192.168.1.146:445 → TCP Opsiyonları: [('MSS', 65495), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')]
Give me tcp option Values (İf you have no value please enter q  ): [('MSS', 65495), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')]
Windows 10 veya sonrası
[ ..+.. ] Detected Operating System With Windows Size and TTL Value  ...
Hedefe ulaşılamıyor
[ ✔ ] Window Size : 65392 
İşletim sistemi tespit edilemedi.
[ ..+.. ] Detected Operating System With Flag Response  ...

[ ✔ ] Response For Open Ports :
[ ✔ ](Port : 139 S → SA  SA → No Response  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 443 S → No Response  SA → R  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 445 S → No Response  SA → No Response  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)

[ ✔ ] Response For Closed Ports:
[ ✔ ](Port : 21 S → RA  SA → R  R → No Response  F → No Response  A → No Response  FA → R  PA → No Response  RA → No Response)
[ ✔ ](Port : 22 S → No Response  SA → R  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 23 S → No Response  SA → No Response  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 25 S → No Response  SA → No Response  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 53 S → RA  SA → R  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 80 S → No Response  SA → No Response  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 110 S → No Response  SA → No Response  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 143 S → RA  SA → R  R → No Response  F → No Response  A → No Response  FA → R  PA → No Response  RA → No Response)
[ ✔ ](Port : 3306 S → No Response  SA → R  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 3389 S → No Response  SA → No Response  R → No Response  F → No Response  A → No Response  FA → R  PA → No Response  RA → No Response)
[ ✔ ](Port : 5900 S → RA  SA → No Response  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ ✔ ](Port : 8080 S → No Response  SA → No Response  R → No Response  F → No Response  A → No Response  FA → No Response  PA → No Response  RA → No Response)
[ İ ]Open Port  139 and  Closed Port 21 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  139 and  Closed Port 22 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  139 and  Closed Port 23 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  139 and  Closed Port 25 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  139 and  Closed Port 53 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  139 and  Closed Port 80 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  139 and  Closed Port 110 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  139 and  Closed Port 143 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  139 and  Closed Port 3306 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  139 and  Closed Port 3389 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  139 and  Closed Port 5900 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  139 and  Closed Port 8080 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  443 and  Closed Port 21 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  443 and  Closed Port 22 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  443 and  Closed Port 23 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  443 and  Closed Port 25 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  443 and  Closed Port 53 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  443 and  Closed Port 80 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  443 and  Closed Port 110 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  443 and  Closed Port 143 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  443 and  Closed Port 3306 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  443 and  Closed Port 3389 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  443 and  Closed Port 5900 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  443 and  Closed Port 8080 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  445 and  Closed Port 21 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  445 and  Closed Port 22 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  445 and  Closed Port 23 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  445 and  Closed Port 25 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  445 and  Closed Port 53 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  445 and  Closed Port 80 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  445 and  Closed Port 110 For OS Analyze:

[ ✔ ] Guess OS : Firewall veya Router
[ İ ]Open Port  445 and  Closed Port 143 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  445 and  Closed Port 3306 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  445 and  Closed Port 3389 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  445 and  Closed Port 5900 For OS Analyze:
[ ? ] Can't Guess Need More Flags Info 
[ İ ]Open Port  445 and  Closed Port 8080 For OS Analyze:

```
