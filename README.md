# 🧠 Automating Network Security Analysis using Rule-Based Engine

This project automates **network intrusion detection and analysis** using a **rule-based interpretation engine** built over **Wireshark** and **TShark**.  
It enables administrators to define and detect attack signatures such as **ARP Storm**, **ARP Poisoning**, and **SYN Flood** directly from captured packet data.

---

## 📘 Project Overview

Traditional Intrusion Detection Systems (IDS) rely on manual packet analysis and human expertise.  
This project provides an **automated detection framework** capable of analyzing `.pcap` network traces and identifying attack patterns based on **user-defined rule sets**.

### 🎯 Objectives
- Automate packet-level intrusion detection using custom rule files.  
- Support detection for ARP Poisoning, ARP Storm, and SYN Flood attacks.  
- Enable administrators to define and expand rules without coding knowledge.  
- Generate detailed, timestamped attack reports.  

---

## ⚙️ System Architecture

The architecture consists of **three major modules**:

1. **Rule Conversion Module** – Reads human-written attack rules and converts them to machine-readable format.  
2. **Packet Parsing Module** – Parses `.pcap` files into `.json` using TShark for efficient analysis.  
3. **Event Detection Engine** – Compares JSON packet data against rule definitions and identifies matching attack patterns.

```mermaid
flowchart LR
    A[Rules File] --> B[Rule Converter]
    B --> C[Parsed PCAP File -JSON]
    C --> D[Rule Evaluation Engine]
    D --> E[Attack Detection Report]
```

---

## 🧩 Methodology

1. Rule Definition:
   - Rules defined in plain text using Wireshark display filter syntax.
   - Each rule includes:
     - Name
     - Description
     - Groups (packet classification)
     - Packets (Wireshark filters)
     - Asserts (logical conditions)
     - Threshold (trigger count)
     - Report (verbosity level)

2. Packet Capture:
   - Attacks performed and logged using Wireshark on victim machine.
   - Saved as .pcap files (e.g., arp_poisoning.pcap, synflood.pcap).

3. Conversion to JSON:
   - TShark commands used:
     ```bash
     tshark -r synflood.pcap -T json > synflood.json
     tshark -r arp_storm.pcap -T json > arp_storm.json
     tshark -r arp_poisoning.pcap -T json > arp_poisoning.json
     ```
   - The resulting .json files are parsed for comparison.

4. Attack Detection:
   - Python program compares parsed packets with the rule dictionary.
   - Detected attacks trigger a report file with time, description, and conditions.

---

## 🧪 Attack Scenarios Implemented
| Attack	| Description	| Detection Logic |
| -------- | -------------- | ------------- |
| ARP Poisoning	| MITM attack that associates attacker MAC with victim IP	| Count duplicate ARP packets (arp.duplicate-address-detected) |
| ARP Storm	| DoS via repeated ARP broadcasts	| Compare ratio of broadcast vs total ARP packets (eth.dst==ff:ff:ff:ff:ff:ff) |
| SYN Flood	| DDoS attack using half-open TCP connections	| Compare count of SYN packets to ACK packets (tcp.flags.syn==1 vs tcp.flags.ack==1) |

---

## 🧠 Tools & Technologies
| Category	| Tools |
| -------- | -------------- |
| Packet Capture	| Wireshark |
| Packet Parsing	| TShark |
| Attack Simulation	| MITMf, Netdiscover, Metasploit |
| Language	| Python 3 |
| OS Used	| Ubuntu (Victim), Kali Linux (Attacker) |

---

## 📈 Results
| Attack	| Detection Accuracy	| Description |
| -------- | -------------- | ------------- |
| ARP Poisoning	| 100%	| Detected using duplicate address filter |
| ARP Storm	| 98%	| Detected using ARP broadcast ratio |
| SYN Flood	| 97%	| Detected using SYN/ACK packet ratio |

---

## 🔮 Future Work

- Extend rule sets for additional attacks (e.g., ICMP Flood, DNS Spoofing).
- Integrate with existing IDS/IPS frameworks.
- Add GUI-based interface for rule creation and visualization.
- Include real-time PCAP sniffing module.
