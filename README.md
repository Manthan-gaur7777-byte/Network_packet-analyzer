# Network Intrusion Detection System (NIDS)

A Python-based **Network Intrusion Detection System (NIDS)** that analyzes captured network traffic from **PCAP** files to identify suspicious activities using rule-based detection techniques. The project is built using **Scapy** and provides detailed traffic analysis along with multiple intrusion detection modules.

---

## Features

- Packet Analysis
- Protocol Analysis (TCP, UDP, ICMP, Others)
- Source and Destination IP Analysis
- Port Usage Analysis
- Packet Size Statistics
- Timestamp Analysis
- Risk Score Calculation
- High Traffic Detection
- Packet Spike Detection
- Port Scan Detection
- Failed Login Detection
- External IP Classification
- Multi-Level Alert System
- Final Security Report

---

## Technologies Used

- Python 3
- Scapy
- Collections (Counter)
- Socket
- IP Address Module

---

## Project Structure

```
Project/
│
├── sample.pcapng
├── test.py
├── README.md
```

---

## Detection Modules

### 1. Packet Analysis
Extracts information such as:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Packet Size
- Timestamp

---

### 2. Protocol Analysis

Counts the number of:

- TCP packets
- UDP packets
- ICMP packets
- Other packets

---

### 3. IP Analysis

Provides:

- Total packets sent by each IP
- Unique ports accessed
- Most Active IP
- Packet statistics

---

### 4. Risk Analysis

Assigns a risk score to every IP based on:

- Number of packets
- Number of unique destination ports

Risk Levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL

---

### 5. High Traffic Detection

Detects IP addresses generating unusually high traffic within a short period.

---

### 6. Packet Spike Detection

Identifies sudden spikes in packet transmission that may indicate suspicious network activity.

---

### 7. Port Scan Detection

Detects hosts attempting connections to multiple ports within a short time interval.

Alert Levels:

- Medium
- High

---

### 8. Failed Login Detection

Detects possible brute-force login attempts by monitoring repeated connections to common authentication ports such as:

- FTP
- SSH
- TELNET
- SMB
- RDP
- MySQL
- PostgreSQL
- MSSQL
- Oracle

---

### 9. External IP Classification

Classifies IP addresses into:

- Private Network
- Verified Public IP
- Unverified Public IP

Known organizations include:

- Google
- AWS
- Cloudflare
- Akamai
- Microsoft
- GitHub
- Netflix
- OpenAI

---

### 10. Alert System

Combines outputs from all detection modules to generate overall security alerts.

Alert Levels:

- Low
- Medium
- High
- Critical

---

## Final Security Report

The program generates a comprehensive report containing:

- Network Statistics
- Protocol Statistics
- IP Analysis
- Risk Analysis
- Traffic Analysis
- Detection Results
- Alert Summary
- Overall Network Status

---

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/NIDS.git
```

Install Scapy:

```bash
pip install scapy
```

---

## Usage

Place your PCAP file in the project directory.

Run:

```bash
python test.py
```

---

## Sample Input

```
sample.pcapng
```

---

## Sample Output

```
NETWORK TRAFFIC SUMMARY

Protocol Statistics

Top Source IPs

Top Destination IPs

Risk Analysis

Packet Spike Detection

Port Scan Detection

Failed Login Detection

External IP Classification

Alert System

Final Security Report
```

---

## Future Scope

- Live Packet Capture
- Machine Learning Based Detection
- Web Dashboard
- Real-Time Alert Notifications
- Threat Intelligence Integration
- Log Export (CSV/PDF)

---

## Author

**Manthan Gaur**

---

## License

This project is licensed under the MIT License.
