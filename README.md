# 🛡️ Ethical Hacking Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
![Coverage](https://codecov.io/gh/CrownCoreStudios/ethical-hacking-toolkit/branch/master/graph/badge.svg)
![GitHub stars](https://img.shields.io/github/stars/CrownCoreStudios/ethical-hacking-toolkit?style=social)

A comprehensive, open-source toolkit for ethical hacking, penetration testing, and security analysis. This collection of Python scripts provides security professionals with powerful tools for network analysis, vulnerability assessment, reverse engineering, and digital forensics.

## 🌟 Features

- **Comprehensive Toolset**: Over 15+ security tools in one repository
- **Detailed Analysis**: In-depth information gathering and security analysis
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Well-Documented**: Detailed usage instructions and examples for each tool
- **Modular Design**: Easy to extend with new scripts and functionality
- **Modern Python**: Built with Python 3.8+ using modern best practices

## 📋 Table of Contents

- [Installation](#-installation)
- [Usage](#-usage)
- [Tools Overview](#-tools-overview)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/CrownCoreStudios/ethical-hacking-toolkit.git
   cd ethical-hacking-toolkit
   ```

2. **Set up a virtual environment (recommended)**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 🛠️ Tools Overview

### 🔍 Network Analysis Tools
- **IP Tracer**: Advanced IP tracing with geolocation and network scanning
- **WiFi Scanner**: Wireless network discovery and analysis
- **ARP Spoof Detector**: Real-time ARP spoofing detection
- **Network Sniffer**: Packet capture and analysis
- **Port Scanner**: Comprehensive port scanning utility

### 🔒 Security Tools
- **SSL Analyzer**: Check SSL/TLS configuration of web servers
- **Brute Force Detector**: Detect brute force attempts on network services
- **Vulnerability Scanner**: Automated vulnerability assessment
- **Subdomain Scanner**: Discover subdomains of a target domain

### 🔍 Forensics Tools
- **Memory Analyzer**: Memory forensics and analysis
- **Browser History**: Extract and analyze browser history
- **File Type Identifier**: Identify file types and extract metadata
- **Hash Calculator**: File hashing and verification

### 🕵️ Reverse Engineering
- **PE Analyzer**: Windows PE file analysis
- **Disassembler**: Code disassembly and analysis
- **String Extractor**: Extract strings from binary files
- **XOR Cipher**: XOR encryption/decryption tool

## 📂 Project Structure

```
ethical-hacking-toolkit/
├── docs/                      # Documentation and guides
├── forensic_analysis/         # Digital forensics tools
│   ├── memory_analyzer.py     # Memory forensics analysis
│   └── browser_history.py     # Browser history analysis
├── network_analysis/          # Network monitoring and analysis
│   ├── ip_tracer.py          # Advanced IP tracing
│   ├── wifi_scanner.py       # Wireless network scanner
│   └── arp_spoof_detector.py # ARP spoofing detection
├── reverse_engineering/       # Malware analysis tools
│   ├── pe_analyzer.py        # PE file analysis
│   └── string_extractor.py   # String extraction
├── tools/                     # Standalone security tools
│   ├── ssl_analyzer.py       # SSL/TLS analyzer
│   └── brute_force_detector.py # Brute force detection
└── scripts/                   # Utility scripts
```

## 🛠️ Tool Catalog

### 🔍 Network Analysis

#### `ip_tracer.py`
- **Description:** Advanced IP tracing with geolocation and network scanning
- **Tags:** `network`, `reconnaissance`, `geolocation`
- **Dependencies:** `scapy`, `requests`, `colorama`
- **Usage:** `python network_analysis/ip_tracer.py <target_ip>`
- **Features:**
  - Traceroute with geolocation
  - Port scanning
  - Network device fingerprinting
  - Service detection
  - Local device information
  - Detailed geolocation data

#### `wifi_scanner.py`
- **Description:** Wireless network scanner with detailed AP information
- **Tags:** `wireless`, `reconnaissance`, `network`
- **Dependencies:** `scapy`, `colorama`
- **Usage:** `python network_analysis/wifi_scanner.py`
- **Features:**
  - Detects nearby wireless networks
  - Shows signal strength and encryption type
  - Identifies connected devices

#### `arp_spoof_detector.py`
- **Description:** Detect ARP spoofing attacks in real-time
- **Tags:** `security`, `network`, `ids`
- **Dependencies:** `scapy`, `colorama`
- **Usage:** `python network_analysis/arp_spoof_detector.py [-i INTERFACE]`
- **Features:**
  - Monitors ARP traffic
  - Alerts on ARP spoofing attempts
  - Shows MAC address changes

### 🔒 Security Tools

#### `ssl_analyzer.py`
- **Description:** Check SSL/TLS configuration of web servers
- **Tags:** `security`, `web`, `ssl`
- **Dependencies:** `ssl`, `socket`, `OpenSSL`, `colorama`
- **Usage:** `python tools/ssl_analyzer.py example.com:443`
- **Features:**
  - Certificate validation
  - Protocol support detection
  - Cipher suite analysis
  - Security headers check

#### `brute_force_detector.py`
- **Description:** Detect brute force attempts on network services
- **Tags:** `security`, `ids`, `monitoring`
- **Dependencies:** `pyshark`, `colorama`
- **Usage:** `python tools/brute_force_detector.py -i eth0 -t 10 -w 60`
- **Features:**
  - Real-time traffic monitoring
  - Configurable thresholds
  - Multiple protocol support
  - Alert system

### 🔍 Forensics

#### `memory_analyzer.py`
- **Description:** Memory forensics analysis tool
- **Tags:** `forensics`, `memory`, `analysis`
- **Dependencies:** `volatility3`, `pandas`, `colorama`
- **Usage:** `python forensic_analysis/memory_analyzer.py memory.dmp [--profile PROFILE]`
- **Features:**
  - Process analysis
  - Network connections
  - Loaded DLLs
  - Malware indicators
  - Registry analysis

#### `browser_history.py`
- **Description:** Extract and analyze browser history from multiple browsers
- **Tags:** `forensics`, `browser`, `artifacts`
- **Dependencies:** `sqlite3`, `colorama`
- **Usage:** `python forensic_analysis/browser_history.py [--output history.json]`
- **Supported Browsers:**
  - Chrome/Chromium
  - Firefox
  - Microsoft Edge
  - Safari (macOS)
- **Features:**
  - Extracts URLs and visit timestamps
  - Preserves metadata
  - JSON output option

### 🕵️ Reverse Engineering

#### `pe_analyzer.py`
- **Description:** Advanced Windows PE file analyzer
- **Tags:** `reversing`, `malware`, `pe`
- **Dependencies:** `pefile`, `peutils`, `colorama`
- **Usage:** `python reverse_engineering/pe_analyzer.py sample.exe`
- **Features:**
  - File header analysis
  - Section information with entropy
  - Import/Export analysis
  - Security features detection
  - Packer detection

#### `string_extractor.py`
- **Description:** Extract strings from binary files
- **Tags:** `reversing`, `analysis`, `strings`
- **Dependencies:** `python-magic`
- **Usage:** `python reverse_engineering/string_extractor.py file.bin [--min-len 4]`
- **Features:**
  - Configurable minimum length
  - Unicode support
  - Output filtering options

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Administrator/root privileges (for some tools)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/CrownCoreStudios/ethical-hacking-toolkit.git
   cd ethical-hacking-toolkit
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the GUI launcher:
   ```bash
   python toolkit_gui.py
   ```

## 🏷️ Tag Reference

- `network`: Network analysis and scanning
- `security`: Security tools and utilities
- `forensics`: Digital forensics tools
- `reversing`: Reverse engineering tools
- `web`: Web application security
- `wireless`: Wireless network tools
- `malware`: Malware analysis tools
- `automation`: Task automation scripts

## ⚠️ Legal & Ethical Notice

This toolkit is intended for:
- Security research
- Penetration testing (with proper authorization)
- Educational purposes
- Security awareness training

**WARNING:** Unauthorized scanning or testing of networks/systems without explicit permission is illegal. The authors are not responsible for any misuse of these tools.

## 🤝 Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
