# 🛡️ SecurityNexus: Full-Stack Cybersecurity Assessment Platform# SecurityNexus: Full-Stack Cybersecurity Assessment Platform



<div align="center">This repository contains **SecurityNexus** — a comprehensive, full-stack cybersecurity assessment platform for professional penetration testing, security audits, and educational purposes.



![Version](https://img.shields.io/badge/version-5.0-blue.svg)All documentation has been consolidated into `DOCUMENTATION.md`.

![Python](https://img.shields.io/badge/python-3.8+-green.svg)

![License](https://img.shields.io/badge/license-Educational-orange.svg)Quick start:

![Status](https://img.shields.io/badge/status-Active-success.svg)

```bash

**A comprehensive penetration testing framework for security professionals and researchers**./launcher.sh

```

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Legal](#-legal-disclaimer)

Read the full documentation:

</div>

- `DOCUMENTATION.md` — comprehensive guide, setup, usage, and references.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Module Documentation](#-module-documentation)
- [Legal Disclaimer](#-legal-disclaimer)
- [Contributing](#-contributing)

---

## 🎯 Overview

**SecurityNexus** is an enterprise-grade cybersecurity assessment platform designed for penetration testing, vulnerability assessment, and security research. Built with Python 3.8+, it provides 23+ specialized modules covering web application security, network reconnaissance, OSINT, and advanced exploitation techniques.

### Key Highlights

- 🚀 **23+ Security Modules** - Comprehensive coverage of attack vectors
- 🔍 **Advanced Reconnaissance** - Subdomain enumeration, port scanning, service detection
- 💉 **Web Exploitation** - SQLi, XSS, SSRF, JWT attacks, directory fuzzing
- 🌐 **Network Analysis** - Port scanning with OS detection, service fingerprinting
- 🕵️ **OSINT Capabilities** - Email harvesting, metadata extraction
- 📊 **Automated Reporting** - JSON reports with severity classification
- 🎨 **Interactive Launcher** - Unified CLI interface for all modules
- 🔐 **Security Hardening** - System hardening and emergency response tools

---

## ✨ Features

### 🔴 Web Application Attacks

| Module | Description | Key Features |
|--------|-------------|--------------|
| **SQL Injection** | Advanced SQLi testing with 8+ techniques | Union-based, Boolean-based, Time-based, Error-based, Stacked queries |
| **XSS Attack** | Cross-Site Scripting vulnerability scanner | Reflected, Stored, DOM-based, Polyglot payloads, WAF bypass |
| **SSRF Scanner** | Server-Side Request Forgery exploitation | Cloud metadata extraction (AWS/GCP/Azure), Internal port scanning, 20+ bypass techniques |
| **JWT Analyzer** | JSON Web Token security testing | "none" algorithm attack, Weak secret brute-force, RS256→HS256 confusion, Header injection |
| **Directory Fuzzer** | Hidden directory & file discovery | 100+ high-value paths, Sensitive file detection, CMS-specific targets |
| **Brute Force** | Authentication brute-forcing | Multi-threaded, Custom wordlists, Form-based & HTTP Basic Auth |

### 🔵 Network Reconnaissance

| Module | Description | Key Features |
|--------|-------------|--------------|
| **Advanced Port Scanner** | Enterprise port scanning with intelligence | OS detection (TTL analysis), Service version detection, CVE lookup, Banner grabbing |
| **Advanced Service Identifier** | Service fingerprinting with CVE integration | Version-specific vulnerabilities, Exploit recommendations, Attack vectors |
| **Advanced Web Crawler** | Intelligent web spidering | JavaScript analysis, API discovery, Form extraction, Vulnerability patterns |
| **Subdomain Scanner** | Subdomain enumeration & takeover detection | DNS brute-force (200+ subdomains), Certificate Transparency logs, Takeover detection (15+ services) |
| **Tech Fingerprinter** | Technology stack identification | WAF detection (20+ vendors), CMS/Framework detection, Server identification |
| **Service Enumerator** | Advanced service enumeration | MySQL, FTP, cPanel reconnaissance |

### 🟢 OSINT & Information Gathering

| Module | Description | Key Features |
|--------|-------------|--------------|
| **Email Harvester** | Email address collection from websites | Multi-source harvesting, Pattern validation, Domain filtering |
| **Metadata Extractor** | File metadata analysis | PDF, Images (EXIF), Office documents, Location data |

### 🟡 Security Hardening

| Module | Description | Key Features |
|--------|-------------|--------------|
| **System Hardening** | Linux security hardening | Firewall configuration, SSH hardening, Service disabling, User auditing |
| **Emergency Response** | Rapid incident response | Threat detection, Log analysis, Network monitoring, Backup creation |

### 🟣 Vulnerable Web Application

| Component | Description | Purpose |
|-----------|-------------|---------|
| **Flask WebApp** | Intentionally vulnerable web application | Practice SQL injection, XSS, CSRF, Command injection, File upload vulnerabilities |

---

## 🏗️ Architecture

```
SecurityNexus/
├── attack_modules/          # Web exploitation modules
│   ├── sql_injection_attack.py      # SQLi testing (900+ lines)
│   ├── xss_attack.py                # XSS scanner (600+ lines)
│   ├── ssrf_scanner.py              # SSRF exploitation (450+ lines)
│   ├── jwt_analyzer.py              # JWT security testing (600+ lines)
│   ├── brute_force_attack.py        # Authentication attacks
│   ├── mysql_attack.py              # MySQL exploitation
│   ├── ftp_attack.py                # FTP attacks
│   ├── cpanel_attack.py             # cPanel testing
│   ├── usernames.txt                # Username wordlist
│   └── passwords.txt                # Password wordlist
│
├── network_attacks/         # Network & reconnaissance modules
│   ├── advanced_port_scanner.py     # Port scanning (800+ lines)
│   ├── advanced_service_identifier.py # Service fingerprinting (650+ lines)
│   ├── advanced_web_crawler.py      # Web crawling (530+ lines)
│   ├── subdomain_scanner.py         # Subdomain enumeration (500+ lines)
│   ├── directory_fuzzer.py          # Directory brute-forcing (350+ lines)
│   ├── tech_fingerprinter.py        # Technology detection (450+ lines)
│   ├── advanced_port_analysis.py    # Port analysis
│   └── service_enumerator.py        # Service enumeration
│
├── osint_module/            # OSINT tools
│   ├── email_harvester.py           # Email harvesting
│   └── metadata_extractor.py        # Metadata extraction
│
├── security_tools/          # Security hardening
│   └── harden.py                    # System hardening tool
│
├── vulnerable_webapp/       # Practice target
│   ├── app.py                       # Flask application
│   ├── templates/                   # HTML templates
│   └── static/                      # Static assets
│
├── reporting/               # Report generation module
├── reports/                 # Generated security reports
├── launcher.sh              # Unified launcher (24 options)
├── requirements.txt         # Python dependencies
└── DOCUMENTATION.md         # Detailed documentation
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.8+** (Tested on 3.8, 3.9, 3.10, 3.11, 3.13)
- **Linux** (Ubuntu/Debian/Kali recommended)
- **Git**

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/SecurityNexus.git
cd SecurityNexus
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
# venv\Scripts\activate   # On Windows
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
chmod +x launcher.sh
./launcher.sh
```

---

## ⚡ Quick Start

### Launch Interactive Menu

```bash
./launcher.sh
```

#### Quick Site Audit (fingerprint + crawl + fuzz)
```bash
python site_audit.py https://example.com --depth 2 --max-urls 150 --max-paths 80 --timeout 10
# Proxy/TLS options:
python site_audit.py https://example.com --proxy http://127.0.0.1:8080 --insecure
```

You'll see a menu with 24 options:

```
╔══════════════════════════════════════════════════════════════╗
║      SecurityNexus: Full-Stack Cybersecurity Platform       ║
╚══════════════════════════════════════════════════════════════╝

WEB APPLICATION ATTACKS:
  1. SQL Injection Attack
  2. XSS (Cross-Site Scripting) Attack
  3. Brute Force Attack

DATABASE & SERVICE ATTACKS:
  4. MySQL Attack
  5. FTP Attack
  6. cPanel Attack

NETWORK RECONNAISSANCE:
  7. Advanced Port Scanner
  8. Advanced Service Identifier
  9. Service Enumerator
 10. Advanced Port Analysis

ADVANCED WEB RECON:
 11. Advanced Web Crawler
 12. Subdomain Scanner & Takeover
 13. Directory & File Fuzzer
 14. Technology Fingerprinter

ADVANCED WEB ATTACKS:
 15. JWT Security Analyzer
 16. SSRF Scanner

OSINT (Open Source Intelligence):
 17. Email Harvester
 18. Metadata Extractor

AUTOMATION:
 24. Quick Site Audit (fingerprint + crawl + fuzz)

SECURITY & HARDENING:
 19. Security Hardening
 20. Emergency Hardening

UTILITIES:
 21. Shell Access
 22. View Reports

 0. Exit
```

### Example Usage

#### 1. SQL Injection Testing
```bash
# Select option 1 from launcher
python attack_modules/sql_injection_attack.py "http://target.com/page?id=1"
```

#### 2. Subdomain Enumeration
```bash
# Select option 12 from launcher
python network_attacks/subdomain_scanner.py target.com -t 50 -o report.json
```

#### 3. Advanced Port Scanning
```bash
# Select option 7 from launcher
python network_attacks/advanced_port_scanner.py 192.168.1.1 --common -t 100
```

#### 4. JWT Security Analysis
```bash
# Select option 15 from launcher
python attack_modules/jwt_analyzer.py "eyJhbGc..." -w attack_modules/passwords.txt
```

#### 5. Directory Fuzzing
```bash
# Select option 13 from launcher
python network_attacks/directory_fuzzer.py http://target.com -t 30
```

---

## 📚 Module Documentation

### Web Exploitation

<details>
<summary><b>SQL Injection Attack</b></summary>

**File:** `attack_modules/sql_injection_attack.py`

**Description:** Advanced SQL injection testing with 8+ exploitation techniques including Union-based, Boolean-based, Time-based, Error-based, and Stacked queries.

**Usage:**
```bash
python attack_modules/sql_injection_attack.py "http://target.com/page?id=1"
python attack_modules/sql_injection_attack.py "http://target.com/search" -p query -m POST
```

**Features:**
- 8+ SQLi techniques
- Automatic database enumeration
- Table and column extraction
- Data exfiltration
- WAF bypass payloads
- JSON report generation

</details>

<details>
<summary><b>XSS Attack Scanner</b></summary>

**File:** `attack_modules/xss_attack.py`

**Description:** Comprehensive XSS vulnerability scanner with support for Reflected, Stored, and DOM-based XSS.

**Usage:**
```bash
python attack_modules/xss_attack.py "http://target.com/search?q=test"
python attack_modules/xss_attack.py "http://target.com/comment" -p message -m POST
```

**Features:**
- 30+ XSS payloads
- Polyglot payloads
- WAF bypass techniques
- Context-aware testing
- Severity classification

</details>

<details>
<summary><b>SSRF Scanner</b></summary>

**File:** `attack_modules/ssrf_scanner.py`

**Description:** Server-Side Request Forgery exploitation with cloud metadata extraction and internal network scanning.

**Usage:**
```bash
python attack_modules/ssrf_scanner.py "http://target.com/fetch?url=google.com"
python attack_modules/ssrf_scanner.py "http://target.com/proxy" -p url -v
```

**Features:**
- Cloud metadata extraction (AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle)
- Internal port scanning via SSRF
- File protocol exploitation
- 20+ bypass techniques
- Blind SSRF detection

</details>

<details>
<summary><b>JWT Analyzer</b></summary>

**File:** `attack_modules/jwt_analyzer.py`

**Description:** JWT security testing with 7 attack vectors including algorithm confusion and secret brute-forcing.

**Usage:**
```bash
python attack_modules/jwt_analyzer.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
python attack_modules/jwt_analyzer.py "token_here" -w passwords.txt
```

**Features:**
- "none" algorithm attack (CVE-2015-9235)
- Weak secret brute-force
- RS256 to HS256 key confusion (CVE-2016-5431)
- Header injection testing
- Claim manipulation

</details>

### Network Reconnaissance

<details>
<summary><b>Advanced Port Scanner</b></summary>

**File:** `network_attacks/advanced_port_scanner.py`

**Description:** Enterprise-grade port scanner with OS detection, service versioning, and CVE lookup.

**Usage:**
```bash
python network_attacks/advanced_port_scanner.py 192.168.1.1 --common
python network_attacks/advanced_port_scanner.py example.com --ports 1-1000 -t 200
python network_attacks/advanced_port_scanner.py target.com --all -o report.json
```

**Features:**
- OS detection via TTL analysis
- Service version detection
- CVE vulnerability lookup
- Banner grabbing
- Multi-threaded scanning (up to 200 threads)
- Common/Top/All port presets

</details>

<details>
<summary><b>Subdomain Scanner</b></summary>

**File:** `network_attacks/subdomain_scanner.py`

**Description:** Comprehensive subdomain enumeration with takeover vulnerability detection.

**Usage:**
```bash
python network_attacks/subdomain_scanner.py example.com
python network_attacks/subdomain_scanner.py target.com -t 50 -o report.json
```

**Features:**
- DNS brute-force (200+ subdomains)
- Certificate Transparency log search
- Subdomain takeover detection (GitHub Pages, AWS S3, Heroku, Azure, Shopify, etc.)
- Multi-threaded scanning
- Severity classification

</details>

<details>
<summary><b>Advanced Web Crawler</b></summary>

**File:** `network_attacks/advanced_web_crawler.py`

**Description:** Intelligent web crawler with JavaScript analysis and vulnerability pattern detection.

**Usage:**
```bash
python network_attacks/advanced_web_crawler.py https://example.com
python network_attacks/advanced_web_crawler.py https://target.com -d 5 -m 1000
python network_attacks/advanced_web_crawler.py https://site.com -o report.json
```

**Features:**
- JavaScript file analysis (API keys, endpoints, secrets)
- API endpoint discovery (REST, GraphQL)
- Form extraction
- Parameter discovery
- Vulnerability pattern detection
- Technology detection

</details>

<details>
<summary><b>Directory Fuzzer</b></summary>

**File:** `network_attacks/directory_fuzzer.py`

**Description:** Directory and file discovery tool with 100+ high-value targets.

**Usage:**
```bash
python network_attacks/directory_fuzzer.py http://target.com
python network_attacks/directory_fuzzer.py http://example.com -t 50 -o report.json
```

**Features:**
- 100+ high-value paths (.git, .env, backup files, admin panels)
- Sensitive file detection
- CMS-specific paths (WordPress, Joomla, Drupal)
- Multi-threaded fuzzing
- Smart severity assessment

</details>

<details>
<summary><b>Technology Fingerprinter</b></summary>

**File:** `network_attacks/tech_fingerprinter.py`

**Description:** Identify web technologies, frameworks, WAFs, and server software.

**Usage:**
```bash
python network_attacks/tech_fingerprinter.py https://target.com
python network_attacks/tech_fingerprinter.py https://example.com -o report.json
```

**Features:**
- WAF detection (Cloudflare, AWS WAF, Akamai, Imperva, etc.)
- CMS detection (WordPress, Joomla, Drupal, Magento)
- Framework identification (React, Angular, Django, Laravel)
- Server software detection
- CDN detection

</details>

### OSINT

<details>
<summary><b>Email Harvester</b></summary>

**File:** `osint_module/email_harvester.py`

**Description:** Email address collection from websites and public sources.

**Usage:**
```bash
python osint_module/email_harvester.py https://example.com
python osint_module/email_harvester.py https://target.com -d 3
```

**Features:**
- Multi-source harvesting
- Pattern validation
- Domain filtering
- Recursive crawling

</details>

<details>
<summary><b>Metadata Extractor</b></summary>

**File:** `osint_module/metadata_extractor.py`

**Description:** Extract metadata from PDFs, images, and office documents.

**Usage:**
```bash
python osint_module/metadata_extractor.py document.pdf
python osint_module/metadata_extractor.py image.jpg
```

**Features:**
- PDF metadata extraction
- EXIF data from images
- Office document properties
- GPS location data
- Author and creation date

</details>

---

## 🧪 Vulnerable Web Application

SecurityNexus includes a deliberately vulnerable Flask web application for practice:

```bash
cd vulnerable_webapp
python app.py
# Access at http://localhost:5000
```

**Available Vulnerabilities:**
- SQL Injection (Login bypass, Data extraction)
- XSS (Reflected, Stored)
- CSRF
- Command Injection
- File Upload Vulnerabilities
- Insecure Direct Object References (IDOR)

---

## 📊 Reporting

All modules generate detailed JSON reports in the `reports/` directory:

```json
{
  "target": "example.com",
  "timestamp": "2025-12-03T22:00:00",
  "module": "subdomain_scanner",
  "findings": [
    {
      "subdomain": "admin.example.com",
      "ip": "192.168.1.100",
      "severity": "HIGH",
      "vulnerability": "Potential subdomain takeover"
    }
  ],
  "summary": {
    "total_subdomains": 25,
    "vulnerable": 3,
    "scan_duration": 45.2
  }
}
```

---

## ⚖️ Legal Disclaimer

**🚨 IMPORTANT - READ CAREFULLY 🚨**

This tool is provided for **EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**.

### Legal Usage

✅ **Authorized Activities:**
- Testing your own systems and networks
- Security research with written permission
- Penetration testing with signed contracts
- Educational purposes in controlled environments
- Bug bounty programs with explicit authorization

❌ **Illegal Activities:**
- Unauthorized access to systems you don't own
- Testing without explicit written permission
- Malicious attacks or data theft
- Violating computer fraud and abuse laws

### User Responsibilities

By using SecurityNexus, you agree to:

1. **Obtain Authorization**: Always get written permission before testing any system
2. **Follow Laws**: Comply with all applicable local, state, and federal laws
3. **Ethical Use**: Use responsibly and ethically
4. **No Liability**: Authors are not responsible for misuse or damages
5. **Educational Intent**: Understand this is for learning and authorized testing only

### Legal Consequences

Unauthorized use of these tools may violate:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

**Penalties may include criminal charges, fines, and imprisonment.**

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

### Code Standards

- Follow PEP 8 style guidelines
- Add docstrings to functions and classes
- Include type hints where appropriate
- Write descriptive commit messages
- Test your code before submitting

---

## 📝 License

This project is licensed under the **Educational Use License**.

**Terms:**
- ✅ Free for educational and research purposes
- ✅ Must obtain authorization before testing
- ❌ No commercial use without permission
- ❌ No warranty or liability

---

## 📬 Contact

- **Author**: Faizan
- **GitHub**: [(https://github.com/MFAIZAN20/SecurityNexus)]
- **Project**: SecurityNexus - Full-Stack Cybersecurity Assessment Platform
- **Issues**: Report bugs or request features via GitHub Issues

---

## 🌟 Acknowledgments

- Python community for excellent libraries
- Security researchers and CTF creators
- Open-source security tools that inspired this project
- Bug bounty platforms for vulnerability research opportunities

---

## 📈 Roadmap

### Upcoming Features

- [ ] Automated exploit generation
- [ ] Machine learning-based vulnerability detection
- [ ] Cloud security testing (AWS, Azure, GCP)
- [ ] API security testing framework
- [ ] Mobile application security testing
- [ ] Advanced phishing simulation
- [ ] Docker containerization
- [ ] Web-based GUI interface

---

<div align="center">

**⭐ Star this repository if you find it helpful! ⭐**

Made with ❤️ for the cybersecurity community

</div>
