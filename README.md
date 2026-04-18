# SecurityNexus: Full-Stack Cybersecurity Assessment Platform

SecurityNexus is a full-stack cybersecurity assessment platform for professional penetration testing, security audits, and education.

![Version](https://img.shields.io/badge/version-5.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-Educational-orange.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)

> All documentation has been consolidated into `DOCUMENTATION.md`.

A comprehensive penetration testing framework for security professionals and researchers.

Quick start:
```bash
./launcher.sh
```

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#module-documentation) • [Legal](#legal-disclaimer)

- `DOCUMENTATION.md` — comprehensive guide, setup, usage, and references.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Module Documentation](#module-documentation)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)

---

## Overview

SecurityNexus is an enterprise-grade cybersecurity assessment platform designed for penetration testing, vulnerability assessment, and security research. Built with Python 3.8+, it provides 23+ specialized modules covering web application security, network reconnaissance, OSINT, and advanced exploitation techniques.

### Key Highlights

- **23+ Security Modules** — Comprehensive coverage of attack vectors
- **Advanced Reconnaissance** — Subdomain enumeration, port scanning, service detection
- **Web Exploitation** — SQLi, XSS, SSRF, JWT attacks, directory fuzzing
- **Network Analysis** — Port scanning with OS detection and service fingerprinting
- **OSINT Capabilities** — Email harvesting and metadata extraction
- **Automated Reporting** — JSON reports with severity classification
- **Interactive Launcher** — Unified CLI interface for all modules
- **Security Hardening** — System hardening and emergency response tools

---

## Features

### Web Application Attacks

| Module | Description | Key Features |
|--------|-------------|--------------|
| **SQL Injection** | Advanced SQLi testing with 8+ techniques | Union-based, Boolean-based, Time-based, Error-based, Stacked queries |
| **XSS Attack** | Cross-site scripting vulnerability scanner | Reflected, Stored, DOM-based, Polyglot payloads, WAF bypass |
| **SSRF Scanner** | Server-side request forgery exploitation | Cloud metadata extraction (AWS/GCP/Azure), internal port scanning, 20+ bypass techniques |
| **JWT Analyzer** | JSON Web Token security testing | `none` algorithm attack, weak secret brute-force, RS256→HS256 confusion, header injection |
| **Directory Fuzzer** | Hidden directory and file discovery | 100+ high-value paths, sensitive file detection, CMS-specific targets |
| **Brute Force** | Authentication brute-forcing | Multi-threaded, custom wordlists, form-based and HTTP Basic Auth |

### Network Reconnaissance

| Module | Description | Key Features |
|--------|-------------|--------------|
| **Advanced Port Scanner** | Enterprise port scanning with intelligence | OS detection (TTL analysis), service version detection, CVE lookup, banner grabbing |
| **Advanced Service Identifier** | Service fingerprinting with CVE integration | Version-specific vulnerabilities, exploit recommendations, attack vectors |
| **Advanced Web Crawler** | Intelligent web spidering | JavaScript analysis, API discovery, form extraction, vulnerability patterns |
| **Subdomain Scanner** | Subdomain enumeration and takeover detection | DNS brute-force (200+ subdomains), Certificate Transparency logs, takeover detection (15+ services) |
| **Tech Fingerprinter** | Technology stack identification | WAF detection (20+ vendors), CMS/framework detection, server identification |
| **Service Enumerator** | Advanced service enumeration | MySQL, FTP, cPanel reconnaissance |

### OSINT and Information Gathering

| Module | Description | Key Features |
|--------|-------------|--------------|
| **Email Harvester** | Email collection from websites | Multi-source harvesting, pattern validation, domain filtering |
| **Metadata Extractor** | File metadata analysis | PDF, images (EXIF), Office documents, location data |

### Security Hardening

| Module | Description | Key Features |
|--------|-------------|--------------|
| **System Hardening** | Linux security hardening | Firewall configuration, SSH hardening, service disabling, user auditing |
| **Emergency Response** | Rapid incident response | Threat detection, log analysis, network monitoring, backup creation |

### Vulnerable Web Application

| Component | Description | Purpose |
|-----------|-------------|---------|
| **Flask WebApp** | Intentionally vulnerable web application | Practice SQL injection, XSS, CSRF, command injection, file upload vulnerabilities |

---

## Architecture

```text
SecurityNexus/
├── attack_modules/
├── network_attacks/
├── osint_module/
├── security_tools/
├── vulnerable_webapp/
├── reporting/
├── reports/
├── launcher.sh
├── requirements.txt
└── DOCUMENTATION.md
```

---

## Installation

### Prerequisites

- Python 3.8+ (tested on 3.8, 3.9, 3.10, 3.11, 3.13)
- Linux (Ubuntu/Debian/Kali recommended)
- Git

### Step 1: Clone Repository

```bash
git clone https://github.com/MFAIZAN20/SecurityNexus.git
cd SecurityNexus
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
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

## Quick Start

### Launch Interactive Menu

```bash
./launcher.sh
```

### Quick Site Audit (fingerprint + crawl + fuzz)

```bash
python site_audit.py https://example.com --depth 2 --max-urls 150 --max-paths 80 --timeout 10
# Proxy/TLS options:
python site_audit.py https://example.com --proxy http://127.0.0.1:8080 --insecure
```

---

## Module Documentation

Detailed module-level usage and examples are available in:

- `DOCUMENTATION.md`

---

## Vulnerable Web Application

SecurityNexus includes a deliberately vulnerable Flask web application for practice:

```bash
cd vulnerable_webapp
python app.py
# Access at http://localhost:5000
```

Available vulnerabilities include SQL Injection, XSS, CSRF, command injection, insecure file upload handling, and IDOR patterns.

---

## Reporting

All modules generate JSON reports in the `reports/` directory.

---

## Legal Disclaimer

This tool is provided for **educational and authorized testing purposes only**.

### Authorized Activities

- Testing systems you own
- Security research with written permission
- Penetration testing with signed contracts
- Controlled educational environments
- Bug bounty programs with explicit authorization

### Prohibited Activities

- Unauthorized access to systems you do not own
- Testing without explicit written permission
- Malicious attacks or data theft
- Violations of computer misuse laws

By using SecurityNexus, you agree to obtain authorization, follow all applicable laws, and use the platform ethically.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m "Add YourFeature"`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

### Code Standards

- Follow PEP 8
- Add docstrings to functions and classes
- Include type hints where appropriate
- Write descriptive commit messages
- Test before submitting

---

## License

This project is licensed under the **Educational Use License**.

- Free for educational and research purposes
- Authorization is required before testing
- No commercial use without permission
- No warranty or liability

---

## Contact

- **Author**: Faizan
- **GitHub**: https://github.com/MFAIZAN20/SecurityNexus
- **Project**: SecurityNexus - Full-Stack Cybersecurity Assessment Platform
- **Issues**: Use GitHub Issues for bug reports and feature requests

---

## Acknowledgments

- Python community and maintainers
- Security researchers and CTF creators
- Open-source security tool authors
- Bug bounty platforms and communities

---

## Roadmap

- [ ] Automated exploit generation
- [ ] ML-based vulnerability detection
- [ ] Cloud security testing (AWS, Azure, GCP)
- [ ] API security testing framework
- [ ] Mobile application security testing
- [ ] Advanced phishing simulation
- [ ] Docker containerization
- [ ] Web-based GUI interface

---

If this project helps you, consider starring the repository.
