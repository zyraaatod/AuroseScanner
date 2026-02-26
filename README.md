<div align="center">

<div align="center">
  
<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=200&section=header&text=Aurose%20Scanner&fontSize=60&fontColor=fff&animation=twinkling&desc=Tools%20Scanning%20Website&descSize=20&descAlignY=70"/>

</div>

### Real-Engine Web Vulnerability Scanner

Advanced, payload-driven scanner built for deep surface discovery, evidence-based findings, and professional reporting.

[![Owner](https://img.shields.io/badge/GitHub%20Owner-zyraaatod-111827?style=for-the-badge&logo=github)](https://github.com/zyraaatod/)
[![Repository](https://img.shields.io/badge/Repository-AuroseScanner-1d4ed8?style=for-the-badge&logo=github)](https://github.com/zyraaatod/AuroseScanner.git)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](#-installation)
[![Engine](https://img.shields.io/badge/Engine-Real%20Request%20Based-059669?style=for-the-badge)](#-core-strengths)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Termux-7c3aed?style=for-the-badge)](#-installation)

</div>

---


## Why AuroseScanner?

AuroseScanner is designed to feel like a practical offensive-security workbench, not a toy script.  
It combines broad vulnerability coverage with deeper discovery logic and structured evidence in every report.

## Core Strengths

- Real HTTP engine (`GET`/`POST`, headers, retries, timing capture)
- Hidden attack-surface discovery:
  - homepage extraction (`href`/`src`/`action`)
  - `robots.txt` parsing
  - `sitemap.xml` parsing
  - hidden-path candidate probing
- Payload-based scanning from `payloads/*_payloads.txt`
- Payload mutation (raw + encoded variants)
- Multi-target testing per phase
- Differential baseline analysis (compare probe vs baseline response)
- Confidence-scored findings with explicit evidence strings
- JSON reporting ready for triage workflows

## 50 Security Phases

`XSS` `SQLi` `LFI` `SSRF` `XXE` `SSTI` `Command Injection` `Open Redirect` `CSRF` `IDOR`  
`JWT` `NoSQLi` `Header Injection` `CORS` `Race` `Smuggling` `Cache Poisoning` `Prototype Pollution`  
`GraphQL` `WebSocket` `API Leakage` `Cloud Misconfiguration` `WordPress` `Laravel` `Deserialization`  
`DNS` `SSL/TLS` `Sensitive Data Exposure` `Default Credentials` `Info Disclosure` `HPP` `LDAP` `XPath`  
`Mail Header Injection` `CRLF` `Response Splitting` `Session Fixation` `Clickjacking` `Server Misconfiguration`  
`DB Exposure` `Backup Files` `Directory Listing` `Debug Mode` `CSP Weakness` `Subdomain Takeover Indicator`  
`Email Harvesting` `Fingerprint Leakage` `WAF Detection` `Rate Limiting Weakness` `Business Logic Indicator`

---

## Quick Start

```bash
git clone https://github.com/zyraaatod/AuroseScanner.git
cd AuroseScanner
python core/scanner.py https://target.com
```

## Installation

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Termux

```bash
pkg update -y && pkg upgrade -y
pkg install -y python git
git clone https://github.com/zyraaatod/AuroseScanner.git
cd AuroseScanner
pip install --upgrade pip
pip install -r requirements.txt
```

If `requirements.txt` fails on lower-end Termux environments:

```bash
pip install requests tqdm colorama tabulate pyfiglet
```

---

## Usage

### Standard

```bash
python core/scanner.py https://target.com
```

### Deep Scan (Recommended)

```bash
python core/scanner.py https://target.com --max-payloads 0 --threads 12 --hidden-limit 300
```

### CLI Options

| Option           | Description                                     |
| ---------------- | ----------------------------------------------- |
| `--max-payloads` | Maximum payloads per phase (`0` = all payloads) |
| `--threads`      | Worker threads for concurrent probe execution   |
| `--hidden-limit` | Hidden path candidates used during discovery    |

---

## Output & Reporting

Each run generates:

- Terminal summary by phase
- JSON report in `reports/scan_YYYYMMDD_HHMMSS.json`

Each finding includes:

- `phase`, `name`, `severity`
- `payload`, `url`
- `status_code`, `elapsed`
- `confidence`
- `evidence`

This structure is built for quick analyst triage and easy integration into pipelines.

---

## Project Layout

```text
AuroseScanner/
|- core/
|  |- scanner.py
|  |- request_handler.py
|  |- payload_manager.py
|  |- report_generator.py
|  `- utils.py
|- payloads/
|  `- *_payloads.txt
|- reports/
|- config/
|- run.sh
`- requirements.txt
```

## Project Statistics

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=zyraaatod/AuroseScanner&type=Date&theme=dark)](https://star-history.com/#zyraaatod/AuroseScanner&Date)

</div>

---

## Operational Notes

- Start with moderate payload limits for broad recon.
- Increase payload depth on validated/high-value targets.
- Review evidence field before confirming exploitation.
- Use higher thread counts only if target and connection are stable.

---

## Disclaimer

Use only on assets you own or are explicitly authorized to test.  
You are fully responsible for legal and ethical use.

---

<div align="center">

### Built for practical security testing workflows

If this project helps you, star the repository and follow the owner.

[Repository](https://github.com/zyraaatod/AuroseScanner.git) • [Owner](https://github.com/zyraaatod/)

</div>
