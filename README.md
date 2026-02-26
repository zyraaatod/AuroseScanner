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
pip install --upgrade --upgrade-strategy eager -r requirements.txt
```

### Termux

```bash
pkg update -y && pkg upgrade -y
pkg install -y python git
git clone https://github.com/zyraaatod/AuroseScanner.git
cd AuroseScanner
pip install --upgrade pip
pip install --upgrade --upgrade-strategy eager -r requirements.txt
```

If `requirements.txt` fails on lower-end Termux environments:

```bash
pip install requests tqdm colorama tabulate pyfiglet
```

Jika muncul warning:
`RequestsDependencyWarning: urllib3 ... doesn't match a supported version`

jalankan sinkronisasi ini di virtual environment:

```bash
pip uninstall -y requests urllib3 chardet charset_normalizer
pip install --upgrade --force-reinstall \
  "requests>=2.32.0,<3.0.0" \
  "urllib3>=2.2.0,<3.0.0" \
  "charset_normalizer>=3.3.0,<4.0.0" \
  "chardet>=5.2.0,<6.0.0"
```

---

## Usage

### Standard

```bash
python core/scanner.py https://target.com
```

### Deep Scan (Recommended)

```bash
python core/scanner.py https://target.com --max-payloads 0 --threads 12 --hidden-limit 300 --ui-profile retro
```

### Aman dan Terkontrol

```bash
python core/scanner.py https://target.com --max-requests 3000 --max-runtime 900 --include api,auth --exclude logout,static
```

### CLI Options

| Option           | Description                                     |
| ---------------- | ----------------------------------------------- |
| `--max-payloads` | Maximum payloads per phase (`0` = all payloads) |
| `--threads`      | Worker threads for concurrent probe execution   |
| `--hidden-limit` | Hidden path candidates used during discovery    |
| `--max-requests` | Batas total request (`0` = tanpa batas)         |
| `--max-runtime`  | Batas waktu scan dalam detik (`0` = tanpa batas) |
| `--include`      | Hanya path yang cocok dengan kata ini (koma)    |
| `--exclude`      | Kecualikan path yang cocok dengan kata ini (koma) |
| `--live-header` / `--no-live-header` | Aktif/nonaktif header live terminal |
| `--ui-profile`   | Gaya UI terminal: `minimal`, `compact`, `retro` |
| `--verify-findings` / `--no-verify-findings` | Verifikasi ulang temuan untuk menekan false positive |

---

## Output & Reporting

Each run generates:

- Terminal summary by phase
- JSON report per domain target, contoh: `reports/target.com.json`
- Jika scan domain yang sama berulang, hasil lama dan baru ditumpuk dalam file yang sama (`riwayat_scan`)

Each finding includes:

- `phase`, `name`, `severity`
- `payload`, `url`
- `status_code`, `elapsed`
- `confidence`
- `evidence`

This structure is built for quick analyst triage and easy integration into pipelines.

### Arti `status_code` pada hasil

- `200`/`201`/`202`/`204`: endpoint bisa diakses (berhasil)
- `301`/`302`/`307`/`308`: endpoint mengalihkan request (redirect)
- `401`: butuh autentikasi
- `403`: akses ditolak
- `404`: endpoint/path tidak ditemukan
- `429`: request dibatasi (rate limit)
- `500`/`502`/`503`/`504`: error di sisi server/gateway
- `0`: tidak ada respons HTTP (jaringan, DNS, timeout, koneksi gagal)

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
