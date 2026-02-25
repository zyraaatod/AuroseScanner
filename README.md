# AuroseScanner

Advanced web vulnerability scanner with a real request engine, payload-based testing, hidden-surface discovery, and evidence-based reporting.

[![Owner](https://img.shields.io/badge/GitHub%20Owner-zyraaatod-black?logo=github)](https://github.com/zyraaatod/)
[![Repository](https://img.shields.io/badge/Repository-AuroseScanner-blue?logo=github)](https://github.com/zyraaatod/AuroseScanner.git)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](#installation)
[![License](https://img.shields.io/badge/Use-Ethically-red)](#disclaimer)

## Official Links

- Owner: https://github.com/zyraaatod/
- Repository: https://github.com/zyraaatod/AuroseScanner.git

## Highlights

- 50 vulnerability test phases
- Real HTTP request engine (GET/POST, retries, headers, timing)
- Hidden attack surface discovery:
  - homepage link extraction
  - `robots.txt`
  - `sitemap.xml`
  - hidden path candidate probing
- Payload-driven scanning (`payloads/*_payloads.txt`)
- Payload mutation (`raw`, encoded variants)
- Multi-target scanning per phase
- Confidence + evidence output per finding
- JSON reporting to `reports/`
- Works on Linux and Termux

## Methods (50)

XSS, SQLi, LFI, SSRF, XXE, SSTI, CMD Injection, Open Redirect, CSRF, IDOR, JWT, NoSQLi, Header Injection, CORS, Race, Smuggling, Cache Poisoning, Prototype Pollution, GraphQL, WebSocket, API Leakage, Cloud Misconfiguration, WordPress, Laravel, Deserialization, DNS, SSL/TLS, Sensitive Data Exposure, Default Credentials, Info Disclosure, HPP, LDAP, XPath, Mail Header Injection, CRLF, Response Splitting, Session Fixation, Clickjacking, Server Misconfiguration, DB Exposure, Backup Files, Directory Listing, Debug Mode, CSP Weakness, Subdomain Takeover Indicator, Email Harvesting, Fingerprint Leakage, WAF Detection, Rate Limiting Weakness, Business Logic Indicator.

## Installation

### Linux

```bash
git clone https://github.com/zyraaatod/AuroseScanner.git
cd AuroseScanner
python3 -m venv .venv
source .venv/bin/activate
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

If `requirements.txt` fails on some Termux devices, install minimal runtime:

```bash
pip install requests tqdm colorama tabulate pyfiglet
```

## Usage

```bash
python core/scanner.py https://target.com
```

### Advanced Usage

```bash
python core/scanner.py https://target.com --max-payloads 0 --threads 12 --hidden-limit 300
```

### CLI Options

- `--max-payloads`: max payloads per phase (`0` = all payloads)
- `--threads`: concurrent workers per phase
- `--hidden-limit`: hidden path candidates used in discovery

## Output

- Scan summary in terminal
- JSON report in `reports/scan_YYYYMMDD_HHMMSS.json`
- Finding fields include:
  - phase
  - severity
  - payload
  - status code
  - elapsed time
  - confidence
  - evidence

## Project Structure

```text
core/
  scanner.py
  request_handler.py
  payload_manager.py
  report_generator.py
  utils.py
payloads/
  *_payloads.txt
reports/
config/
```

## Disclaimer

Use this tool only on systems you own or have explicit permission to test.  
You are responsible for legal and ethical usage.
