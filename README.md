# VulnScanX

A Python CLI web application vulnerability scanner that crawls target apps and detects common security vulnerabilities, outputting a structured HTML report.

## Screenshots

### Terminal Output
![Terminal](screenshots/terminal.png)

### HTML Report
![Report](screenshots/report.png)

## Features
- Crawls web applications up to configurable depth
- Detects XSS (Reflected, Stored)
- Detects SQL Injection via error-based detection
- Detects Missing Security Headers
- Detects Open Redirects
- Auto-login support for DVWA
- Self-contained HTML report with Critical/High/Medium/Low severity breakdown

## Tested Against
- DVWA (Damn Vulnerable Web Application)
- OWASP Juice Shop

## Setup

```bash
git clone https://github.com/YOURUSERNAME/vulnscanx
cd vulnscanx
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py --url http://localhost --dvwa --depth 3 --output report.html
```

| Flag | Description |
|------|-------------|
| `--url` | Target base URL |
| `--depth` | Crawl depth (default: 2) |
| `--dvwa` | Auto-login to DVWA |
| `--checks` | xss sqli redirect headers (default: all) |
| `--output` | Output filename (default: report.html) |

## Legal
For authorized security testing only. Run against DVWA or Juice Shop locally.
