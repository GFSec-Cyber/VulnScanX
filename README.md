# VulnScanX 🔍

A Python CLI tool that crawls web applications and automatically detects common vulnerabilities — then generates a clean, structured HTML security report.

Built from scratch as a portfolio project. Tested against DVWA running locally in Docker.

## Screenshots

### Scanner in Action
<img width="1319" height="983" alt="11 findings terminal" src="https://github.com/user-attachments/assets/177e2acc-a746-4543-b63e-21a041c82022" />


### HTML Report Output
<img width="1319" height="983" alt="11 findings" src="https://github.com/user-attachments/assets/50ee8efd-fb1c-4f77-abd0-9de63cfeba54" />


## What It Detects

| Vulnerability | Severity | How |
|---|---|---|
| SQL Injection | Critical | Sends payloads, checks for DB errors in response |
| XSS (Reflected + Stored) | High | Injects scripts, checks if they reflect back unescaped |
| Open Redirects | Medium | Tests URL parameters for external redirect acceptance |
| Missing Security Headers | Low | Checks response headers against a known-good list |

## How It Works

1. Logs into the target app (DVWA auto-login supported)
2. Crawls all reachable pages up to a configurable depth
3. Extracts every form and input field on each page
4. Fires payloads against each form for each vulnerability class
5. Writes findings to a self-contained HTML report

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
# Full scan against DVWA
python main.py --url http://localhost --dvwa --depth 3 --output report.html

# Specific checks only
python main.py --url http://localhost --dvwa --checks xss sqli

# Scan any target
python main.py --url http://target.com --depth 2 --output report.html
```

## Flags

| Flag | Description |
|---|---|
| `--url` | Target URL (required) |
| `--depth` | How deep to crawl (default: 2) |
| `--dvwa` | Auto-login to DVWA |
| `--checks` | Which checks to run: xss sqli redirect headers |
| `--output` | Report filename (default: report.html) |

## Run Your Own DVWA Target

```bash
sudo docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa
# Then visit http://localhost/setup.php → Create/Reset Database
```

## Project Structure
'''
vulnscanx/
├── scanner/
│   ├── crawler.py           # Crawls pages, extracts forms and links
│   ├── reporter.py          # Generates the HTML report
│   └── checks/
│       ├── xss.py           # XSS payload injection and reflection check
│       ├── sqli.py          # SQL injection error-based detection
│       ├── open_redirect.py # URL parameter redirect testing
│       └── headers.py       # Security header presence check
├── main.py                  # CLI entry point
└── requirements.txt
'''
## Results Against DVWA

- 21 pages crawled
- 2 Critical — SQL Injection
- 3 High — XSS (Reflected + Stored)
- 6 Low — Missing Security Headers

## Stack

- Python 3
- requests + BeautifulSoup4 for crawling
- Custom HTML report generator (no frameworks)
- Docker for running vulnerable target apps

## ⚠️ Legal

For authorized testing only. Run against DVWA, Juice Shop, or apps you own. Never scan targets without permission.
