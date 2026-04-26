import argparse
import requests
from bs4 import BeautifulSoup
from scanner.crawler import Crawler
from scanner.checks.xss import check_xss
from scanner.checks.sqli import check_sqli
from scanner.checks.open_redirect import check_open_redirect
from scanner.checks.headers import check_headers
from scanner.reporter import generate_report

def login_dvwa(session, base_url):
    base = base_url.rstrip("/")
    resp = session.get(base + "/login.php")
    soup = BeautifulSoup(resp.text, "html.parser")
    token_tag = soup.find("input", {"name": "user_token"})
    token = token_tag["value"] if token_tag else ""
    session.post(base + "/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token,
    })
    resp2 = session.get(base + "/security.php")
    soup2 = BeautifulSoup(resp2.text, "html.parser")
    token_tag2 = soup2.find("input", {"name": "user_token"})
    token2 = token_tag2["value"] if token_tag2 else ""
    session.post(base + "/security.php", data={
        "seclev_submit": "Submit",
        "security": "low",
        "user_token": token2,
    })
    print("[+] Logged into DVWA (security: low)")

def main():
    parser = argparse.ArgumentParser(description="VulnScanX")
    parser.add_argument("--url", required=True)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--output", default="report.html")
    parser.add_argument("--dvwa", action="store_true")
    parser.add_argument("--checks", nargs="+",
        choices=["xss", "sqli", "redirect", "headers"],
        default=["xss", "sqli", "redirect", "headers"])
    args = parser.parse_args()

    print(f"""
  ╔══════════════════════════════════╗
  ║        VulnScanX Scanner         ║
  ║  Target : {args.url:<24}║
  ║  Depth  : {str(args.depth):<24}║
  ╚══════════════════════════════════╝
    """)

    session = requests.Session()
    session.headers.update({"User-Agent": "VulnScanX/1.0 Security Scanner"})

    if args.dvwa:
        login_dvwa(session, args.url)

    print(f"\n[*] Starting crawl at depth {args.depth}...")
    crawler = Crawler(args.url, session=session)
    crawler.crawl(depth=args.depth)
    print(f"[+] Crawl complete. {len(crawler.pages)} pages found.\n")

    all_findings = []

    if "xss" in args.checks:
        print("[*] Running XSS checks...")
        xss_findings = check_xss(crawler.pages, session)
        print(f"    Found {len(xss_findings)} XSS issue(s)")
        all_findings += xss_findings

    if "sqli" in args.checks:
        print("[*] Running SQL Injection checks...")
        sqli_findings = check_sqli(crawler.pages, session)
        print(f"    Found {len(sqli_findings)} SQLi issue(s)")
        all_findings += sqli_findings

    if "redirect" in args.checks:
        print("[*] Running Open Redirect checks...")
        redirect_findings = check_open_redirect(crawler.pages, session)
        print(f"    Found {len(redirect_findings)} redirect issue(s)")
        all_findings += redirect_findings

    if "headers" in args.checks:
        print("[*] Running Security Header checks...")
        header_findings = check_headers(crawler.pages, session)
        print(f"    Found {len(header_findings)} header issue(s)")
        all_findings += header_findings

    print(f"\n[*] Generating report...")
    generate_report(all_findings, target_url=args.url, output_path=args.output)
    print(f"[+] Done! Found {len(all_findings)} issue(s).")

if __name__ == "__main__":
    main()
