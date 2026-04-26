import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

REDIRECT_PAYLOAD = "https://evil.example.com"
REDIRECT_PARAMS = ["redirect", "redirect_to", "next", "url", "return", "returnUrl", "goto", "dest"]

def check_open_redirect(pages, session):
    findings = []

    for page in pages:
        parsed = urlparse(page["url"])
        query_params = parse_qs(parsed.query)

        for param in REDIRECT_PARAMS:
            if param in query_params:
                # Replace the param value with the evil URL
                new_params = {k: v[0] for k, v in query_params.items()}
                new_params[param] = REDIRECT_PAYLOAD
                new_query = urlencode(new_params)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = session.get(test_url, allow_redirects=False, timeout=5)
                    location = resp.headers.get("Location", "")
                    if REDIRECT_PAYLOAD in location:
                        findings.append({
                            "type": "Open Redirect",
                            "severity": "Medium",
                            "url": test_url,
                            "detail": f"Redirects to external URL via param '{param}'",
                        })
                        print(f"[!!] Open Redirect found at {test_url}")
                except requests.RequestException:
                    pass

    return findings
