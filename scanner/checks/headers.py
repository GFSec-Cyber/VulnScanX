SECURITY_HEADERS = {
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Content-Security-Policy": "Restricts resource loading",
    "Strict-Transport-Security": "Forces HTTPS (HSTS)",
    "Referrer-Policy": "Controls referrer info",
    "Permissions-Policy": "Controls browser feature access",
}

def check_headers(pages, session):
    findings = []
    missing_tracker = {}  # header -> list of urls missing it

    for page in pages:
        response = page["response"]
        for header, description in SECURITY_HEADERS.items():
            if header not in response.headers:
                if header not in missing_tracker:
                    missing_tracker[header] = {"description": description, "urls": []}
                missing_tracker[header]["urls"].append(page["url"])

    for header, data in missing_tracker.items():
        url_count = len(data["urls"])
        findings.append({
            "type": "Missing Security Header",
            "severity": "Low",
            "url": f"{url_count} pages affected",
            "detail": f"{header} — {data['description']}",
        })

    return findings
