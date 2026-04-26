import requests

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "1' OR '1'='1",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sql syntax",
    "mysql_fetch",
    "mariadb",
]

SUCCESS_SIGNATURES = [
    "first name",
    "surname",
]

def check_sqli(pages, session):
    findings = []
    checked_urls = set()

    for page in pages:
        for form in page["forms"]:
            if form["action"] in checked_urls:
                continue

            named_inputs = [i for i in form["inputs"] if i["name"] and i["type"] not in ("submit", "hidden", "button")]
            if not named_inputs:
                continue

            for payload in SQLI_PAYLOADS:
                data = {}
                for inp in form["inputs"]:
                    if not inp["name"]:
                        continue
                    if inp["type"] == "hidden":
                        data[inp["name"]] = inp["value"]
                    elif inp["type"] in ("submit", "button"):
                        data[inp["name"]] = inp["value"] or "Submit"
                    else:
                        data[inp["name"]] = payload

                try:
                    if form["method"] == "post":
                        resp = session.post(form["action"], data=data, timeout=5)
                    else:
                        resp = session.get(form["action"], params=data, timeout=5)

                    body_lower = resp.text.lower()

                    for sig in ERROR_SIGNATURES:
                        if sig in body_lower:
                            findings.append({
                                "type": "SQL Injection",
                                "severity": "Critical",
                                "url": form["action"],
                                "detail": f"DB error triggered with payload: {payload}",
                            })
                            print(f"[!!] SQLi found at {form['action']}")
                            checked_urls.add(form["action"])
                            break

                    if form["action"] not in checked_urls:
                        for sig in SUCCESS_SIGNATURES:
                            if sig in body_lower:
                                findings.append({
                                    "type": "SQL Injection",
                                    "severity": "Critical",
                                    "url": form["action"],
                                    "detail": f"DB data returned with payload: {payload}",
                                })
                                print(f"[!!] SQLi found at {form['action']}")
                                checked_urls.add(form["action"])
                                break

                except requests.RequestException:
                    pass

    return findings
