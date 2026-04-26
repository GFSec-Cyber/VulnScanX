import requests

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
]

def check_xss(pages, session):
    findings = []

    for page in pages:
        for form in page["forms"]:
            # Skip forms with no useful inputs
            named_inputs = [i for i in form["inputs"] if i["name"] and i["type"] not in ("submit", "hidden", "button")]
            if not named_inputs:
                continue

            for payload in XSS_PAYLOADS:
                # Build data: use existing values for non-text fields, inject payload into text fields
                data = {}
                for inp in form["inputs"]:
                    if not inp["name"]:
                        continue
                    if inp["type"] in ("submit", "button"):
                        data[inp["name"]] = inp["value"] or "Submit"
                    elif inp["type"] == "hidden":
                        data[inp["name"]] = inp["value"]
                    else:
                        data[inp["name"]] = payload

                try:
                    if form["method"] == "post":
                        resp = session.post(form["action"], data=data, timeout=5)
                    else:
                        resp = session.get(form["action"], params=data, timeout=5)

                    if payload in resp.text:
                        findings.append({
                            "type": "XSS",
                            "severity": "High",
                            "url": form["action"],
                            "detail": f"Payload reflected in response: {payload[:80]}",
                        })
                        print(f"[!!] XSS found at {form['action']}")
                        break

                except requests.RequestException:
                    pass

    return findings
