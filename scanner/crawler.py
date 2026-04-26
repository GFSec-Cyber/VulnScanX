import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

SKIP_URLS = ["logout", "security.php", "setup.php"]

class Crawler:
    def __init__(self, base_url, session=None):
        self.base_url = base_url
        self.visited = set()
        self.session = session or requests.Session()
        self.pages = []

    def crawl(self, url=None, depth=2):
        if url is None:
            url = self.base_url
        if depth == 0 or url in self.visited:
            return
        self.visited.add(url)

        try:
            response = self.session.get(url, timeout=5)
        except requests.RequestException as e:
            print(f"[!] Could not reach {url}: {e}")
            return

        soup = BeautifulSoup(response.text, "html.parser")
        forms = self._extract_forms(soup, url)
        links = self._extract_links(soup, url)

        self.pages.append({
            "url": url,
            "forms": forms,
            "links": links,
            "response": response,
        })

        print(f"[+] Crawled: {url}  ({len(forms)} forms, {len(links)} links)")

        for link in links:
            self.crawl(link, depth - 1)

    def _extract_forms(self, soup, base_url):
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            action_url = urljoin(base_url, action)
            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": tag.get("name", ""),
                    "type": tag.get("type", "text"),
                    "value": tag.get("value", ""),
                })
            forms.append({
                "action": action_url,
                "method": method,
                "inputs": inputs,
            })
        return forms

    def _extract_links(self, soup, base_url):
        links = []
        base_domain = urlparse(self.base_url).netloc
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if any(skip in href.lower() for skip in SKIP_URLS):
                continue
            if href.startswith("#") or href.startswith("javascript"):
                continue
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc == base_domain and full_url not in self.visited:
                links.append(full_url)
        return links
