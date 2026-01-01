"""
Web Crawler Module
Automatically discovers URLs, forms, parameters, and endpoints
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
from datetime import datetime


class WebCrawler:
    def __init__(self, target_url, max_depth=3, timeout=10):
        self.target_url = target_url
        self.max_depth = max_depth
        self.timeout = timeout
        self.parsed_url = urlparse(target_url)
        self.base_domain = self.parsed_url.netloc

        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.parameters = set()
        self.endpoints = set()
        self.js_files = []
        self.api_endpoints = []

    def run_crawl(self):
        """Execute the complete crawling process"""
        print(f"[+] Starting crawl of {self.target_url}")
        self._crawl(self.target_url, 0)

        return {
            "timestamp": datetime.now().isoformat(),
            "target": self.target_url,
            "total_urls": len(self.discovered_urls),
            "total_forms": len(self.forms),
            "total_parameters": len(self.parameters),
            "total_endpoints": len(self.endpoints),
            "discovered_urls": list(self.discovered_urls)[:50],
            "forms": self.forms,
            "parameters": list(self.parameters),
            "endpoints": list(self.endpoints)[:30],
            "js_files": self.js_files[:20],
            "api_endpoints": self.api_endpoints[:20],
        }

    def _crawl(self, url, depth):
        """Recursive crawling function"""
        if depth > self.max_depth or url in self.visited_urls:
            return

        # Check if URL belongs to target domain
        parsed = urlparse(url)
        if parsed.netloc != self.base_domain:
            return

        self.visited_urls.add(url)
        print(f"[*] Crawling: {url} (depth: {depth})")

        try:
            response = requests.get(
                url, timeout=self.timeout, verify=False, allow_redirects=True
            )

            if response.status_code != 200:
                return

            content_type = response.headers.get("Content-Type", "")

            # Only parse HTML content
            if "text/html" not in content_type:
                return

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract links
            self._extract_links(soup, url, depth)

            # Extract forms
            self._extract_forms(soup, url)

            # Extract parameters from current URL
            self._extract_parameters(url)

            # Extract JavaScript files
            self._extract_js_files(soup, url)

            # Extract API endpoints from JS and page content
            self._extract_api_endpoints(response.text, url)

        except Exception as e:
            print(f"[-] Error crawling {url}: {str(e)}")

    def _extract_links(self, soup, current_url, depth):
        """Extract all links from the page"""
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href")
            if not href:
                continue

            # Convert relative URLs to absolute
            full_url = urljoin(current_url, href)

            # Clean URL (remove fragments)
            full_url = full_url.split("#")[0]

            parsed = urlparse(full_url)

            # Only crawl same domain
            if parsed.netloc == self.base_domain:
                self.discovered_urls.add(full_url)
                self.endpoints.add(parsed.path)

                # Recursively crawl
                if full_url not in self.visited_urls:
                    self._crawl(full_url, depth + 1)

    def _extract_forms(self, soup, current_url):
        """Extract all forms and their details"""
        for form in soup.find_all("form"):
            form_details = {
                "url": current_url,
                "action": urljoin(current_url, form.get("action", "")),
                "method": form.get("method", "get").upper(),
                "inputs": [],
            }

            # Extract all input fields
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_details = {
                    "type": input_tag.get("type", "text"),
                    "name": input_tag.get("name", ""),
                    "value": input_tag.get("value", ""),
                    "placeholder": input_tag.get("placeholder", ""),
                }

                if input_details["name"]:
                    form_details["inputs"].append(input_details)
                    self.parameters.add(input_details["name"])

            if form_details["inputs"]:
                self.forms.append(form_details)

    def _extract_parameters(self, url):
        """Extract parameters from URL query string"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in params.keys():
            self.parameters.add(param_name)

    def _extract_js_files(self, soup, current_url):
        """Extract JavaScript file URLs"""
        for script in soup.find_all("script", src=True):
            js_url = urljoin(current_url, script["src"])

            if js_url not in self.js_files:
                self.js_files.append(js_url)

    def _extract_api_endpoints(self, content, current_url):
        """Extract potential API endpoints from content"""
        # Common API patterns
        api_patterns = [
            r"/api/[a-zA-Z0-9/_-]+",
            r"/v\d+/[a-zA-Z0-9/_-]+",
            r"/rest/[a-zA-Z0-9/_-]+",
            r"/graphql",
            r"/webhook/[a-zA-Z0-9/_-]+",
            r'"/[a-zA-Z0-9/_-]+\.json"',
            r'"/[a-zA-Z0-9/_-]+\.xml"',
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Clean quotes
                endpoint = match.strip('"')
                full_endpoint = urljoin(current_url, endpoint)

                if full_endpoint not in self.api_endpoints:
                    self.api_endpoints.append(full_endpoint)

    def get_attack_surface(self):
        """Return complete attack surface summary"""
        return {
            "total_urls": len(self.discovered_urls),
            "total_forms": len(self.forms),
            "total_parameters": len(self.parameters),
            "total_endpoints": len(self.endpoints),
            "forms_by_method": self._count_forms_by_method(),
            "input_types": self._count_input_types(),
            "potential_apis": len(self.api_endpoints),
        }

    def _count_forms_by_method(self):
        """Count forms by HTTP method"""
        methods = {}
        for form in self.forms:
            method = form["method"]
            methods[method] = methods.get(method, 0) + 1
        return methods

    def _count_input_types(self):
        """Count different input types"""
        types = {}
        for form in self.forms:
            for input_field in form["inputs"]:
                input_type = input_field["type"]
                types[input_type] = types.get(input_type, 0) + 1
        return types
