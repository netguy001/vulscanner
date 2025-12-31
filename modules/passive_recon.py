"""
Passive Reconnaissance Module
Performs safe, non-intrusive information gathering
"""

import socket
import ssl
import requests
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver


class PassiveRecon:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.results = {}

    def run_all_checks(self):
        """Execute all passive reconnaissance checks"""
        self.results["timestamp"] = datetime.now().isoformat()
        self.results["target"] = self.target_url

        self.results["dns_info"] = self.get_dns_info()
        self.results["ip_info"] = self.get_ip_info()
        self.results["http_headers"] = self.get_http_headers()
        self.results["tls_info"] = self.get_tls_info()
        self.results["tech_stack"] = self.detect_technology()
        self.results["robots_sitemap"] = self.check_robots_sitemap()

        return self.results

    def get_dns_info(self):
        """Retrieve DNS records"""
        dns_data = {}
        try:
            # A Record
            a_records = dns.resolver.resolve(self.domain, "A")
            dns_data["a_records"] = [str(r) for r in a_records]
        except:
            dns_data["a_records"] = []

        try:
            # MX Record
            mx_records = dns.resolver.resolve(self.domain, "MX")
            dns_data["mx_records"] = [str(r) for r in mx_records]
        except:
            dns_data["mx_records"] = []

        try:
            # NS Record
            ns_records = dns.resolver.resolve(self.domain, "NS")
            dns_data["ns_records"] = [str(r) for r in ns_records]
        except:
            dns_data["ns_records"] = []

        return dns_data

    def get_ip_info(self):
        """Get IP address information"""
        try:
            ip_address = socket.gethostbyname(self.domain)
            return {"ip_address": ip_address, "hostname": self.domain}
        except Exception as e:
            return {"error": str(e)}

    def get_http_headers(self):
        """Fetch HTTP response headers"""
        headers_data = {}
        try:
            response = requests.get(
                self.target_url, timeout=self.timeout, allow_redirects=True, verify=True
            )
            headers_data["status_code"] = response.status_code
            headers_data["headers"] = dict(response.headers)
            headers_data["redirects"] = len(response.history)

            if response.history:
                headers_data["redirect_chain"] = [r.url for r in response.history]

        except requests.exceptions.SSLError:
            headers_data["error"] = "SSL Certificate Error"
        except requests.exceptions.ConnectionError:
            headers_data["error"] = "Connection Error"
        except requests.exceptions.Timeout:
            headers_data["error"] = "Request Timeout"
        except Exception as e:
            headers_data["error"] = str(e)

        return headers_data

    def get_tls_info(self):
        """Analyze TLS/SSL configuration"""
        tls_data = {}

        if self.parsed_url.scheme != "https":
            tls_data["error"] = "Not an HTTPS site"
            return tls_data

        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (self.domain, 443), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_data["tls_version"] = ssock.version()
                    tls_data["cipher"] = ssock.cipher()

                    # Certificate details
                    tls_data["certificate"] = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "version": cert["version"],
                        "serial_number": cert["serialNumber"],
                        "not_before": cert["notBefore"],
                        "not_after": cert["notAfter"],
                    }

        except ssl.SSLError as e:
            tls_data["error"] = f"SSL Error: {str(e)}"
        except Exception as e:
            tls_data["error"] = str(e)

        return tls_data

    def detect_technology(self):
        """Detect web technologies and frameworks"""
        tech_data = {
            "server": None,
            "frameworks": [],
            "cms": None,
            "programming_language": None,
        }

        try:
            response = requests.get(self.target_url, timeout=self.timeout)
            headers = response.headers

            # Server detection
            if "Server" in headers:
                tech_data["server"] = headers["Server"]

            # X-Powered-By detection
            if "X-Powered-By" in headers:
                tech_data["programming_language"] = headers["X-Powered-By"]

            # Framework detection from headers
            framework_headers = {
                "X-AspNet-Version": "ASP.NET",
                "X-AspNetMvc-Version": "ASP.NET MVC",
                "X-Drupal-Cache": "Drupal",
                "X-Generator": headers.get("X-Generator", ""),
            }

            for header, framework in framework_headers.items():
                if header in headers:
                    tech_data["frameworks"].append(framework)

            # Content-based detection
            content = response.text.lower()

            # CMS Detection
            cms_patterns = {
                "wordpress": ["wp-content", "wp-includes"],
                "joomla": ["joomla", "com_content"],
                "drupal": ["drupal", "sites/default"],
                "magento": ["magento", "mage/cookies"],
                "shopify": ["shopify", "cdn.shopify"],
            }

            for cms, patterns in cms_patterns.items():
                if any(pattern in content for pattern in patterns):
                    tech_data["cms"] = cms.capitalize()
                    break

        except Exception as e:
            tech_data["error"] = str(e)

        return tech_data

    def check_robots_sitemap(self):
        """Check for robots.txt and sitemap.xml"""
        files_data = {}

        base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"

        # Check robots.txt
        try:
            robots_url = f"{base_url}/robots.txt"
            response = requests.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                files_data["robots_txt"] = {
                    "exists": True,
                    "size": len(response.text),
                    "url": robots_url,
                }
            else:
                files_data["robots_txt"] = {"exists": False}
        except:
            files_data["robots_txt"] = {"exists": False}

        # Check sitemap.xml
        try:
            sitemap_url = f"{base_url}/sitemap.xml"
            response = requests.get(sitemap_url, timeout=self.timeout)
            if response.status_code == 200:
                files_data["sitemap_xml"] = {
                    "exists": True,
                    "size": len(response.text),
                    "url": sitemap_url,
                }
            else:
                files_data["sitemap_xml"] = {"exists": False}
        except:
            files_data["sitemap_xml"] = {"exists": False}

        return files_data
