"""
Passive Vulnerability Scanner Module
Performs read-only security checks without active probing
"""

from datetime import datetime
import re


class PassiveVulnScanner:
    def __init__(self, recon_results):
        self.recon_results = recon_results
        self.vulnerabilities = []

    def run_all_checks(self):
        """Execute all passive vulnerability checks"""
        self.check_security_headers()
        self.check_cookie_security()
        self.check_tls_configuration()
        self.check_information_disclosure()
        self.check_http_methods()

        return {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
        }

    def add_vulnerability(self, title, description, severity, remediation, category):
        """Add a vulnerability finding"""
        severity_scores = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Info": 0}

        vuln = {
            "title": title,
            "description": description,
            "severity": severity,
            "severity_score": severity_scores.get(severity, 0),
            "remediation": remediation,
            "category": category,
        }
        self.vulnerabilities.append(vuln)

    def check_security_headers(self):
        """Check for missing or misconfigured security headers"""
        if (
            "http_headers" not in self.recon_results
            or "headers" not in self.recon_results["http_headers"]
        ):
            return

        headers = self.recon_results["http_headers"]["headers"]

        # X-Frame-Options
        if "X-Frame-Options" not in headers:
            self.add_vulnerability(
                title="Missing X-Frame-Options Header",
                description="The X-Frame-Options header is not set, making the site vulnerable to clickjacking attacks.",
                severity="Medium",
                remediation='Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header to all responses.',
                category="Security Headers",
            )

        # Content-Security-Policy
        if "Content-Security-Policy" not in headers:
            self.add_vulnerability(
                title="Missing Content-Security-Policy Header",
                description="No Content Security Policy detected. CSP helps prevent XSS and data injection attacks.",
                severity="Medium",
                remediation="Implement a Content-Security-Policy header with appropriate directives for your application.",
                category="Security Headers",
            )

        # Strict-Transport-Security
        if "Strict-Transport-Security" not in headers:
            self.add_vulnerability(
                title="Missing Strict-Transport-Security Header",
                description="HSTS header not found. Site may be vulnerable to protocol downgrade attacks.",
                severity="Medium",
                remediation='Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header.',
                category="Security Headers",
            )

        # X-Content-Type-Options
        if "X-Content-Type-Options" not in headers:
            self.add_vulnerability(
                title="Missing X-Content-Type-Options Header",
                description="Missing header allows MIME-sniffing which could lead to security vulnerabilities.",
                severity="Low",
                remediation='Add "X-Content-Type-Options: nosniff" header to all responses.',
                category="Security Headers",
            )

        # Referrer-Policy
        if "Referrer-Policy" not in headers:
            self.add_vulnerability(
                title="Missing Referrer-Policy Header",
                description="No Referrer-Policy set. Sensitive information in URLs may leak to third parties.",
                severity="Low",
                remediation='Add "Referrer-Policy: strict-origin-when-cross-origin" or stricter policy.',
                category="Security Headers",
            )

        # Permissions-Policy (formerly Feature-Policy)
        if "Permissions-Policy" not in headers and "Feature-Policy" not in headers:
            self.add_vulnerability(
                title="Missing Permissions-Policy Header",
                description="No Permissions-Policy header found. Browser features not explicitly controlled.",
                severity="Info",
                remediation="Add Permissions-Policy header to control browser features like geolocation, camera, etc.",
                category="Security Headers",
            )

        # X-XSS-Protection (legacy but still useful)
        if "X-XSS-Protection" not in headers:
            self.add_vulnerability(
                title="Missing X-XSS-Protection Header",
                description="Legacy XSS protection header not set (still used by older browsers).",
                severity="Info",
                remediation='Add "X-XSS-Protection: 1; mode=block" header.',
                category="Security Headers",
            )

    def check_cookie_security(self):
        """Analyze cookie security attributes"""
        if (
            "http_headers" not in self.recon_results
            or "headers" not in self.recon_results["http_headers"]
        ):
            return

        headers = self.recon_results["http_headers"]["headers"]

        if "Set-Cookie" in headers:
            cookie = headers["Set-Cookie"]

            # Check Secure flag
            if "Secure" not in cookie:
                self.add_vulnerability(
                    title="Cookie Missing Secure Flag",
                    description="Cookies are set without the Secure flag, allowing transmission over unencrypted connections.",
                    severity="Medium",
                    remediation='Add "Secure" flag to all cookies: Set-Cookie: name=value; Secure',
                    category="Cookie Security",
                )

            # Check HttpOnly flag
            if "HttpOnly" not in cookie:
                self.add_vulnerability(
                    title="Cookie Missing HttpOnly Flag",
                    description="Cookies accessible via JavaScript, increasing XSS attack risk.",
                    severity="Medium",
                    remediation='Add "HttpOnly" flag to all cookies: Set-Cookie: name=value; HttpOnly',
                    category="Cookie Security",
                )

            # Check SameSite attribute
            if "SameSite" not in cookie:
                self.add_vulnerability(
                    title="Cookie Missing SameSite Attribute",
                    description="Cookies lack SameSite attribute, vulnerable to CSRF attacks.",
                    severity="Medium",
                    remediation='Add "SameSite=Strict" or "SameSite=Lax" to cookies.',
                    category="Cookie Security",
                )

    def check_tls_configuration(self):
        """Check TLS/SSL configuration weaknesses"""
        if "tls_info" not in self.recon_results:
            return

        tls_info = self.recon_results["tls_info"]

        if "error" in tls_info:
            if tls_info["error"] == "Not an HTTPS site":
                self.add_vulnerability(
                    title="Site Not Using HTTPS",
                    description="Website is served over HTTP without encryption.",
                    severity="High",
                    remediation="Implement HTTPS with a valid SSL/TLS certificate. Use Let's Encrypt for free certificates.",
                    category="TLS/SSL",
                )
            return

        # Check TLS version
        if "tls_version" in tls_info:
            version = tls_info["tls_version"]
            if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                self.add_vulnerability(
                    title=f"Outdated TLS Version: {version}",
                    description=f"Server supports outdated {version} protocol with known vulnerabilities.",
                    severity="High",
                    remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Use TLS 1.2 or TLS 1.3 only.",
                    category="TLS/SSL",
                )

        # Check cipher suite
        if "cipher" in tls_info:
            cipher_info = tls_info["cipher"]
            if cipher_info:
                cipher_name = (
                    cipher_info[0]
                    if isinstance(cipher_info, tuple)
                    else str(cipher_info)
                )

                # Check for weak ciphers
                weak_patterns = ["DES", "RC4", "MD5", "NULL", "EXPORT", "anon"]
                if any(weak in cipher_name.upper() for weak in weak_patterns):
                    self.add_vulnerability(
                        title="Weak Cipher Suite Detected",
                        description=f"Server uses weak cipher: {cipher_name}",
                        severity="High",
                        remediation="Configure server to use strong cipher suites only (AES-GCM, ChaCha20).",
                        category="TLS/SSL",
                    )

        # Check certificate validity
        if "certificate" in tls_info:
            cert = tls_info["certificate"]

            # Certificate expiration check would require date parsing
            # This is a simplified check
            if "not_after" in cert:
                self.add_vulnerability(
                    title="Certificate Expiration Check",
                    description=f'Certificate expires on: {cert["not_after"]}',
                    severity="Info",
                    remediation="Monitor certificate expiration and renew before expiry.",
                    category="TLS/SSL",
                )

    def check_information_disclosure(self):
        """Check for information disclosure in headers"""
        if (
            "http_headers" not in self.recon_results
            or "headers" not in self.recon_results["http_headers"]
        ):
            return

        headers = self.recon_results["http_headers"]["headers"]

        # Server version disclosure
        if "Server" in headers:
            server = headers["Server"]
            if re.search(r"\d+\.\d+", server):  # Contains version numbers
                self.add_vulnerability(
                    title="Server Version Disclosure",
                    description=f"Server header reveals version information: {server}",
                    severity="Low",
                    remediation="Configure server to hide version information in Server header.",
                    category="Information Disclosure",
                )

        # X-Powered-By disclosure
        if "X-Powered-By" in headers:
            self.add_vulnerability(
                title="Technology Stack Disclosure",
                description=f'X-Powered-By header reveals: {headers["X-Powered-By"]}',
                severity="Low",
                remediation="Remove or obscure X-Powered-By header to prevent technology fingerprinting.",
                category="Information Disclosure",
            )

        # X-AspNet-Version
        if "X-AspNet-Version" in headers:
            self.add_vulnerability(
                title="ASP.NET Version Disclosure",
                description=f'X-AspNet-Version header reveals: {headers["X-AspNet-Version"]}',
                severity="Low",
                remediation="Disable ASP.NET version header in web.config.",
                category="Information Disclosure",
            )

    def check_http_methods(self):
        """Check for potentially dangerous HTTP methods"""
        if (
            "http_headers" not in self.recon_results
            or "headers" not in self.recon_results["http_headers"]
        ):
            return

        headers = self.recon_results["http_headers"]["headers"]

        # Check Allow header
        if "Allow" in headers:
            allowed_methods = headers["Allow"].upper()
            dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]

            found_dangerous = [m for m in dangerous_methods if m in allowed_methods]

            if found_dangerous:
                self.add_vulnerability(
                    title="Dangerous HTTP Methods Enabled",
                    description=f'Potentially dangerous HTTP methods are allowed: {", ".join(found_dangerous)}',
                    severity="Medium",
                    remediation="Disable unnecessary HTTP methods. Only allow GET, POST, HEAD unless specifically required.",
                    category="HTTP Configuration",
                )
