"""
Active Probing Module
Performs authorized active security testing
"""

import requests
from urllib.parse import urljoin, urlparse
from datetime import datetime
import time


class ActiveProbe:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.vulnerabilities = []

    def run_all_checks(self):
        """Execute all active probing checks"""
        self.check_parameter_behavior()
        self.check_error_handling()
        self.check_common_endpoints()
        self.check_cors_configuration()
        self.check_backup_files()
        self.check_http_methods()
        self.check_default_credentials()

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

    def safe_request(self, method, url, **kwargs):
        """Make a safe HTTP request with error handling"""
        try:
            kwargs["timeout"] = self.timeout
            kwargs["allow_redirects"] = False
            response = requests.request(method, url, **kwargs)
            time.sleep(0.5)  # Rate limiting
            return response
        except Exception as e:
            return None

    def check_parameter_behavior(self):
        """Test how application handles special characters in parameters"""
        test_params = [
            ("'", "SQL Injection Pattern"),
            ("<script>", "XSS Pattern"),
            ("../", "Path Traversal Pattern"),
            ("${7*7}", "Template Injection Pattern"),
        ]

        for payload, pattern_name in test_params:
            test_url = f"{self.target_url}?test={payload}"
            response = self.safe_request("GET", test_url)

            if response and response.status_code == 200:
                content = response.text.lower()

                # Check if payload is reflected
                if payload.lower() in content:
                    self.add_vulnerability(
                        title=f"Input Reflection Detected - {pattern_name}",
                        description=f'User input "{payload}" is reflected in the response without proper encoding.',
                        severity="Medium",
                        remediation="Implement proper input validation and output encoding. Use context-aware escaping.",
                        category="Input Validation",
                    )

                # Check for SQL error patterns
                if payload == "'" and any(
                    err in content
                    for err in ["sql", "mysql", "syntax", "database", "query"]
                ):
                    self.add_vulnerability(
                        title="Potential SQL Injection Vulnerability",
                        description="Application returns database error messages when special characters are used.",
                        severity="High",
                        remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
                        category="Injection",
                    )

    def check_error_handling(self):
        """Test error handling and information disclosure"""
        error_urls = [
            ("nonexistent-page-12345", "Non-existent Page"),
            ("..%2F..%2F..%2Fetc%2Fpasswd", "Path Traversal Attempt"),
            ("%00", "Null Byte"),
        ]

        for path, test_name in error_urls:
            test_url = urljoin(self.base_url, path)
            response = self.safe_request("GET", test_url)

            if response:
                content = response.text.lower()

                # Check for stack traces
                stack_trace_patterns = [
                    "traceback",
                    "stack trace",
                    "exception",
                    "at line",
                    "error in",
                    "warning:",
                    "fatal error",
                    "mysql_",
                    "postgresql",
                ]

                if any(pattern in content for pattern in stack_trace_patterns):
                    self.add_vulnerability(
                        title="Verbose Error Messages Detected",
                        description=f"Application exposes detailed error information in response to {test_name}.",
                        severity="Low",
                        remediation="Implement custom error pages. Log detailed errors server-side, show generic messages to users.",
                        category="Information Disclosure",
                    )
                    break

    def check_common_endpoints(self):
        """Check for common sensitive endpoints"""
        sensitive_paths = [
            "/admin",
            "/administrator",
            "/wp-admin",
            "/phpmyadmin",
            "/cpanel",
            "/login",
            "/admin/login",
            "/dashboard",
            "/.git/HEAD",
            "/.env",
            "/config.php",
            "/backup",
            "/phpinfo.php",
            "/test.php",
            "/debug",
            "/.DS_Store",
            "/web.config",
        ]

        found_endpoints = []

        for path in sensitive_paths:
            url = urljoin(self.base_url, path)
            response = self.safe_request("GET", url)

            if response and response.status_code in [200, 301, 302, 401, 403]:
                found_endpoints.append({"path": path, "status": response.status_code})

        if found_endpoints:
            paths_list = ", ".join(
                [f"{e['path']} ({e['status']})" for e in found_endpoints]
            )

            # Determine severity based on what was found
            severity = "Info"
            if any(e["status"] == 200 for e in found_endpoints):
                if any(
                    path in [e["path"] for e in found_endpoints]
                    for path in ["/.git/HEAD", "/.env", "/phpinfo.php"]
                ):
                    severity = "High"
                else:
                    severity = "Medium"

            self.add_vulnerability(
                title="Sensitive Endpoints Discovered",
                description=f"Found accessible sensitive paths: {paths_list}",
                severity=severity,
                remediation="Restrict access to administrative interfaces. Remove development/debug files. Use .htaccess or firewall rules.",
                category="Access Control",
            )

    def check_cors_configuration(self):
        """Test CORS configuration for misconfigurations"""
        headers = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }

        response = self.safe_request("OPTIONS", self.target_url, headers=headers)

        if response:
            cors_header = response.headers.get("Access-Control-Allow-Origin", "")

            if cors_header == "*":
                self.add_vulnerability(
                    title="CORS Wildcard Origin Allowed",
                    description="CORS policy allows requests from any origin (*).",
                    severity="Medium",
                    remediation="Restrict CORS to specific trusted domains. Avoid using wildcard (*) in production.",
                    category="CORS",
                )
            elif cors_header == "https://evil.com":
                self.add_vulnerability(
                    title="CORS Reflects Arbitrary Origins",
                    description="CORS policy reflects the requesting origin without validation.",
                    severity="High",
                    remediation="Implement whitelist of allowed origins. Validate Origin header against trusted domains.",
                    category="CORS",
                )

            # Check for credentials with wildcard
            allow_creds = response.headers.get(
                "Access-Control-Allow-Credentials", ""
            ).lower()
            if allow_creds == "true" and cors_header == "*":
                self.add_vulnerability(
                    title="CORS Credentials with Wildcard Origin",
                    description="CORS allows credentials with wildcard origin (not allowed by spec but worth checking).",
                    severity="High",
                    remediation="Never use wildcard origin with credentials. Specify exact origins.",
                    category="CORS",
                )

    def check_backup_files(self):
        """Check for common backup file patterns"""
        parsed = urlparse(self.target_url)
        path = parsed.path if parsed.path else "/index.html"

        backup_extensions = [
            ".bak",
            ".old",
            ".backup",
            ".copy",
            ".orig",
            ".save",
            ".swp",
            "~",
        ]

        found_backups = []

        for ext in backup_extensions:
            backup_url = self.target_url + ext
            response = self.safe_request("GET", backup_url)

            if response and response.status_code == 200:
                found_backups.append(backup_url)

        if found_backups:
            self.add_vulnerability(
                title="Backup Files Accessible",
                description=f'Found accessible backup files: {", ".join(found_backups)}',
                severity="Medium",
                remediation="Remove backup files from web-accessible directories. Use proper backup storage solutions.",
                category="Information Disclosure",
            )

    def check_http_methods(self):
        """Test for dangerous HTTP methods"""
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]

        allowed_methods = []

        # Test OPTIONS first
        response = self.safe_request("OPTIONS", self.target_url)
        if response and "Allow" in response.headers:
            allowed = response.headers["Allow"].upper()
            allowed_methods = [m for m in dangerous_methods if m in allowed]
        else:
            # Test each method individually
            for method in dangerous_methods:
                response = self.safe_request(method, self.target_url)
                if response and response.status_code not in [404, 405, 501]:
                    allowed_methods.append(method)

        if allowed_methods:
            self.add_vulnerability(
                title="Dangerous HTTP Methods Enabled",
                description=f'Server accepts potentially dangerous HTTP methods: {", ".join(allowed_methods)}',
                severity="Medium",
                remediation="Disable unnecessary HTTP methods at web server level. Only allow required methods.",
                category="HTTP Configuration",
            )

    def check_default_credentials(self):
        """Test for common default credentials (non-brute force)"""
        # Only test very common defaults, not brute forcing
        login_paths = ["/login", "/admin", "/wp-login.php"]

        common_defaults = [("admin", "admin"), ("admin", "password")]

        for path in login_paths:
            login_url = urljoin(self.base_url, path)
            response = self.safe_request("GET", login_url)

            if response and response.status_code == 200:
                # Just check if login page exists
                self.add_vulnerability(
                    title="Login Interface Detected",
                    description=f"Login page found at: {login_url}. Ensure strong authentication is implemented.",
                    severity="Info",
                    remediation="Implement: strong passwords, account lockout, MFA, rate limiting, and CAPTCHA.",
                    category="Authentication",
                )
                break  # Only report once
