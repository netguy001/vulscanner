"""
Authentication Scanner Module
Tests authentication mechanisms, JWT tokens, sessions, and auth bypasses
"""

import requests
import base64
import json
import hmac
import hashlib
from datetime import datetime
from urllib.parse import urljoin


class AuthenticationScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.vulnerabilities = []

    def run_all_checks(self):
        """Execute all authentication security checks"""
        print("[+] Starting authentication security scan...")

        self.check_jwt_tokens()
        self.check_session_management()
        self.check_cookie_security_advanced()
        self.check_weak_credentials()
        self.check_authentication_bypass()
        self.check_password_reset_flaws()

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
            return response
        except Exception as e:
            return None

    def check_jwt_tokens(self):
        """Analyze JWT token security"""
        print("[*] Checking JWT token security...")

        # Try to find JWT tokens in cookies or response
        response = self.safe_request("GET", self.target_url)

        if not response:
            return

        # Check cookies for JWT
        cookies = response.cookies
        headers = response.headers

        jwt_found = False
        jwt_token = None
        jwt_location = None

        # Look for JWT in cookies
        for cookie_name, cookie_value in cookies.items():
            if self._is_jwt(cookie_value):
                jwt_found = True
                jwt_token = cookie_value
                jwt_location = f"Cookie: {cookie_name}"
                break

        # Look for JWT in Authorization header (for APIs)
        if "Authorization" in headers and "Bearer" in headers["Authorization"]:
            token = headers["Authorization"].replace("Bearer ", "").strip()
            if self._is_jwt(token):
                jwt_found = True
                jwt_token = token
                jwt_location = "Authorization Header"

        if jwt_found and jwt_token:
            self._analyze_jwt(jwt_token, jwt_location)

    def _is_jwt(self, token):
        """Check if string is a JWT token"""
        parts = token.split(".")
        return len(parts) == 3

    def _analyze_jwt(self, token, location):
        """Analyze JWT token for vulnerabilities"""
        try:
            parts = token.split(".")

            # Decode header
            header = self._jwt_decode(parts[0])
            payload = self._jwt_decode(parts[1])

            if header:
                # Check algorithm
                alg = header.get("alg", "").upper()

                if alg == "NONE":
                    evidence = {
                        "token_preview": token[:50] + "...",
                        "location": location,
                        "decoded_header": json.dumps(header, indent=2),
                        "decoded_payload": (
                            json.dumps(payload, indent=2) if payload else "N/A"
                        ),
                        "algorithm": alg,
                    }

                    self.add_vulnerability(
                        title="JWT Using 'none' Algorithm",
                        description="JWT token uses 'none' algorithm which accepts unsigned tokens.",
                        severity="Critical",
                        remediation="Never accept 'none' algorithm. Use strong algorithms like RS256 or HS256.",
                        category="Authentication",
                        affected_url=self.target_url,
                        evidence=evidence,
                    )

                if alg == "HS256":
                    evidence = {
                        "token_preview": token[:50] + "...",
                        "location": location,
                        "decoded_header": json.dumps(header, indent=2),
                        "algorithm": alg,
                        "warning": "Symmetric algorithm - secret strength is critical",
                    }

                    self.add_vulnerability(
                        title="JWT Using Symmetric Algorithm",
                        description="JWT uses HS256 (symmetric). If secret is weak, token can be forged.",
                        severity="Medium",
                        remediation="Use asymmetric algorithms (RS256) for better security or ensure strong secrets.",
                        category="Authentication",
                        affected_url=self.target_url,
                        evidence=evidence,
                    )

                # Test for algorithm confusion attack
                self._test_jwt_algorithm_confusion(token, header, payload, location)

            if payload:
                # Check for sensitive data in payload
                sensitive_keys = ["password", "secret", "api_key", "ssn", "credit_card"]
                found_sensitive = [key for key in sensitive_keys if key in payload]

                if found_sensitive:
                    evidence = {
                        "token_preview": token[:50] + "...",
                        "location": location,
                        "decoded_payload": json.dumps(payload, indent=2),
                        "sensitive_fields_found": found_sensitive,
                        "warning": "JWT payloads are only base64 encoded, not encrypted",
                    }

                    self.add_vulnerability(
                        title="Sensitive Data in JWT Payload",
                        description=f"JWT contains sensitive fields: {', '.join(found_sensitive)}. JWT payloads are base64 encoded, not encrypted.",
                        severity="High",
                        remediation="Never store sensitive data in JWT payload. Use encrypted tokens or server-side sessions.",
                        category="Authentication",
                        affected_url=self.target_url,
                        evidence=evidence,
                    )

                # Check for expiration
                if "exp" not in payload:
                    evidence = {
                        "token_preview": token[:50] + "...",
                        "location": location,
                        "decoded_payload": json.dumps(payload, indent=2),
                        "missing_claim": "exp (expiration time)",
                        "issue": "Token never expires",
                    }

                    self.add_vulnerability(
                        title="JWT Missing Expiration Claim",
                        description="JWT token does not have an expiration time (exp claim).",
                        severity="Medium",
                        remediation="Always set expiration time (exp) for JWT tokens. Recommended: 15-60 minutes.",
                        category="Authentication",
                        affected_url=self.target_url,
                        evidence=evidence,
                    )

        except Exception as e:
            print(f"[-] Error analyzing JWT: {str(e)}")

    def _jwt_decode(self, encoded):
        """Decode JWT part (base64)"""
        try:
            # Add padding if needed
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += "=" * padding

            decoded = base64.urlsafe_b64decode(encoded)
            return json.loads(decoded)
        except:
            return None

    def _test_jwt_algorithm_confusion(self, token, header, payload, location):
        """Test for JWT algorithm confusion vulnerability"""
        try:
            # Try to change algorithm to 'none'
            modified_header = header.copy()
            modified_header["alg"] = "none"

            # Encode modified token
            new_header = (
                base64.urlsafe_b64encode(json.dumps(modified_header).encode())
                .decode()
                .rstrip("=")
            )

            new_payload = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )

            # Create token with no signature
            modified_token = f"{new_header}.{new_payload}."

            # Test the modified token
            response = self.safe_request(
                "GET",
                self.target_url,
                headers={"Authorization": f"Bearer {modified_token}"},
            )

            if response and response.status_code == 200:
                evidence = {
                    "original_token": token[:50] + "...",
                    "original_algorithm": header.get("alg"),
                    "modified_token": modified_token[:50] + "...",
                    "modified_algorithm": "none",
                    "test_result": "Server accepted token with 'none' algorithm",
                    "response_status": response.status_code,
                    "original_header": json.dumps(header, indent=2),
                    "modified_header": json.dumps(modified_header, indent=2),
                }

                self.add_vulnerability(
                    title="JWT Algorithm Confusion Vulnerability",
                    description="Server accepts JWT tokens with 'none' algorithm, allowing signature bypass.",
                    severity="Critical",
                    remediation="Strictly validate JWT algorithm. Reject 'none' algorithm tokens.",
                    category="Authentication",
                    affected_url=self.target_url,
                    evidence=evidence,
                )

        except Exception as e:
            pass

    def check_session_management(self):
        """Check session management security"""
        print("[*] Checking session management...")

        response = self.safe_request("GET", self.target_url)

        if not response:
            return

        cookies = response.cookies

        for cookie_name, cookie_value in cookies.items():
            # Check session token length/entropy
            if "session" in cookie_name.lower() or "sess" in cookie_name.lower():
                if len(cookie_value) < 16:
                    evidence = {
                        "cookie_name": cookie_name,
                        "cookie_value": cookie_value,
                        "token_length": len(cookie_value),
                        "minimum_recommended": 16,
                        "issue": "Token too short - susceptible to brute force",
                    }

                    self.add_vulnerability(
                        title="Weak Session Token",
                        description=f"Session token '{cookie_name}' is too short ({len(cookie_value)} chars). Susceptible to brute force.",
                        severity="High",
                        remediation="Use cryptographically strong session IDs with minimum 128 bits of entropy.",
                        category="Session Management",
                        affected_url=self.target_url,
                        evidence=evidence,
                    )

                # Check if token is predictable (sequential, timestamp-based)
                if cookie_value.isdigit():
                    evidence = {
                        "cookie_name": cookie_name,
                        "cookie_value": cookie_value,
                        "pattern": "Sequential/Numeric",
                        "issue": "Predictable session token - can be guessed",
                    }

                    self.add_vulnerability(
                        title="Predictable Session Token",
                        description=f"Session token '{cookie_name}' appears to be sequential/numeric.",
                        severity="High",
                        remediation="Use cryptographically random session IDs. Avoid sequential or timestamp-based tokens.",
                        category="Session Management",
                        affected_url=self.target_url,
                        evidence=evidence,
                    )

    def check_cookie_security_advanced(self):
        """Advanced cookie security checks"""
        print("[*] Performing advanced cookie security analysis...")

        response = self.safe_request("GET", self.target_url)

        if not response:
            return

        # Check Set-Cookie headers
        set_cookie_headers = response.headers.get("Set-Cookie", "")

        if set_cookie_headers:
            # Analyze cookie attributes
            cookies_info = []

            for cookie_name, cookie_value in response.cookies.items():
                cookie_data = {
                    "name": cookie_name,
                    "value": (
                        cookie_value[:50] + "..."
                        if len(cookie_value) > 50
                        else cookie_value
                    ),
                    "has_secure": "Secure"
                    in str(response.headers.get("Set-Cookie", "")),
                    "has_httponly": "HttpOnly"
                    in str(response.headers.get("Set-Cookie", "")),
                    "has_samesite": "SameSite"
                    in str(response.headers.get("Set-Cookie", "")),
                }
                cookies_info.append(cookie_data)

            # Check for session fixation vulnerability
            # Try to set custom session ID
            custom_session = "CUSTOM_SESSION_12345"
            custom_cookies = {"PHPSESSID": custom_session, "session": custom_session}

            response2 = self.safe_request(
                "GET", self.target_url, cookies=custom_cookies
            )

            if response2:
                returned_cookies = response2.cookies

                for cookie_name, cookie_value in returned_cookies.items():
                    if cookie_value == custom_session:
                        evidence = {
                            "test_method": "Session Fixation Test",
                            "injected_session_id": custom_session,
                            "returned_cookie_name": cookie_name,
                            "returned_cookie_value": cookie_value,
                            "result": "Server accepted externally provided session ID",
                            "vulnerability": "Session Fixation possible",
                        }

                        self.add_vulnerability(
                            title="Potential Session Fixation Vulnerability",
                            description="Application accepts externally provided session IDs without regeneration.",
                            severity="High",
                            remediation="Regenerate session ID after authentication. Never accept user-supplied session IDs.",
                            category="Session Management",
                            affected_url=self.target_url,
                            evidence=evidence,
                        )
                        break

    def check_weak_credentials(self):
        """Check for default/weak credentials disclosure"""
        print("[*] Checking for weak credential patterns...")

        # Check common paths that might expose credentials
        credential_paths = [
            "/.git/config",
            "/.env",
            "/config.php.bak",
            "/database.yml",
            "/credentials.json",
            "/api_keys.txt",
        ]

        for path in credential_paths:
            url = urljoin(self.target_url, path)
            response = self.safe_request("GET", url)

            if response and response.status_code == 200:
                content = response.text.lower()

                # Check for credential patterns
                credential_keywords = [
                    "password",
                    "api_key",
                    "secret",
                    "token",
                    "apikey",
                ]

                if any(keyword in content for keyword in credential_keywords):
                    evidence = {
                        "exposed_file": path,
                        "full_url": url,
                        "status_code": response.status_code,
                        "file_preview": response.text[:300] + "...",
                        "keywords_found": [
                            kw for kw in credential_keywords if kw in content
                        ],
                    }

                    self.add_vulnerability(
                        title="Exposed Credential File",
                        description=f"Sensitive configuration file exposed at: {path}",
                        severity="Critical",
                        remediation="Remove configuration files from web root. Use environment variables for secrets.",
                        category="Authentication",
                        affected_url=url,
                        evidence=evidence,
                    )
                    break

    def check_authentication_bypass(self):
        """Test for authentication bypass techniques"""
        print("[*] Testing authentication bypass methods...")

        # Test SQL injection in login
        bypass_payloads = ["admin' OR '1'='1", "admin' --", "' OR '1'='1' --"]

        # Look for login endpoints
        login_endpoints = ["/login", "/admin/login", "/signin", "/api/login"]

        for endpoint in login_endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self.safe_request("GET", url)

            if response and response.status_code == 200:
                # Found a login page
                for payload in bypass_payloads:
                    test_data = {"username": payload, "password": payload}

                    bypass_response = self.safe_request("POST", url, data=test_data)

                    if bypass_response:
                        # Check if redirected to dashboard or got session cookie
                        if (
                            bypass_response.status_code in [302, 303]
                            or "dashboard" in bypass_response.text.lower()
                        ):
                            evidence = {
                                "endpoint": endpoint,
                                "full_url": url,
                                "payload_username": payload,
                                "payload_password": payload,
                                "response_status": bypass_response.status_code,
                                "response_headers": dict(bypass_response.headers),
                                "response_preview": bypass_response.text[:500],
                                "cookies_received": dict(bypass_response.cookies),
                                "bypass_successful": True,
                            }

                            self.add_vulnerability(
                                title="Authentication Bypass via SQL Injection",
                                description=f"Login form at {endpoint} vulnerable to SQL injection authentication bypass.",
                                severity="Critical",
                                remediation="Use parameterized queries. Implement proper input validation. Use prepared statements.",
                                category="Authentication",
                                affected_url=url,
                                evidence=evidence,
                            )
                            return

    def check_password_reset_flaws(self):
        """Check password reset functionality for flaws"""
        print("[*] Checking password reset security...")

        reset_endpoints = ["/forgot-password", "/reset-password", "/password/reset"]

        for endpoint in reset_endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self.safe_request("GET", url)

            if response and response.status_code == 200:
                # Found password reset page
                self.add_vulnerability(
                    title="Password Reset Functionality Found",
                    description=f"Password reset endpoint found at {endpoint}. Ensure proper security measures are implemented.",
                    severity="Info",
                    remediation="Implement: token expiration, rate limiting, account enumeration protection, and email verification.",
                    category="Authentication",
                    affected_url=url,
                )

                # Test for user enumeration
                test_emails = ["nonexistent@example.com", "admin@example.com"]
                responses = []

                for email in test_emails:
                    test_response = self.safe_request(
                        "POST", url, data={"email": email}
                    )
                    if test_response:
                        responses.append(
                            (email, test_response.text, test_response.status_code)
                        )

                # Compare responses
                if len(responses) == 2:
                    if (
                        responses[0][1] != responses[1][1]
                        or responses[0][2] != responses[1][2]
                    ):
                        evidence = {
                            "endpoint": endpoint,
                            "full_url": url,
                            "test_email_1": responses[0][0],
                            "response_1_status": responses[0][2],
                            "response_1_length": len(responses[0][1]),
                            "test_email_2": responses[1][0],
                            "response_2_status": responses[1][2],
                            "response_2_length": len(responses[1][1]),
                            "difference": "Responses differ - indicates user enumeration",
                        }

                        self.add_vulnerability(
                            title="User Enumeration in Password Reset",
                            description="Password reset form reveals whether email exists (different responses for valid/invalid emails).",
                            severity="Medium",
                            remediation="Return same generic message for both valid and invalid emails.",
                            category="Authentication",
                            affected_url=url,
                            evidence=evidence,
                        )

                break
