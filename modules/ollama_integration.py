"""
Ollama Integration Module
Connects to local Ollama API for AI-powered vulnerability analysis and exploit generation
"""

import requests
import json
from typing import Dict, List, Optional, Any
import time


class OllamaClient:
    """Client for interacting with local Ollama models"""

    def __init__(
        self, base_url: str = "http://localhost:11434", model: str = "qwen2.5-coder:7b"
    ):
        self.base_url = base_url
        self.model = model
        self.timeout = 120  # 2 minutes for complex analysis

    def _make_request(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Make HTTP request to Ollama API"""
        try:
            url = f"{self.base_url}/{endpoint}"
            response = requests.post(url, json=data, timeout=self.timeout, stream=True)

            if response.status_code != 200:
                print(f"[-] Ollama API error: {response.status_code}")
                return None

            # Parse streaming response
            full_response = ""
            for line in response.iter_lines():
                if line:
                    try:
                        json_line = json.loads(line)
                        if "response" in json_line:
                            full_response += json_line["response"]
                        if json_line.get("done", False):
                            break
                    except json.JSONDecodeError:
                        continue

            return {"response": full_response}

        except requests.exceptions.RequestException as e:
            print(f"[-] Connection error to Ollama: {str(e)}")
            return None
        except Exception as e:
            print(f"[-] Unexpected error: {str(e)}")
            return None

    def generate(
        self, prompt: str, temperature: float = 0.7, system: str = None
    ) -> Optional[str]:
        """Generate text completion from Ollama model"""
        data = {
            "model": self.model,
            "prompt": prompt,
            "temperature": temperature,
            "stream": True,
        }

        if system:
            data["system"] = system

        result = self._make_request("api/generate", data)
        return result["response"] if result else None

    def chat(self, messages: List[Dict[str, str]]) -> Optional[str]:
        """Chat with Ollama model using conversation history"""
        data = {"model": self.model, "messages": messages, "stream": True}

        result = self._make_request("api/chat", data)
        return result["response"] if result else None

    def check_health(self) -> bool:
        """Check if Ollama server is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False


class VulnerabilityAnalyzer:
    """AI-powered vulnerability analysis using Ollama"""

    def __init__(self, ollama_client: OllamaClient):
        self.client = ollama_client
        self.analysis_model = "qwen2.5-coder:7b"  # Best for code/security analysis
        self.exploit_model = (
            "dolphin-unlocked:latest"  # Best for creative exploit ideas
        )

    def analyze_vulnerability(self, vuln: Dict) -> Dict[str, Any]:
        """Deep analysis of a single vulnerability"""

        prompt = f"""You are a senior penetration tester analyzing a security vulnerability.

VULNERABILITY DETAILS:
- Title: {vuln.get('title')}
- Severity: {vuln.get('severity')}
- Category: {vuln.get('category')}
- Description: {vuln.get('description')}
- Evidence: {json.dumps(vuln.get('evidence', {}), indent=2)}

TASKS:
1. Explain the technical root cause in 2-3 sentences
2. Assess real-world exploitability (1-10 scale with reasoning)
3. Estimate potential business impact (data breach, financial loss, reputation)
4. Provide 3 specific exploitation techniques an attacker would use
5. Suggest defensive detection mechanisms (WAF rules, monitoring alerts)

Respond in valid JSON format:
{{
    "root_cause": "...",
    "exploitability_score": 8,
    "exploitability_reasoning": "...",
    "business_impact": "...",
    "exploitation_techniques": ["...", "...", "..."],
    "detection_mechanisms": ["...", "...", "..."]
}}
"""

        # Switch to analysis model
        original_model = self.client.model
        self.client.model = self.analysis_model

        response = self.client.generate(
            prompt=prompt,
            temperature=0.3,  # Lower temperature for consistent analysis
            system="You are a security expert. Always respond with valid JSON only.",
        )

        # Restore original model
        self.client.model = original_model

        if not response:
            return self._fallback_analysis()

        try:
            # Extract JSON from response (LLM might add extra text)
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                analysis = json.loads(json_str)
                return analysis
            else:
                return self._fallback_analysis()
        except json.JSONDecodeError:
            print("[-] Failed to parse AI response as JSON")
            return self._fallback_analysis()

    def generate_attack_chains(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Identify multi-step attack chains from discovered vulnerabilities"""

        if len(vulnerabilities) < 2:
            return []

        # Prepare vulnerability summary
        vuln_summary = "\n".join(
            [
                f"{i+1}. {v['title']} ({v['severity']}) - {v['category']}"
                for i, v in enumerate(vulnerabilities[:10])  # Limit to top 10
            ]
        )

        prompt = f"""You are a red team operator planning an attack campaign.

DISCOVERED VULNERABILITIES:
{vuln_summary}

TASK: Identify realistic attack chains where multiple vulnerabilities can be chained together.

Example attack chain:
1. XSS (steal admin session cookie)
2. Session Hijacking (access admin panel)
3. SQL Injection in admin panel (extract database)
4. Privilege Escalation (gain system access)

Respond with valid JSON array:
[
    {{
        "chain_name": "Admin Account Takeover via XSS",
        "steps": [
            {{"vuln": "XSS", "action": "Steal session cookie"}},
            {{"vuln": "Session Hijacking", "action": "Access admin panel"}}
        ],
        "impact": "Complete admin access, data exfiltration",
        "complexity": "Medium"
    }}
]

Generate 2-3 realistic attack chains. Respond with JSON array only.
"""

        # Switch to exploit model for creative thinking
        original_model = self.client.model
        self.client.model = self.exploit_model

        response = self.client.generate(
            prompt=prompt,
            temperature=0.7,  # Higher temperature for creative chains
            system="You are an offensive security expert. Respond with valid JSON only.",
        )

        # Restore original model
        self.client.model = original_model

        if not response:
            return []

        try:
            # Extract JSON array
            json_start = response.find("[")
            json_end = response.rfind("]") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                chains = json.loads(json_str)
                return chains
            else:
                return []
        except json.JSONDecodeError:
            print("[-] Failed to parse attack chains JSON")
            return []

    def generate_executive_summary(self, scan_results: Dict) -> str:
        """Generate executive-level summary of scan results"""

        total_vulns = scan_results.get("summary", {}).get("total_vulnerabilities", 0)
        severity_dist = scan_results.get("summary", {}).get("severity_distribution", {})

        prompt = f"""You are a CISO presenting to the board of directors.

SECURITY SCAN RESULTS:
- Total Vulnerabilities: {total_vulns}
- Critical: {severity_dist.get('Critical', 0)}
- High: {severity_dist.get('High', 0)}
- Medium: {severity_dist.get('Medium', 0)}
- Low: {severity_dist.get('Low', 0)}

Write a 4-paragraph executive summary:
1. Overall security posture (1-2 sentences)
2. Top 3 critical risks and business impact
3. Immediate actions required (next 7 days)
4. Long-term recommendations (30-90 days)

Use business language, avoid technical jargon. Be direct and action-oriented.
"""

        response = self.client.generate(
            prompt=prompt,
            temperature=0.5,
            system="You are a Chief Information Security Officer. Write for business executives.",
        )

        return response if response else "Executive summary generation failed."

    def suggest_exploit_code(self, vuln: Dict) -> str:
        """Generate proof-of-concept exploit code"""

        category = vuln.get("category", "")
        title = vuln.get("title", "")
        evidence = vuln.get("evidence", {})

        prompt = f"""You are a penetration tester writing a proof-of-concept exploit.

VULNERABILITY:
- Type: {category}
- Title: {title}
- Evidence: {json.dumps(evidence, indent=2)}

Generate working Python exploit code with:
1. Clear comments explaining each step
2. Error handling
3. Output showing successful exploitation
4. Safe/educational approach (don't cause damage)

Provide only the Python code, no explanations outside code comments.
"""

        # Use exploit model
        original_model = self.client.model
        self.client.model = self.exploit_model

        response = self.client.generate(
            prompt=prompt,
            temperature=0.6,
            system="You are a security researcher. Generate ethical, educational exploit code.",
        )

        # Restore original model
        self.client.model = original_model

        return response if response else "# Exploit generation failed"

    def _fallback_analysis(self) -> Dict[str, Any]:
        """Fallback analysis when AI fails"""
        return {
            "root_cause": "Unable to generate AI analysis",
            "exploitability_score": 0,
            "exploitability_reasoning": "AI analysis unavailable",
            "business_impact": "Requires manual assessment",
            "exploitation_techniques": [],
            "detection_mechanisms": [],
        }


# Usage example and testing
if __name__ == "__main__":
    print("[+] Testing Ollama Integration...")

    # Initialize client
    client = OllamaClient()

    # Health check
    if client.check_health():
        print("[✓] Ollama server is running")
    else:
        print("[✗] Ollama server is not accessible")
        print("[!] Make sure Ollama is running: 'ollama serve'")
        exit(1)

    # Test vulnerability analysis
    print("\n[+] Testing vulnerability analysis...")
    analyzer = VulnerabilityAnalyzer(client)

    test_vuln = {
        "title": "SQL Injection in Login Form",
        "severity": "Critical",
        "category": "Injection",
        "description": "Application accepts SQL injection in username parameter",
        "evidence": {
            "payload": "admin' OR '1'='1'--",
            "matched_pattern": "SQL error: syntax error",
        },
    }

    analysis = analyzer.analyze_vulnerability(test_vuln)
    print(json.dumps(analysis, indent=2))

    print("\n[✓] Ollama integration test complete!")
