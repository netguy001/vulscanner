"""
Ollama Client - Core API wrapper for local AI models
Handles communication with Ollama API for all AI-powered features
"""

import requests
import json
from typing import Dict, List, Optional, Any


class OllamaClient:
    """
    Ollama API Client for interacting with local AI models
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "qwen2.5-coder:7b",
        timeout: int = 120,
    ):
        """
        Initialize Ollama client

        Args:
            base_url: Ollama API base URL
            model: Model name to use
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.session = requests.Session()

    def check_health(self) -> bool:
        """
        Check if Ollama service is running and accessible

        Returns:
            bool: True if service is healthy
        """
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Ollama health check failed: {str(e)}")
            return False

    def list_models(self) -> List[str]:
        """
        List available models in Ollama

        Returns:
            List of model names
        """
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return [model["name"] for model in data.get("models", [])]
            return []
        except Exception as e:
            print(f"[!] Failed to list models: {str(e)}")
            return []

    def generate(
        self,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2000,
        system_prompt: Optional[str] = None,
    ) -> Optional[str]:
        """
        Generate text using Ollama model

        Args:
            prompt: User prompt
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate
            system_prompt: Optional system prompt for context

        Returns:
            Generated text or None if failed
        """
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            # Add system prompt if provided
            if system_prompt:
                payload["system"] = system_prompt

            response = self.session.post(
                f"{self.base_url}/api/generate", json=payload, timeout=self.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return result.get("response", "").strip()
            else:
                print(f"[!] Ollama API error: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            print(f"[!] Ollama request timed out after {self.timeout}s")
            return None
        except Exception as e:
            print(f"[!] Ollama generation failed: {str(e)}")
            return None

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ) -> Optional[str]:
        """
        Chat completion using conversation history

        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Generated response or None
        """
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            response = self.session.post(
                f"{self.base_url}/api/chat", json=payload, timeout=self.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return result.get("message", {}).get("content", "").strip()
            else:
                print(f"[!] Ollama chat API error: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            print(f"[!] Ollama chat timed out after {self.timeout}s")
            return None
        except Exception as e:
            print(f"[!] Ollama chat failed: {str(e)}")
            return None

    def analyze_code(self, code: str, context: str = "") -> Optional[str]:
        """
        Analyze code for security issues using AI

        Args:
            code: Code to analyze
            context: Additional context about the code

        Returns:
            Analysis result or None
        """
        system_prompt = """You are an expert security researcher and code auditor. 
Analyze the provided code for security vulnerabilities, exploits, and weaknesses.
Provide detailed technical analysis with specific recommendations."""

        prompt = f"""Analyze this code for security issues:

Context: {context}

Code:
```
{code}
```

Provide:
1. Identified vulnerabilities
2. Severity assessment
3. Exploitation techniques
4. Remediation recommendations"""

        return self.generate(prompt, temperature=0.3, system_prompt=system_prompt)

    def generate_exploit(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """
        Generate exploit code for a vulnerability

        Args:
            vulnerability: Vulnerability details dict

        Returns:
            Generated exploit code or None
        """
        system_prompt = """You are an expert penetration tester and exploit developer.
Generate working proof-of-concept exploit code for the given vulnerability.
Code should be production-ready, well-commented, and safe for testing."""

        prompt = f"""Generate a working exploit for this vulnerability:

Title: {vulnerability.get('title', 'Unknown')}
Category: {vulnerability.get('category', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
Description: {vulnerability.get('description', '')}

Requirements:
1. Working Python exploit code
2. Clear comments explaining each step
3. Error handling
4. Safe execution (no destructive operations)
5. Output results clearly

Generate ONLY the Python code, no explanations before or after."""

        return self.generate(
            prompt, temperature=0.7, max_tokens=3000, system_prompt=system_prompt
        )

    def suggest_attack_chain(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Optional[str]:
        """
        Suggest attack chains from multiple vulnerabilities

        Args:
            vulnerabilities: List of vulnerability dicts

        Returns:
            Attack chain suggestions or None
        """
        system_prompt = """You are an expert penetration tester specializing in advanced attack chains.
Analyze multiple vulnerabilities and identify how they can be chained together for maximum impact."""

        vuln_summary = "\n".join(
            [
                f"- {v.get('title', 'Unknown')} ({v.get('severity', 'Unknown')}): {v.get('category', 'Unknown')}"
                for v in vulnerabilities[:10]  # Limit to 10 for token efficiency
            ]
        )

        prompt = f"""Given these vulnerabilities found in a target application:

{vuln_summary}

Identify potential attack chains where vulnerabilities can be combined:
1. List possible attack chains (2-5 steps each)
2. Explain how each step enables the next
3. Rate the impact and feasibility of each chain
4. Provide the most critical chain to execute first

Format as JSON with this structure:
{{
  "attack_chains": [
    {{
      "name": "Chain name",
      "steps": ["step1", "step2", "step3"],
      "impact": "Critical/High/Medium",
      "feasibility": "High/Medium/Low",
      "description": "How this chain works"
    }}
  ]
}}"""

        return self.generate(
            prompt, temperature=0.5, max_tokens=2000, system_prompt=system_prompt
        )

    def generate_payload(
        self, payload_type: str, context: Dict[str, Any], count: int = 5
    ) -> Optional[List[str]]:
        """
        Generate custom payloads using AI

        Args:
            payload_type: Type of payload (sql, xss, etc.)
            context: Context about the target
            count: Number of payloads to generate

        Returns:
            List of generated payloads or None
        """
        system_prompt = f"""You are an expert payload crafter specializing in {payload_type} attacks.
Generate creative, diverse, and effective payloads that bypass common security controls."""

        context_str = json.dumps(context, indent=2)

        prompt = f"""Generate {count} diverse {payload_type} payloads for this context:

Context:
{context_str}

Requirements:
1. Each payload should use different techniques
2. Include WAF bypass attempts
3. Be creative with encoding and obfuscation
4. Payloads should be ready to use
5. Return ONLY a JSON array of strings, nothing else

Example format:
["payload1", "payload2", "payload3"]"""

        response = self.generate(
            prompt, temperature=0.8, max_tokens=1500, system_prompt=system_prompt
        )

        if response:
            try:
                # Try to parse JSON response
                payloads = json.loads(response)
                if isinstance(payloads, list):
                    return payloads
            except json.JSONDecodeError:
                # If not JSON, split by newlines and clean
                payloads = [
                    line.strip()
                    for line in response.split("\n")
                    if line.strip() and not line.strip().startswith("#")
                ]
                return payloads[:count]

        return None

    def summarize_scan(self, scan_results: Dict[str, Any]) -> Optional[str]:
        """
        Generate executive summary of scan results

        Args:
            scan_results: Complete scan results dict

        Returns:
            Executive summary text or None
        """
        system_prompt = """You are a security consultant writing executive summaries for non-technical stakeholders.
Explain technical security issues in business terms with clear risk assessment and recommendations."""

        total_vulns = scan_results.get("summary", {}).get("total_vulnerabilities", 0)
        severity_dist = scan_results.get("summary", {}).get("severity_distribution", {})

        prompt = f"""Generate an executive summary for this security scan:

Total Vulnerabilities: {total_vulns}
Severity Distribution:
- Critical: {severity_dist.get('Critical', 0)}
- High: {severity_dist.get('High', 0)}
- Medium: {severity_dist.get('Medium', 0)}
- Low: {severity_dist.get('Low', 0)}

Top Vulnerabilities:
{json.dumps(scan_results.get('summary', {}).get('vulnerabilities', [])[:5], indent=2)}

Provide:
1. Executive Summary (2-3 paragraphs)
2. Business Risk Assessment
3. Immediate Actions Required
4. Strategic Recommendations
5. Compliance Implications

Keep it concise and business-focused."""

        return self.generate(
            prompt, temperature=0.5, max_tokens=2000, system_prompt=system_prompt
        )

    def set_model(self, model: str):
        """Change the active model"""
        self.model = model

    def get_model(self) -> str:
        """Get current model name"""
        return self.model
