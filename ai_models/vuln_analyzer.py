"""
Vulnerability Analyzer - AI-powered deep analysis of security vulnerabilities
Uses Ollama to provide intelligent vulnerability assessment and exploitation guidance
"""

import json
from typing import Dict, List, Optional, Any
from .ollama_client import OllamaClient


class VulnerabilityAnalyzer:
    """
    AI-powered vulnerability analysis using local Ollama models
    """

    def __init__(self, ollama_client: OllamaClient):
        """
        Initialize vulnerability analyzer

        Args:
            ollama_client: Initialized OllamaClient instance
        """
        self.client = ollama_client
        self.analysis_cache = {}

    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform deep AI analysis of a vulnerability

        Args:
            vulnerability: Vulnerability dict with title, description, severity, etc.

        Returns:
            Dict containing detailed analysis
        """
        vuln_id = vulnerability.get("title", "unknown")

        # Check cache
        if vuln_id in self.analysis_cache:
            return self.analysis_cache[vuln_id]

        system_prompt = """You are an elite security researcher and penetration tester.
Analyze vulnerabilities with extreme technical depth, providing actionable exploitation techniques,
real-world attack scenarios, and comprehensive remediation strategies."""

        prompt = f"""Perform deep security analysis of this vulnerability:

**Vulnerability Details:**
- Title: {vulnerability.get('title', 'Unknown')}
- Category: {vulnerability.get('category', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- Description: {vulnerability.get('description', 'No description')}

**Evidence:**
{json.dumps(vulnerability.get('evidence', {}), indent=2)}

**Your Analysis Must Include:**

1. **Technical Root Cause Analysis:**
   - What is the underlying security flaw?
   - Why does this vulnerability exist?
   - What security controls are missing or bypassed?

2. **Exploitation Methodology:**
   - Step-by-step exploitation process
   - Required preconditions
   - Tools and techniques needed
   - Expected attacker skill level

3. **Real-World Attack Scenarios:**
   - How would a sophisticated attacker exploit this?
   - What data/systems could be compromised?
   - Potential for lateral movement or privilege escalation?

4. **Impact Assessment:**
   - Technical impact (CIA triad)
   - Business impact
   - Compliance violations (GDPR, PCI-DSS, etc.)
   - Estimated cost of exploitation

5. **Advanced Exploitation Techniques:**
   - Novel attack vectors
   - WAF/IDS bypass methods
   - Chaining with other vulnerabilities
   - Persistence mechanisms

6. **Detection Strategies:**
   - How to detect active exploitation
   - IOCs (Indicators of Compromise)
   - Log patterns to monitor

7. **Comprehensive Remediation:**
   - Immediate fixes (0-7 days)
   - Long-term solutions
   - Security architecture improvements
   - Code examples where applicable

8. **Risk Prioritization:**
   - Should this be fixed immediately?
   - Exploitability score (1-10)
   - Likelihood of exploitation in the wild

Provide detailed, technical analysis suitable for security professionals."""

        try:
            analysis_text = self.client.generate(
                prompt=prompt,
                temperature=0.3,  # Low temperature for consistent analysis
                max_tokens=3000,
                system_prompt=system_prompt,
            )

            if analysis_text:
                result = {
                    "vulnerability": vuln_id,
                    "analysis": analysis_text,
                    "timestamp": vulnerability.get("timestamp"),
                    "analyzed_by": f"AI Model: {self.client.get_model()}",
                }

                # Cache the result
                self.analysis_cache[vuln_id] = result
                return result
            else:
                return {
                    "vulnerability": vuln_id,
                    "error": "AI analysis failed - no response from model",
                    "fallback": "Using standard vulnerability assessment",
                }

        except Exception as e:
            return {
                "vulnerability": vuln_id,
                "error": f"AI analysis exception: {str(e)}",
                "fallback": "Using standard vulnerability assessment",
            }

    def suggest_exploit_code(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """
        Generate working exploit code for the vulnerability

        Args:
            vulnerability: Vulnerability details

        Returns:
            Python exploit code or None
        """
        system_prompt = """You are an expert exploit developer with deep knowledge of:
- Web application security
- Network protocols
- Cryptography
- Binary exploitation
- Scripting and automation

Generate production-ready, well-documented exploit code that security professionals can use for testing."""

        evidence = vulnerability.get("evidence", {})
        affected_url = vulnerability.get("affected_url", "http://target.com")

        prompt = f"""Generate a complete, working Python exploit for this vulnerability:

**Vulnerability:**
- Type: {vulnerability.get('category', 'Unknown')}
- Title: {vulnerability.get('title', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- Target URL: {affected_url}

**Evidence:**
{json.dumps(evidence, indent=2)}

**Requirements for the exploit code:**

1. **Complete Python script** that can be run standalone
2. **Proper imports** (requests, sys, argparse, etc.)
3. **Clear comments** explaining each step
4. **Error handling** for common failure cases
5. **Configurable target** (URL as command-line argument)
6. **Output formatting** showing success/failure clearly
7. **Safe execution** (no destructive operations by default)
8. **Proof-of-concept validation** (show the vulnerability was exploited)

**Code Structure:**
```python
#!/usr/bin/env python3
\"\"\"
Exploit for: {vulnerability.get('title', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
Category: {vulnerability.get('category', 'Unknown')}
\"\"\"

import requests
import sys
import argparse
# ... other imports

def exploit(target_url):
    # Your exploit logic here
    pass

def main():
    parser = argparse.ArgumentParser(description='Exploit for ...')
    parser.add_argument('target', help='Target URL')
    args = parser.parse_args()
    
    result = exploit(args.target)
    if result:
        print("[+] Exploit successful!")
    else:
        print("[-] Exploit failed")

if __name__ == "__main__":
    main()
```

Generate ONLY the complete Python code. No explanations before or after the code."""

        try:
            exploit_code = self.client.generate(
                prompt=prompt,
                temperature=0.7,  # Higher temperature for creative exploits
                max_tokens=3000,
                system_prompt=system_prompt,
            )

            if exploit_code:
                # Clean up the code (remove markdown fences if present)
                exploit_code = (
                    exploit_code.replace("```python", "").replace("```", "").strip()
                )
                return exploit_code
            return None

        except Exception as e:
            print(f"[!] Exploit generation failed: {str(e)}")
            return None

    def generate_attack_chains(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Identify and generate attack chains from multiple vulnerabilities

        Args:
            vulnerabilities: List of vulnerabilities found in target

        Returns:
            List of attack chain dicts
        """
        if len(vulnerabilities) < 2:
            return []

        system_prompt = """You are a red team operator specializing in advanced persistent threats.
Identify creative attack chains by combining multiple vulnerabilities for maximum impact."""

        # Summarize vulnerabilities for the prompt
        vuln_summary = []
        for i, v in enumerate(vulnerabilities[:15], 1):  # Limit to 15 to save tokens
            vuln_summary.append(
                f"{i}. {v.get('title', 'Unknown')} - {v.get('severity', 'Unknown')} - {v.get('category', 'Unknown')}"
            )

        prompt = f"""Analyze these {len(vulnerabilities)} vulnerabilities and identify attack chains:

**Discovered Vulnerabilities:**
{chr(10).join(vuln_summary)}

**Identify Attack Chains:**

An attack chain is a sequence of 2-5 vulnerabilities that can be exploited in order to achieve a high-impact objective (data breach, account takeover, system compromise, etc.).

For each attack chain, provide:
1. Chain name (descriptive)
2. Steps (list of vulnerability titles in order)
3. Objective (what attacker achieves)
4. Impact level (Critical/High/Medium)
5. Feasibility (High/Medium/Low)
6. Detailed explanation of how each step enables the next

Return ONLY valid JSON in this exact format:
{{
  "attack_chains": [
    {{
      "name": "Authentication Bypass to Admin Access",
      "steps": ["SQL Injection in Login", "Session Fixation", "CSRF on Admin Panel"],
      "objective": "Complete administrative control",
      "impact": "Critical",
      "feasibility": "High",
      "explanation": "First use SQL injection to bypass login, then fixate admin session, finally use CSRF to create backdoor admin account"
    }}
  ]
}}

Generate 3-5 most impactful attack chains. Return ONLY the JSON, no other text."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.6,
                max_tokens=2500,
                system_prompt=system_prompt,
            )

            if response:
                # Try to parse JSON
                try:
                    # Clean response (remove markdown fences)
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    data = json.loads(response)
                    return data.get("attack_chains", [])
                except json.JSONDecodeError:
                    print("[!] Failed to parse attack chain JSON")
                    return []
            return []

        except Exception as e:
            print(f"[!] Attack chain generation failed: {str(e)}")
            return []

    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate executive summary for non-technical stakeholders

        Args:
            scan_results: Complete scan results

        Returns:
            Executive summary text
        """
        system_prompt = """You are a Chief Information Security Officer (CISO) writing an executive summary.
Translate technical security findings into business risk language that executives understand.
Focus on impact, urgency, and actionable recommendations."""

        summary = scan_results.get("summary", {})
        total_vulns = summary.get("total_vulnerabilities", 0)
        severity_dist = summary.get("severity_distribution", {})

        # Get top 3 critical vulnerabilities
        top_vulns = [
            v
            for v in summary.get("vulnerabilities", [])
            if v.get("severity") == "Critical"
        ][:3]
        if not top_vulns:
            top_vulns = [
                v
                for v in summary.get("vulnerabilities", [])
                if v.get("severity") == "High"
            ][:3]

        top_vuln_list = "\n".join([f"- {v.get('title', 'Unknown')}" for v in top_vulns])

        prompt = f"""Generate an executive summary for this security assessment:

**Scan Overview:**
- Total Security Issues: {total_vulns}
- Critical: {severity_dist.get('Critical', 0)}
- High: {severity_dist.get('High', 0)}
- Medium: {severity_dist.get('Medium', 0)}
- Low: {severity_dist.get('Low', 0)}

**Top Critical Issues:**
{top_vuln_list}

**Generate Executive Summary Including:**

1. **Executive Overview** (2-3 sentences)
   - Current security posture
   - Overall risk level
   - Urgency of response needed

2. **Key Findings** (business terms)
   - What are the most critical issues?
   - What data/systems are at risk?
   - What could attackers do?

3. **Business Impact Assessment**
   - Financial risk (potential breach costs)
   - Reputational damage risk
   - Regulatory/compliance violations
   - Operational disruption risk

4. **Immediate Actions Required** (prioritized)
   - What must be fixed in 24-48 hours
   - What needs fixing within 1 week
   - What can be scheduled for next month

5. **Strategic Recommendations**
   - Long-term security improvements
   - Investment areas (tools, training, processes)
   - Risk management approach

6. **Compliance Considerations**
   - GDPR, PCI-DSS, HIPAA implications
   - Regulatory reporting requirements

Write in clear, non-technical business language. Use analogies where helpful. 
Keep total length to 500-800 words. Be direct and actionable."""

        try:
            summary_text = self.client.generate(
                prompt=prompt,
                temperature=0.5,
                max_tokens=2000,
                system_prompt=system_prompt,
            )

            return summary_text or "Executive summary generation failed."

        except Exception as e:
            return f"Executive summary generation error: {str(e)}"

    def assess_exploitability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess how easily this vulnerability can be exploited

        Args:
            vulnerability: Vulnerability details

        Returns:
            Exploitability assessment dict
        """
        system_prompt = """You are a vulnerability researcher assessing exploitability.
Rate vulnerabilities using industry-standard metrics (CVSS, exploitability scores)."""

        prompt = f"""Assess the exploitability of this vulnerability:

**Vulnerability:**
- Title: {vulnerability.get('title', 'Unknown')}
- Category: {vulnerability.get('category', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- Description: {vulnerability.get('description', '')}

**Evidence:**
{json.dumps(vulnerability.get('evidence', {}), indent=2)}

**Provide Exploitability Assessment as JSON:**

{{
  "exploitability_score": 9.5,
  "attack_complexity": "Low/Medium/High",
  "privileges_required": "None/Low/High",
  "user_interaction": "None/Required",
  "scope": "Unchanged/Changed",
  "confidentiality_impact": "None/Low/High",
  "integrity_impact": "None/Low/High",
  "availability_impact": "None/Low/High",
  "exploit_availability": "Public/PoC/Theoretical/None",
  "estimated_time_to_exploit": "Minutes/Hours/Days/Weeks",
  "weaponization_difficulty": "Trivial/Easy/Moderate/Difficult",
  "detection_difficulty": "Easy/Moderate/Hard",
  "remediation_difficulty": "Easy/Moderate/Hard",
  "recommendation": "Immediate/Urgent/Scheduled/Low priority"
}}

Return ONLY valid JSON, no other text."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.2,
                max_tokens=1000,
                system_prompt=system_prompt,
            )

            if response:
                try:
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    return json.loads(response)
                except json.JSONDecodeError:
                    return {"error": "Failed to parse exploitability assessment"}
            return {"error": "No response from AI model"}

        except Exception as e:
            return {"error": f"Assessment failed: {str(e)}"}

    def clear_cache(self):
        """Clear the analysis cache"""
        self.analysis_cache.clear()
