"""
Attack Planner - AI-powered multi-step attack planning and orchestration
Plans complex attack chains and coordinates exploitation sequences
"""

import json
from typing import Dict, List, Optional, Any, Tuple
from .ollama_client import OllamaClient


class AttackPlanner:
    """
    AI-powered attack planning and orchestration system
    Plans multi-step attacks and coordinates exploitation
    """

    def __init__(self, ollama_client: OllamaClient):
        """
        Initialize attack planner

        Args:
            ollama_client: Initialized OllamaClient instance
        """
        self.client = ollama_client
        self.attack_plans = []
        self.execution_history = []

    def plan_attack_path(
        self, vulnerabilities: List[Dict[str, Any]], objective: str = "maximum_impact"
    ) -> Dict[str, Any]:
        """
        Plan optimal attack path from discovered vulnerabilities

        Args:
            vulnerabilities: List of discovered vulnerabilities
            objective: Attack objective (maximum_impact, data_exfiltration, persistence, etc.)

        Returns:
            Complete attack plan dict
        """
        system_prompt = """You are an advanced persistent threat (APT) operator planning sophisticated attacks.
Create detailed, multi-stage attack plans that maximize success probability while minimizing detection."""

        # Summarize vulnerabilities
        vuln_summary = []
        for i, v in enumerate(vulnerabilities[:20], 1):
            vuln_summary.append(
                f"{i}. {v.get('title', 'Unknown')} | "
                f"{v.get('severity', 'Unknown')} | "
                f"{v.get('category', 'Unknown')} | "
                f"Affected: {v.get('affected_url', 'N/A')}"
            )

        prompt = f"""Plan a sophisticated attack using these vulnerabilities:

**Available Vulnerabilities:**
{chr(10).join(vuln_summary)}

**Attack Objective:** {objective}

**Create a Comprehensive Attack Plan:**

1. **Reconnaissance Phase:**
   - Initial information gathering steps
   - Vulnerability validation
   - Target profiling

2. **Initial Access:**
   - Which vulnerability to exploit first
   - Why this provides best entry point
   - Backup entry methods

3. **Privilege Escalation:**
   - How to gain higher privileges
   - Which vulnerabilities enable this
   - Alternative escalation paths

4. **Lateral Movement:**
   - How to move within the target environment
   - Potential pivot points
   - Network mapping techniques

5. **Data Exfiltration:**
   - What data to target
   - Exfiltration methods
   - Anti-forensics techniques

6. **Persistence:**
   - How to maintain long-term access
   - Backup persistence mechanisms
   - Detection evasion

7. **Cleanup:**
   - Log tampering
   - Evidence removal
   - Attribution obfuscation

**Return as JSON:**
{{
  "plan_name": "Descriptive attack plan name",
  "objective": "{objective}",
  "difficulty": "Low/Medium/High/Advanced",
  "estimated_time": "Hours/Days/Weeks",
  "detection_risk": "Low/Medium/High",
  "phases": [
    {{
      "phase": "Phase name",
      "order": 1,
      "vulnerabilities_used": ["vuln1", "vuln2"],
      "actions": [
        {{
          "action": "Action description",
          "technique": "Technique name",
          "expected_outcome": "What happens",
          "failure_handling": "What to do if fails"
        }}
      ],
      "success_criteria": ["criterion1", "criterion2"],
      "estimated_duration": "Minutes/Hours"
    }}
  ],
  "prerequisites": ["prereq1", "prereq2"],
  "success_indicators": ["indicator1", "indicator2"],
  "abort_conditions": ["condition1", "condition2"],
  "alternative_paths": ["path1", "path2"]
}}

Return ONLY valid JSON, no other text."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.6,
                max_tokens=3500,
                system_prompt=system_prompt,
            )

            if response:
                try:
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    plan = json.loads(response)

                    # Store plan
                    self.attack_plans.append(plan)

                    return plan
                except json.JSONDecodeError as e:
                    print(f"[!] Failed to parse attack plan JSON: {str(e)}")
                    return {"error": "Failed to parse attack plan"}
            return {"error": "No response from AI"}

        except Exception as e:
            print(f"[!] Attack planning failed: {str(e)}")
            return {"error": f"Planning failed: {str(e)}"}

    def optimize_attack_sequence(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Optimize the order of vulnerability exploitation

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Optimized list of vulnerabilities in exploitation order
        """
        system_prompt = """You are optimizing attack sequences for maximum efficiency and stealth.
Order vulnerabilities to create the most effective exploitation path."""

        vuln_details = json.dumps(
            [
                {
                    "title": v.get("title", "Unknown"),
                    "severity": v.get("severity", "Unknown"),
                    "category": v.get("category", "Unknown"),
                    "exploitability": v.get("exploitability", "Unknown"),
                }
                for v in vulnerabilities[:15]
            ],
            indent=2,
        )

        prompt = f"""Optimize the exploitation order for these vulnerabilities:

**Vulnerabilities:**
{vuln_details}

**Optimization Criteria:**
1. Start with low-detection-risk vulnerabilities
2. Build from information disclosure to code execution
3. Ensure each step enables the next
4. Minimize noise and detection probability
5. Have fallback options at each stage

**Return Optimized Sequence as JSON:**
{{
  "exploitation_sequence": [
    {{
      "order": 1,
      "vulnerability": "Vulnerability title",
      "rationale": "Why exploit this first",
      "enables": ["What this unlocks"],
      "detection_risk": "Low/Medium/High",
      "fallback": "Alternative if this fails"
    }}
  ],
  "reasoning": "Overall strategy explanation"
}}

Return ONLY valid JSON."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.4,
                max_tokens=2000,
                system_prompt=system_prompt,
            )

            if response:
                try:
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    data = json.loads(response)
                    return data.get("exploitation_sequence", [])
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            print(f"[!] Sequence optimization failed: {str(e)}")
            return []

    def generate_contingency_plans(
        self, primary_plan: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate backup plans if primary attack fails

        Args:
            primary_plan: Main attack plan

        Returns:
            List of contingency plans
        """
        system_prompt = """You are creating backup attack plans.
Generate alternative approaches that achieve the same objective through different means."""

        prompt = f"""Create contingency plans for this primary attack:

**Primary Attack Plan:**
{json.dumps(primary_plan, indent=2)}

**Generate 2-3 Alternative Attack Plans:**

Each plan should:
1. Use different vulnerabilities than primary
2. Have different detection signatures
3. Achieve same objective
4. Be viable if primary is blocked/detected

**Return as JSON:**
{{
  "contingency_plans": [
    {{
      "plan_name": "Alternative plan name",
      "trigger_condition": "When to use this plan",
      "differences": "How it differs from primary",
      "phases": [...],
      "advantages": ["advantage1", "advantage2"],
      "disadvantages": ["disadvantage1", "disadvantage2"]
    }}
  ]
}}

Return ONLY valid JSON."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.7,
                max_tokens=2500,
                system_prompt=system_prompt,
            )

            if response:
                try:
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    data = json.loads(response)
                    return data.get("contingency_plans", [])
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            print(f"[!] Contingency planning failed: {str(e)}")
            return []

    def assess_attack_feasibility(
        self, attack_plan: Dict[str, Any], constraints: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Assess if an attack plan is feasible given constraints

        Args:
            attack_plan: Proposed attack plan
            constraints: Environmental constraints (time, resources, detection risk)

        Returns:
            Feasibility assessment
        """
        system_prompt = """You are assessing attack plan feasibility.
Provide realistic assessment considering operational constraints and risks."""

        prompt = f"""Assess the feasibility of this attack plan:

**Attack Plan:**
{json.dumps(attack_plan, indent=2)}

**Operational Constraints:**
{json.dumps(constraints, indent=2)}

**Assess:**
1. Is the plan executable given constraints?
2. What is probability of success?
3. What is probability of detection?
4. What resources are required?
5. What is the risk level?
6. What modifications would improve feasibility?

**Return as JSON:**
{{
  "feasible": true/false,
  "success_probability": 0.75,
  "detection_probability": 0.30,
  "required_resources": ["resource1", "resource2"],
  "estimated_time": "Hours/Days",
  "risk_level": "Low/Medium/High/Critical",
  "bottlenecks": ["bottleneck1", "bottleneck2"],
  "recommendations": ["recommendation1", "recommendation2"],
  "confidence": 0.85
}}

Return ONLY valid JSON."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.3,
                max_tokens=1500,
                system_prompt=system_prompt,
            )

            if response:
                try:
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    return json.loads(response)
                except json.JSONDecodeError:
                    return {"error": "Failed to parse assessment"}
            return {"error": "No response from AI"}

        except Exception as e:
            return {"error": f"Assessment failed: {str(e)}"}

    def generate_attack_timeline(self, attack_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed timeline for attack execution

        Args:
            attack_plan: Attack plan to schedule

        Returns:
            Timeline with timestamps and milestones
        """
        system_prompt = """You are creating operational attack timelines.
Generate realistic schedules with proper pacing and operational security considerations."""

        prompt = f"""Create a detailed execution timeline for this attack:

**Attack Plan:**
{json.dumps(attack_plan, indent=2)}

**Generate Timeline with:**
1. Phase durations
2. Wait times between phases (for stealth)
3. Checkpoints and decision points
4. Abort conditions and timing
5. Data collection windows
6. Cleanup scheduling

**Return as JSON:**
{{
  "total_duration": "X hours/days",
  "phases": [
    {{
      "phase": "Phase name",
      "start_time": "T+0h",
      "duration": "2 hours",
      "actions": [
        {{
          "time": "T+0h",
          "action": "Action description",
          "duration": "30 minutes",
          "checkpoint": "Success criteria"
        }}
      ],
      "decision_point": "What to check before next phase",
      "abort_if": "Abort conditions"
    }}
  ],
  "critical_milestones": ["milestone1", "milestone2"],
  "optimal_execution_window": "Time of day/week",
  "minimum_time_required": "X hours",
  "buffer_time": "X hours for contingencies"
}}

Return ONLY valid JSON."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.4,
                max_tokens=2000,
                system_prompt=system_prompt,
            )

            if response:
                try:
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    return json.loads(response)
                except json.JSONDecodeError:
                    return {"error": "Failed to parse timeline"}
            return {"error": "No response from AI"}

        except Exception as e:
            return {"error": f"Timeline generation failed: {str(e)}"}

    def suggest_evasion_techniques(
        self, attack_phase: str, target_defenses: List[str]
    ) -> List[Dict[str, str]]:
        """
        Suggest evasion techniques for specific defenses

        Args:
            attack_phase: Current attack phase
            target_defenses: Known security controls (WAF, IDS, EDR, etc.)

        Returns:
            List of evasion techniques
        """
        system_prompt = """You are a stealth operations specialist.
Suggest creative evasion techniques for bypassing security controls."""

        prompt = f"""Suggest evasion techniques for:

**Attack Phase:** {attack_phase}
**Target Defenses:** {', '.join(target_defenses)}

**Provide evasion techniques for each defense:**

Return as JSON:
{{
  "evasion_techniques": [
    {{
      "defense": "Defense name",
      "techniques": [
        {{
          "technique": "Technique name",
          "description": "How it works",
          "effectiveness": "High/Medium/Low",
          "implementation": "Code or command example",
          "detection_risk": "Low/Medium/High"
        }}
      ]
    }}
  ]
}}

Return ONLY valid JSON."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.7,
                max_tokens=2000,
                system_prompt=system_prompt,
            )

            if response:
                try:
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    data = json.loads(response)
                    return data.get("evasion_techniques", [])
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            print(f"[!] Evasion technique suggestion failed: {str(e)}")
            return []

    def record_execution_result(
        self, phase: str, success: bool, details: Dict[str, Any]
    ):
        """
        Record the result of executing an attack phase

        Args:
            phase: Phase name
            success: Whether phase succeeded
            details: Execution details
        """
        self.execution_history.append(
            {
                "phase": phase,
                "success": success,
                "details": details,
                "timestamp": details.get("timestamp", "unknown"),
            }
        )

    def analyze_execution_history(self) -> Dict[str, Any]:
        """
        Analyze execution history to optimize future attacks

        Returns:
            Analysis of what worked and what didn't
        """
        if not self.execution_history:
            return {"error": "No execution history"}

        system_prompt = """You are analyzing attack execution results.
Identify patterns, success factors, and areas for improvement."""

        prompt = f"""Analyze this attack execution history:

**Execution History:**
{json.dumps(self.execution_history, indent=2)}

**Provide Analysis:**
1. Success rate by phase
2. Common failure points
3. What techniques worked best
4. What should be avoided
5. Recommendations for future attacks

Return as JSON:
{{
  "success_rate": 0.75,
  "most_successful_techniques": ["technique1", "technique2"],
  "common_failures": ["failure1", "failure2"],
  "recommendations": ["rec1", "rec2"],
  "lessons_learned": ["lesson1", "lesson2"]
}}

Return ONLY valid JSON."""

        try:
            response = self.client.generate(
                prompt=prompt,
                temperature=0.3,
                max_tokens=1500,
                system_prompt=system_prompt,
            )

            if response:
                try:
                    response = (
                        response.replace("```json", "").replace("```", "").strip()
                    )
                    return json.loads(response)
                except json.JSONDecodeError:
                    return {"error": "Failed to parse analysis"}
            return {"error": "No response from AI"}

        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def get_attack_plans(self) -> List[Dict[str, Any]]:
        """Get all stored attack plans"""
        return self.attack_plans

    def clear_plans(self):
        """Clear all stored plans and history"""
        self.attack_plans.clear()
        self.execution_history.clear()
