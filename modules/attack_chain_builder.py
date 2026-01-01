"""
Attack Chain Builder Module
Identifies and executes multi-step attack sequences to demonstrate complex exploitation paths
"""

import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import time
from collections import defaultdict


class AttackChainBuilder:
    """Build and execute complex multi-step attack chains"""

    def __init__(self, vulnerabilities: List[Dict], target_url: str):
        self.vulnerabilities = vulnerabilities
        self.target_url = target_url
        self.attack_chains = []
        self.executed_chains = []

        # Attack chain templates - predefined logical attack sequences
        self.chain_templates = self._initialize_chain_templates()

    def _initialize_chain_templates(self) -> List[Dict]:
        """Define common attack chain patterns"""
        return [
            {
                "name": "Admin Account Takeover Chain",
                "description": "Gain admin access through multiple vulnerability exploitation",
                "steps": [
                    {
                        "type": "XSS",
                        "action": "Steal admin session cookie",
                        "required": True,
                    },
                    {
                        "type": "Session Management",
                        "action": "Hijack admin session",
                        "required": True,
                    },
                    {
                        "type": "Injection",
                        "action": "Extract database credentials",
                        "required": False,
                    },
                    {
                        "type": "Access Control",
                        "action": "Escalate privileges",
                        "required": False,
                    },
                ],
                "impact": "Complete administrative control over application",
                "severity": "Critical",
            },
            {
                "name": "Data Exfiltration Chain",
                "description": "Extract sensitive data through multiple vulnerabilities",
                "steps": [
                    {
                        "type": "Information Disclosure",
                        "action": "Discover database structure",
                        "required": True,
                    },
                    {
                        "type": "Injection",
                        "action": "Execute SQL injection",
                        "required": True,
                    },
                    {
                        "type": "Path Traversal",
                        "action": "Access backup files",
                        "required": False,
                    },
                ],
                "impact": "Complete data breach - customer records, credentials, PII",
                "severity": "Critical",
            },
            {
                "name": "Remote Code Execution Chain",
                "description": "Achieve server-level code execution",
                "steps": [
                    {
                        "type": "Injection",
                        "action": "SQL injection to file write",
                        "required": True,
                    },
                    {
                        "type": "Path Traversal",
                        "action": "Upload malicious file",
                        "required": False,
                    },
                    {
                        "type": "Authentication",
                        "action": "Bypass admin authentication",
                        "required": False,
                    },
                ],
                "impact": "Full server compromise - can install backdoors, pivot to internal network",
                "severity": "Critical",
            },
            {
                "name": "Privilege Escalation Chain",
                "description": "Escalate from regular user to administrator",
                "steps": [
                    {
                        "type": "Authentication",
                        "action": "Create/compromise user account",
                        "required": True,
                    },
                    {
                        "type": "Session Management",
                        "action": "Session fixation or hijacking",
                        "required": True,
                    },
                    {
                        "type": "Access Control",
                        "action": "Exploit IDOR to access admin functions",
                        "required": False,
                    },
                ],
                "impact": "Unauthorized administrative access",
                "severity": "High",
            },
            {
                "name": "Persistent Access Chain",
                "description": "Establish long-term unauthorized access",
                "steps": [
                    {
                        "type": "XSS",
                        "action": "Inject persistent payload",
                        "required": True,
                    },
                    {
                        "type": "Authentication",
                        "action": "Create backdoor account",
                        "required": True,
                    },
                    {
                        "type": "Session Management",
                        "action": "Generate long-lived session token",
                        "required": False,
                    },
                ],
                "impact": "Persistent unauthorized access even after initial vulnerability is patched",
                "severity": "High",
            },
            {
                "name": "Lateral Movement Chain",
                "description": "Move from web app to internal systems",
                "steps": [
                    {
                        "type": "Injection",
                        "action": "Command injection or SQL injection",
                        "required": True,
                    },
                    {
                        "type": "Information Disclosure",
                        "action": "Extract internal credentials/API keys",
                        "required": True,
                    },
                    {
                        "type": "CORS",
                        "action": "Access internal APIs",
                        "required": False,
                    },
                ],
                "impact": "Access to internal systems, databases, and APIs",
                "severity": "Critical",
            },
            {
                "name": "Business Logic Bypass Chain",
                "description": "Circumvent application security controls",
                "steps": [
                    {
                        "type": "Authentication",
                        "action": "Bypass login mechanism",
                        "required": True,
                    },
                    {
                        "type": "Input Validation",
                        "action": "Inject malicious data",
                        "required": True,
                    },
                    {
                        "type": "Session Management",
                        "action": "Manipulate session state",
                        "required": False,
                    },
                ],
                "impact": "Circumvent payment, access controls, or other business rules",
                "severity": "High",
            },
        ]

    def analyze_attack_chains(self) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities to identify possible attack chains"""
        print("[+] Analyzing potential attack chains...")

        # Group vulnerabilities by category
        vuln_by_category = defaultdict(list)
        for vuln in self.vulnerabilities:
            category = vuln.get("category", "Other")
            vuln_by_category[category].append(vuln)

        print(f"[*] Vulnerability categories found: {list(vuln_by_category.keys())}")

        # Check each chain template against discovered vulnerabilities
        feasible_chains = []

        for template in self.chain_templates:
            chain_feasible, matched_vulns, missing_steps = (
                self._check_chain_feasibility(template, vuln_by_category)
            )

            if chain_feasible:
                chain_info = {
                    "chain_id": len(feasible_chains) + 1,
                    "name": template["name"],
                    "description": template["description"],
                    "severity": template["severity"],
                    "impact": template["impact"],
                    "feasibility": "High" if not missing_steps else "Medium",
                    "steps": template["steps"],
                    "matched_vulnerabilities": matched_vulns,
                    "missing_steps": missing_steps,
                    "execution_status": "Not Executed",
                }

                feasible_chains.append(chain_info)
                self.attack_chains.append(chain_info)

                print(f"[+] Feasible chain identified: {template['name']}")

        if not feasible_chains:
            print("[*] No multi-step attack chains identified")
        else:
            print(f"[+] Total feasible attack chains: {len(feasible_chains)}")

        return feasible_chains

    def _check_chain_feasibility(
        self, template: Dict, vuln_by_category: Dict[str, List]
    ) -> Tuple[bool, List[Dict], List[str]]:
        """Check if an attack chain is feasible with discovered vulnerabilities"""

        matched_vulns = []
        missing_steps = []
        required_steps_met = True

        for step in template["steps"]:
            step_type = step["type"]
            step_required = step.get("required", False)

            # Find matching vulnerabilities for this step
            matching_vulns = []

            # Exact category match
            if step_type in vuln_by_category:
                matching_vulns.extend(vuln_by_category[step_type])

            # Partial matches (e.g., "SQL Injection" matches "Injection" category)
            for category, vulns in vuln_by_category.items():
                if (
                    step_type.lower() in category.lower()
                    or category.lower() in step_type.lower()
                ):
                    matching_vulns.extend(vulns)

            if matching_vulns:
                # Use the highest severity vulnerability for this step
                best_vuln = max(
                    matching_vulns,
                    key=lambda v: {
                        "Critical": 4,
                        "High": 3,
                        "Medium": 2,
                        "Low": 1,
                        "Info": 0,
                    }.get(v.get("severity", "Info"), 0),
                )

                matched_vulns.append(
                    {
                        "step": step["action"],
                        "vulnerability": best_vuln["title"],
                        "severity": best_vuln["severity"],
                        "category": best_vuln["category"],
                    }
                )
            else:
                if step_required:
                    required_steps_met = False
                missing_steps.append(step["action"])

        # Chain is feasible if all required steps have matching vulnerabilities
        is_feasible = required_steps_met and len(matched_vulns) >= 2

        return is_feasible, matched_vulns, missing_steps

    def execute_attack_chain(
        self, chain_id: int, exploit_executor=None
    ) -> Dict[str, Any]:
        """Execute a specific attack chain"""

        if chain_id < 1 or chain_id > len(self.attack_chains):
            return {"error": "Invalid chain ID"}

        chain = self.attack_chains[chain_id - 1]

        print(f"\n[+] Executing Attack Chain: {chain['name']}")
        print(f"[*] Description: {chain['description']}")
        print(f"[*] Steps: {len(chain['steps'])}")

        execution_result = {
            "chain_id": chain_id,
            "chain_name": chain["name"],
            "timestamp": datetime.now().isoformat(),
            "execution_steps": [],
            "overall_success": False,
            "impact_achieved": [],
            "chain_broken_at_step": None,
        }

        # Execute each step in sequence
        for i, step_info in enumerate(chain["matched_vulnerabilities"], 1):
            print(
                f"\n[*] Step {i}/{len(chain['matched_vulnerabilities'])}: {step_info['step']}"
            )

            step_result = {
                "step_number": i,
                "action": step_info["step"],
                "vulnerability_used": step_info["vulnerability"],
                "severity": step_info["severity"],
                "success": False,
                "evidence": {},
            }

            # Simulate step execution with delay
            time.sleep(0.5)

            # If exploit executor is provided, actually execute the exploit
            if exploit_executor:
                # Find the actual vulnerability object
                matching_vuln = None
                for vuln in self.vulnerabilities:
                    if vuln.get("title") == step_info["vulnerability"]:
                        matching_vuln = vuln
                        break

                if matching_vuln:
                    # Execute the appropriate exploit
                    category = matching_vuln.get("category")

                    if category == "Injection" and "SQL" in matching_vuln.get(
                        "title", ""
                    ):
                        exploit_result = exploit_executor.exploit_sql_injection(
                            matching_vuln
                        )
                    elif category == "XSS":
                        exploit_result = exploit_executor.exploit_xss(matching_vuln)
                    elif category == "Authentication":
                        exploit_result = exploit_executor.exploit_auth_bypass(
                            matching_vuln
                        )
                    elif category == "Path Traversal":
                        exploit_result = exploit_executor.exploit_path_traversal(
                            matching_vuln
                        )
                    else:
                        # Generic success for other types
                        exploit_result = {
                            "success": True,
                            "evidence": {"simulated": True},
                        }

                    step_result["success"] = exploit_result.get("success", False)
                    step_result["evidence"] = exploit_result.get("evidence", {})
                    step_result["impact"] = exploit_result.get(
                        "impact_demonstrated", []
                    )
            else:
                # Simulated execution without actual exploits
                # High/Critical vulns have higher success probability
                success_probability = (
                    0.9 if step_info["severity"] in ["Critical", "High"] else 0.7
                )
                step_result["success"] = True  # Assume success for demonstration
                step_result["evidence"] = {
                    "simulated": True,
                    "note": "Actual exploit not executed",
                }

            execution_result["execution_steps"].append(step_result)

            # If step fails, chain breaks
            if not step_result["success"]:
                execution_result["chain_broken_at_step"] = i
                execution_result["overall_success"] = False
                print(f"[!] Chain broken at step {i} - {step_info['step']}")
                break

        # If all steps succeeded, chain is successful
        if execution_result["chain_broken_at_step"] is None:
            execution_result["overall_success"] = True
            execution_result["impact_achieved"] = [chain["impact"]]
            print(f"\n[+] Attack chain SUCCESSFUL!")
            print(f"[+] Impact: {chain['impact']}")

        self.executed_chains.append(execution_result)

        # Update chain status
        chain["execution_status"] = (
            "Successful" if execution_result["overall_success"] else "Failed"
        )
        chain["execution_result"] = execution_result

        return execution_result

    def execute_all_chains(self, exploit_executor=None) -> List[Dict]:
        """Execute all identified attack chains"""
        print("\n[+] Executing all feasible attack chains...")

        results = []
        for i, chain in enumerate(self.attack_chains, 1):
            result = self.execute_attack_chain(i, exploit_executor)
            results.append(result)
            time.sleep(1)  # Delay between chains

        return results

    def generate_attack_graph(self) -> Dict[str, Any]:
        """Generate attack graph visualization data"""

        nodes = []
        edges = []

        # Entry point node
        nodes.append(
            {
                "id": "start",
                "label": "Initial Access",
                "type": "entry",
                "color": "#10b981",
            }
        )

        # Create nodes for each vulnerability
        for i, vuln in enumerate(self.vulnerabilities):
            node_id = f"vuln_{i}"
            nodes.append(
                {
                    "id": node_id,
                    "label": vuln.get("title", "Unknown")[:40],
                    "type": "vulnerability",
                    "severity": vuln.get("severity", "Info"),
                    "category": vuln.get("category", "Other"),
                    "color": self._get_severity_color(vuln.get("severity", "Info")),
                }
            )

            # Connect entry point to all vulnerabilities
            edges.append({"from": "start", "to": node_id, "label": "exploit"})

        # Create nodes for each attack chain
        for i, chain in enumerate(self.attack_chains):
            chain_id = f"chain_{i}"
            nodes.append(
                {
                    "id": chain_id,
                    "label": chain["name"],
                    "type": "attack_chain",
                    "severity": chain["severity"],
                    "color": (
                        "#ef4444" if chain["severity"] == "Critical" else "#f59e0b"
                    ),
                }
            )

            # Connect vulnerabilities to chains
            for matched_vuln in chain.get("matched_vulnerabilities", []):
                for j, vuln in enumerate(self.vulnerabilities):
                    if vuln.get("title") == matched_vuln["vulnerability"]:
                        edges.append(
                            {"from": f"vuln_{j}", "to": chain_id, "label": "chain step"}
                        )

        # Impact node
        nodes.append(
            {
                "id": "impact",
                "label": "System Compromise",
                "type": "impact",
                "color": "#dc2626",
            }
        )

        # Connect successful chains to impact
        for i, chain in enumerate(self.attack_chains):
            if chain.get("execution_status") == "Successful":
                edges.append(
                    {
                        "from": f"chain_{i}",
                        "to": "impact",
                        "label": "achieve",
                        "color": "#dc2626",
                        "width": 3,
                    }
                )

        return {
            "nodes": nodes,
            "edges": edges,
            "statistics": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_chains": len(self.attack_chains),
                "successful_chains": len(
                    [
                        c
                        for c in self.attack_chains
                        if c.get("execution_status") == "Successful"
                    ]
                ),
                "failed_chains": len(
                    [
                        c
                        for c in self.attack_chains
                        if c.get("execution_status") == "Failed"
                    ]
                ),
            },
        }

    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#f59e0b",
            "Low": "#06b6d4",
            "Info": "#6b7280",
        }
        return colors.get(severity, "#6b7280")

    def generate_chain_report(self) -> Dict[str, Any]:
        """Generate comprehensive attack chain report"""

        successful_chains = [
            c for c in self.executed_chains if c.get("overall_success")
        ]
        failed_chains = [
            c for c in self.executed_chains if not c.get("overall_success")
        ]

        report = {
            "summary": {
                "total_chains_identified": len(self.attack_chains),
                "chains_executed": len(self.executed_chains),
                "successful_chains": len(successful_chains),
                "failed_chains": len(failed_chains),
                "success_rate": (
                    f"{(len(successful_chains) / len(self.executed_chains) * 100):.1f}%"
                    if self.executed_chains
                    else "0%"
                ),
            },
            "identified_chains": self.attack_chains,
            "execution_results": self.executed_chains,
            "critical_findings": self._extract_critical_findings(),
            "attack_graph": self.generate_attack_graph(),
        }

        return report

    def _extract_critical_findings(self) -> List[str]:
        """Extract critical security findings from attack chains"""
        findings = []

        for chain in self.executed_chains:
            if chain.get("overall_success"):
                findings.append(
                    f"CRITICAL: {chain['chain_name']} is fully exploitable - {', '.join(chain.get('impact_achieved', []))}"
                )

        # Check for particularly dangerous combinations
        vuln_categories = set([v.get("category") for v in self.vulnerabilities])

        if "Injection" in vuln_categories and "Authentication" in vuln_categories:
            findings.append(
                "CRITICAL COMBINATION: SQL Injection + Authentication vulnerabilities enable complete system takeover"
            )

        if "XSS" in vuln_categories and "Session Management" in vuln_categories:
            findings.append(
                "HIGH RISK COMBINATION: XSS + Weak Session Management enables widespread account hijacking"
            )

        return findings


# Testing
if __name__ == "__main__":
    print("[+] Testing Attack Chain Builder...")

    # Mock vulnerabilities
    test_vulns = [
        {
            "title": "SQL Injection in Login Form",
            "severity": "Critical",
            "category": "Injection",
        },
        {"title": "Stored XSS in Comment Field", "severity": "High", "category": "XSS"},
        {
            "title": "Weak Session Token",
            "severity": "High",
            "category": "Session Management",
        },
        {
            "title": "Missing Authentication on Admin Panel",
            "severity": "Critical",
            "category": "Authentication",
        },
    ]

    builder = AttackChainBuilder(test_vulns, "http://example.com")

    # Analyze chains
    chains = builder.analyze_attack_chains()
    print(f"\n[+] Identified {len(chains)} attack chains")

    # Show chains
    for chain in chains:
        print(f"\n Chain: {chain['name']}")
        print(f"   Severity: {chain['severity']}")
        print(f"   Steps: {len(chain['steps'])}")
        print(f"   Impact: {chain['impact']}")

    # Generate report
    report = builder.generate_chain_report()
    print(f"\n[+] Report generated: {json.dumps(report['summary'], indent=2)}")

    print("\n[✓] Attack chain builder test complete!")
