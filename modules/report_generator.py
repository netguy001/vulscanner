"""
Report Generator Module
Generates JSON and Markdown reports from scan results
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    def __init__(self, target_url, recon_results, passive_vulns, active_vulns):
        self.target_url = target_url
        self.recon_results = recon_results
        self.passive_vulns = passive_vulns
        self.active_vulns = active_vulns
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_all_reports(self):
        """Generate both JSON and Markdown reports"""
        # Create reports directories if they don't exist
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

        # Sort by severity score (highest first)
        all_vulns.sort(key=lambda x: x["severity_score"], reverse=True)

        return all_vulns

    def get_severity_summary(self, vulnerabilities):
        """Calculate severity distribution"""
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for vuln in vulnerabilities:
            severity = vuln["severity"]
            if severity in summary:
                summary[severity] += 1

        return summary

    def generate_json_report(self):
        """Generate JSON report"""
        all_vulns = self.get_all_vulnerabilities()
        severity_summary = self.get_severity_summary(all_vulns)

        report_data = {
            "scan_info": {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "total_vulnerabilities": len(all_vulns),
            },
            "severity_summary": severity_summary,
            "reconnaissance": self.recon_results,
            "vulnerabilities": all_vulns,
        }

        filename = f"scan_report_{self.timestamp}.json"
        filepath = os.path.join("reports", "json", filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return filepath

    def generate_markdown_report(self):
        """Generate Markdown report"""
        all_vulns = self.get_all_vulnerabilities()
        severity_summary = self.get_severity_summary(all_vulns)

        md_content = []

        # Header
        md_content.append(f"# Web Security Scan Report")
        md_content.append(f"\n---\n")

        # Executive Summary
        md_content.append(f"## Executive Summary")
        md_content.append(f"\n**Target:** {self.target_url}")
        md_content.append(
            f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        md_content.append(f"**Total Findings:** {len(all_vulns)}\n")

        # Severity Distribution
        md_content.append(f"### Severity Distribution\n")
        for severity, count in severity_summary.items():
            if count > 0:
                md_content.append(f"- **{severity}:** {count}")
        md_content.append("\n---\n")

        # Reconnaissance Results
        md_content.append(f"## Reconnaissance Results\n")

        # DNS Information
        if "dns_info" in self.recon_results:
            dns = self.recon_results["dns_info"]
            md_content.append(f"### DNS Information\n")
            if dns.get("a_records"):
                md_content.append(f"**A Records:** {', '.join(dns['a_records'])}")
            if dns.get("mx_records"):
                md_content.append(f"**MX Records:** {', '.join(dns['mx_records'])}")
            if dns.get("ns_records"):
                md_content.append(f"**NS Records:** {', '.join(dns['ns_records'])}")
            md_content.append("")

        # IP Information
        if "ip_info" in self.recon_results:
            ip = self.recon_results["ip_info"]
            if "ip_address" in ip:
                md_content.append(f"### IP Information\n")
                md_content.append(f"**IP Address:** {ip['ip_address']}")
                md_content.append(f"**Hostname:** {ip.get('hostname', 'N/A')}\n")

        # Technology Stack
        if "tech_stack" in self.recon_results:
            tech = self.recon_results["tech_stack"]
            md_content.append(f"### Technology Stack\n")
            if tech.get("server"):
                md_content.append(f"**Web Server:** {tech['server']}")
            if tech.get("programming_language"):
                md_content.append(
                    f"**Programming Language:** {tech['programming_language']}"
                )
            if tech.get("cms"):
                md_content.append(f"**CMS:** {tech['cms']}")
            if tech.get("frameworks"):
                md_content.append(f"**Frameworks:** {', '.join(tech['frameworks'])}")
            md_content.append("")

        # TLS/SSL Information
        if "tls_info" in self.recon_results:
            tls = self.recon_results["tls_info"]
            if "tls_version" in tls:
                md_content.append(f"### TLS/SSL Configuration\n")
                md_content.append(f"**TLS Version:** {tls['tls_version']}")
                if "cipher" in tls and tls["cipher"]:
                    cipher_name = (
                        tls["cipher"][0]
                        if isinstance(tls["cipher"], tuple)
                        else str(tls["cipher"])
                    )
                    md_content.append(f"**Cipher Suite:** {cipher_name}")
                md_content.append("")

        md_content.append("\n---\n")

        # Vulnerabilities by Severity
        md_content.append(f"## Vulnerability Findings\n")

        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            severity_vulns = [v for v in all_vulns if v["severity"] == severity]

            if severity_vulns:
                md_content.append(f"### {severity} Severity ({len(severity_vulns)})\n")

                for i, vuln in enumerate(severity_vulns, 1):
                    md_content.append(f"#### {i}. {vuln['title']}\n")
                    md_content.append(f"**Category:** {vuln['category']}")
                    md_content.append(
                        f"**Severity:** {vuln['severity']} (Score: {vuln['severity_score']})\n"
                    )
                    md_content.append(f"**Description:**")
                    md_content.append(f"{vuln['description']}\n")
                    md_content.append(f"**Remediation:**")
                    md_content.append(f"{vuln['remediation']}\n")
                    md_content.append("---\n")

        # Footer
        md_content.append(f"\n## Report Information\n")
        md_content.append(f"This report was generated by Web Security Scanner")
        md_content.append(
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        md_content.append(f"\n---")
        md_content.append(f"\n*This scan is for authorized security testing only.*")

        # Write to file
        filename = f"scan_report_{self.timestamp}.md"
        filepath = os.path.join("reports", "markdown", filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(md_content))

        return filepath
