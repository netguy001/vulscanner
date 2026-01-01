"""
Flask Web Application - AI-Powered Security Scanner Backend
Enhanced with Exploit Execution, Attack Chains, AI Analysis, and Adaptive Evasion
Version 3.0.0
"""

from flask import Flask, render_template, request, jsonify, send_file
import traceback
import os
import yaml
from datetime import datetime
from modules.passive_recon import PassiveRecon
from modules.passive_vuln_scanner import PassiveVulnScanner
from modules.active_probe import ActiveProbe
from modules.crawler import WebCrawler
from modules.authentication_scanner import AuthenticationScanner
from modules.auth_bypass_advanced import AdvancedAuthBypass
from modules.exploit_executor import ExploitExecutor
from modules.attack_chain_builder import AttackChainBuilder
from modules.ollama_integration import OllamaClient, VulnerabilityAnalyzer
from modules.payload_generator import PayloadGenerator
from modules.adaptive_evasion import AdaptiveEvasion
from modules.report_generator import ReportGenerator

app = Flask(__name__)

# Load configuration
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Store scan results and sessions
scan_sessions = {}
active_scans = {}


@app.route("/")
def index():
    """Render main page"""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Initialize and run comprehensive AI-powered security scan"""
    try:
        data = request.get_json()
        target_url = data.get("target_url", "").strip()
        scan_type = data.get(
            "scan_type", "full"
        )  # 'passive', 'full', 'comprehensive', 'ai-enhanced'
        crawler_depth = data.get(
            "crawler_depth", config["scanning"]["crawler"]["max_depth"]
        )
        enable_exploitation = data.get(
            "enable_exploitation", config["exploitation"]["enabled"]
        )
        enable_ai_analysis = data.get("enable_ai", config["ai_features"]["enabled"])

        # Validation
        if not target_url:
            return jsonify({"error": "Target URL is required"}), 400

        if not target_url.startswith(("http://", "https://")):
            return jsonify({"error": "URL must start with http:// or https://"}), 400

        # Generate session ID
        session_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Initialize results
        results = {
            "session_id": session_id,
            "target": target_url,
            "scan_type": scan_type,
            "status": "running",
            "progress": [],
            "ai_enabled": enable_ai_analysis,
            "exploitation_enabled": enable_exploitation,
        }

        active_scans[session_id] = results

        # Phase 1: Passive Reconnaissance
        results["progress"].append("[1/8] Starting passive reconnaissance...")
        recon = PassiveRecon(target_url)
        recon_results = recon.run_all_checks()
        results["recon"] = recon_results
        results["progress"].append("[1/8] ✓ Passive reconnaissance completed")

        # Phase 2: Passive Vulnerability Scanning
        results["progress"].append("[2/8] Starting passive vulnerability scan...")
        passive_scanner = PassiveVulnScanner(recon_results)
        passive_vulns = passive_scanner.run_all_checks()
        results["passive_vulnerabilities"] = passive_vulns
        results["progress"].append("[2/8] ✓ Passive vulnerability scan completed")

        # Phase 3: Web Crawling
        crawler_results = {
            "discovered_urls": [],
            "forms": [],
            "parameters": [],
            "endpoints": [],
        }
        if scan_type in ["full", "comprehensive", "ai-enhanced"]:
            results["progress"].append(
                f"[3/8] Starting web crawling (depth: {crawler_depth})..."
            )
            crawler = WebCrawler(target_url, max_depth=crawler_depth)
            crawler_results = crawler.run_crawl()
            results["crawler"] = crawler_results
            results["progress"].append(
                f'[3/8] ✓ Web crawling completed - Found {crawler_results["total_urls"]} URLs, {crawler_results["total_forms"]} forms'
            )
        else:
            results["progress"].append(
                "[3/8] ⊘ Web crawling skipped (passive scan only)"
            )
            results["crawler"] = crawler_results

        # Phase 4: Authentication Testing
        auth_results = {"vulnerabilities": []}
        if scan_type in ["comprehensive", "ai-enhanced"]:
            results["progress"].append(
                "[4/8] Starting authentication & session testing..."
            )

            # Standard auth scanner
            auth_scanner = AuthenticationScanner(target_url)
            auth_results = auth_scanner.run_all_checks()

            # Advanced auth bypass testing
            if config["scanning"]["auth_testing"]["test_jwt_vulnerabilities"]:
                results["progress"].append(
                    "[4/8] Running advanced authentication bypass tests..."
                )
                advanced_auth = AdvancedAuthBypass(target_url)
                advanced_results = advanced_auth.run_all_tests()

                # Merge results
                auth_results["vulnerabilities"].extend(
                    advanced_results["vulnerabilities"]
                )
                auth_results["total_findings"] = len(auth_results["vulnerabilities"])

            results["auth_vulnerabilities"] = auth_results
            results["progress"].append(
                f'[4/8] ✓ Authentication testing completed - Found {auth_results["total_findings"]} issues'
            )
        else:
            results["progress"].append("[4/8] ⊘ Authentication testing skipped")
            results["auth_vulnerabilities"] = auth_results

        # Phase 5: Active Probing
        active_vulns = {"vulnerabilities": []}
        if scan_type in ["full", "comprehensive", "ai-enhanced"]:
            results["progress"].append("[5/8] Starting active security probing...")
            active_scanner = ActiveProbe(target_url)
            active_vulns = active_scanner.run_all_checks()
            results["active_vulnerabilities"] = active_vulns
            results["progress"].append(
                f'[5/8] ✓ Active probing completed - Found {active_vulns["total_findings"]} issues'
            )
        else:
            results["progress"].append(
                "[5/8] ⊘ Active probing skipped (passive scan only)"
            )
            results["active_vulnerabilities"] = active_vulns

        # Collect all vulnerabilities
        all_vulns = []
        if "vulnerabilities" in passive_vulns:
            all_vulns.extend(passive_vulns["vulnerabilities"])
        if "vulnerabilities" in active_vulns:
            all_vulns.extend(active_vulns["vulnerabilities"])
        if "vulnerabilities" in auth_results:
            all_vulns.extend(auth_results["vulnerabilities"])

        # Phase 6: AI-Powered Analysis
        ai_analysis_results = None
        if enable_ai_analysis and scan_type == "ai-enhanced":
            results["progress"].append(
                "[6/8] Running AI-powered vulnerability analysis..."
            )

            try:
                # Initialize Ollama client
                ollama_client = OllamaClient(
                    base_url=config["ollama"]["base_url"],
                    model=config["ollama"]["models"]["analysis"],
                )

                # Check if Ollama is running
                if ollama_client.check_health():
                    analyzer = VulnerabilityAnalyzer(ollama_client)

                    # Analyze top vulnerabilities
                    ai_analysis_results = {
                        "analyzed_vulnerabilities": [],
                        "attack_chains": [],
                        "executive_summary": None,
                    }

                    # Analyze critical/high severity vulnerabilities
                    critical_vulns = [
                        v
                        for v in all_vulns
                        if v.get("severity") in ["Critical", "High"]
                    ]

                    for vuln in critical_vulns[:5]:  # Analyze top 5
                        results["progress"].append(
                            f"[6/8] Analyzing: {vuln['title'][:50]}..."
                        )
                        analysis = analyzer.analyze_vulnerability(vuln)
                        ai_analysis_results["analyzed_vulnerabilities"].append(
                            {"vulnerability": vuln["title"], "analysis": analysis}
                        )

                    # Generate attack chains
                    if len(all_vulns) >= 2:
                        results["progress"].append("[6/8] Identifying attack chains...")
                        attack_chains = analyzer.generate_attack_chains(all_vulns)
                        ai_analysis_results["attack_chains"] = attack_chains

                    # Generate executive summary
                    results["progress"].append("[6/8] Generating executive summary...")
                    summary_data = {
                        "summary": {
                            "total_vulnerabilities": len(all_vulns),
                            "severity_distribution": _calculate_severity_distribution(
                                all_vulns
                            ),
                        }
                    }
                    executive_summary = analyzer.generate_executive_summary(
                        summary_data
                    )
                    ai_analysis_results["executive_summary"] = executive_summary

                    results["ai_analysis"] = ai_analysis_results
                    results["progress"].append("[6/8] ✓ AI analysis completed")
                else:
                    results["progress"].append(
                        "[6/8] ⚠ Ollama not running - AI analysis skipped"
                    )
                    results["ai_analysis"] = {"error": "Ollama service not available"}

            except Exception as e:
                results["progress"].append(f"[6/8] ⚠ AI analysis error: {str(e)}")
                results["ai_analysis"] = {"error": str(e)}
        else:
            results["progress"].append("[6/8] ⊘ AI analysis skipped")

        # Phase 7: Exploit Execution
        exploitation_results = None
        if enable_exploitation and len(all_vulns) > 0:
            results["progress"].append("[7/8] Starting exploit execution...")

            try:
                executor = ExploitExecutor(target_url)
                exploitation_results = {
                    "exploited_vulnerabilities": [],
                    "exploitation_summary": None,
                }

                # Execute exploits for critical/high vulnerabilities
                exploitable_vulns = [
                    v for v in all_vulns if v.get("severity") in ["Critical", "High"]
                ]

                for vuln in exploitable_vulns[:10]:  # Limit to 10 exploits
                    results["progress"].append(
                        f"[7/8] Exploiting: {vuln['title'][:50]}..."
                    )
                    exploit_result = executor.execute_vulnerability(vuln)

                    exploitation_results["exploited_vulnerabilities"].append(
                        {
                            "vulnerability": vuln["title"],
                            "exploit_result": exploit_result,
                        }
                    )

                    if exploit_result.get("success"):
                        results["progress"].append(f"[7/8] ✓ Exploit successful!")

                # Get exploitation summary
                exploitation_results["exploitation_summary"] = (
                    executor.get_exploitation_summary()
                )
                results["exploitation"] = exploitation_results
                results["progress"].append(
                    f'[7/8] ✓ Exploitation completed - {exploitation_results["exploitation_summary"]["successful_exploits"]} successful'
                )

            except Exception as e:
                results["progress"].append(f"[7/8] ⚠ Exploitation error: {str(e)}")
                results["exploitation"] = {"error": str(e)}
        else:
            results["progress"].append("[7/8] ⊘ Exploitation skipped")

        # Phase 8: Generate Reports
        results["progress"].append("[8/8] Generating comprehensive reports...")
        report_gen = ReportGenerator(
            target_url,
            recon_results,
            passive_vulns,
            active_vulns,
            (
                crawler_results
                if scan_type in ["full", "comprehensive", "ai-enhanced"]
                else None
            ),
            auth_results if scan_type in ["comprehensive", "ai-enhanced"] else None,
        )
        report_paths = report_gen.generate_all_reports()
        results["reports"] = report_paths
        results["progress"].append("[8/8] ✓ Reports generated successfully")

        # Calculate comprehensive summary
        severity_count = _calculate_severity_distribution(all_vulns)

        # Categorize vulnerabilities
        vulns_by_category = {}
        for vuln in all_vulns:
            category = vuln.get("category", "Other")
            if category not in vulns_by_category:
                vulns_by_category[category] = []
            vulns_by_category[category].append(vuln)

        # Sort vulnerabilities by severity score
        all_vulns.sort(key=lambda x: x.get("severity_score", 0), reverse=True)

        # Build comprehensive summary
        results["summary"] = {
            "total_vulnerabilities": len(all_vulns),
            "severity_distribution": severity_count,
            "vulnerabilities": all_vulns,
            "vulnerabilities_by_category": vulns_by_category,
            "scan_coverage": {
                "passive_recon": True,
                "passive_vulns": True,
                "crawler": scan_type in ["full", "comprehensive", "ai-enhanced"],
                "authentication": scan_type in ["comprehensive", "ai-enhanced"],
                "active_probing": scan_type in ["full", "comprehensive", "ai-enhanced"],
                "ai_analysis": enable_ai_analysis and scan_type == "ai-enhanced",
                "exploitation": enable_exploitation
                and exploitation_results is not None,
            },
            "attack_surface": (
                {
                    "urls_discovered": crawler_results.get("total_urls", 0),
                    "forms_found": crawler_results.get("total_forms", 0),
                    "parameters_found": crawler_results.get("total_parameters", 0),
                    "endpoints_found": crawler_results.get("total_endpoints", 0),
                }
                if scan_type in ["full", "comprehensive", "ai-enhanced"]
                else None
            ),
        }

        results["status"] = "completed"
        results["progress"].append("═══════════════════════════════════════")
        results["progress"].append(f"✓ SCAN COMPLETED SUCCESSFULLY")
        results["progress"].append(f"  Total Vulnerabilities: {len(all_vulns)}")
        results["progress"].append(
            f'  Critical: {severity_count["Critical"]} | High: {severity_count["High"]} | Medium: {severity_count["Medium"]}'
        )
        if exploitation_results:
            results["progress"].append(
                f'  Exploits: {exploitation_results["exploitation_summary"]["successful_exploits"]} successful'
            )
        results["progress"].append("═══════════════════════════════════════")

        # Store in sessions
        scan_sessions[session_id] = results

        return jsonify(results), 200

    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"ERROR: {error_trace}")
        return (
            jsonify({"error": str(e), "traceback": error_trace, "status": "failed"}),
            500,
        )


@app.route("/api/ai-analyze", methods=["POST"])
def ai_analyze_vulnerability():
    """AI-powered deep analysis of a specific vulnerability"""
    try:
        data = request.get_json()
        vulnerability = data.get("vulnerability")

        if not vulnerability:
            return jsonify({"error": "Vulnerability data required"}), 400

        # Initialize Ollama client
        ollama_client = OllamaClient(
            base_url=config["ollama"]["base_url"],
            model=config["ollama"]["models"]["analysis"],
        )

        if not ollama_client.check_health():
            return jsonify({"error": "Ollama service not available"}), 503

        analyzer = VulnerabilityAnalyzer(ollama_client)
        analysis = analyzer.analyze_vulnerability(vulnerability)

        # Generate exploit suggestions
        exploit_code = analyzer.suggest_exploit_code(vulnerability)

        return (
            jsonify(
                {
                    "vulnerability": vulnerability["title"],
                    "ai_analysis": analysis,
                    "exploit_code": exploit_code,
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit", methods=["POST"])
def execute_exploit():
    """Execute exploit for a specific vulnerability"""
    try:
        data = request.get_json()
        target_url = data.get("target_url")
        vulnerability = data.get("vulnerability")

        if not target_url or not vulnerability:
            return jsonify({"error": "Target URL and vulnerability required"}), 400

        # Initialize exploit executor
        executor = ExploitExecutor(target_url)
        result = executor.execute_vulnerability(vulnerability)

        return (
            jsonify(
                {
                    "vulnerability": vulnerability["title"],
                    "exploitation_result": result,
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/attack-chain", methods=["POST"])
def build_attack_chain():
    """Build and optionally execute attack chains"""
    try:
        data = request.get_json()
        target_url = data.get("target_url")
        vulnerabilities = data.get("vulnerabilities", [])
        execute = data.get("execute", False)

        if not target_url or not vulnerabilities:
            return jsonify({"error": "Target URL and vulnerabilities required"}), 400

        # Build attack chains
        builder = AttackChainBuilder(vulnerabilities, target_url)
        chains = builder.analyze_attack_chains()

        results = {"identified_chains": chains, "execution_results": None}

        # Execute chains if requested
        if execute and config["ai_features"]["attack_chains"]["execute_chains"]:
            executor = ExploitExecutor(target_url)
            execution_results = builder.execute_all_chains(executor)
            results["execution_results"] = execution_results

        # Generate attack graph
        attack_graph = builder.generate_attack_graph()
        results["attack_graph"] = attack_graph

        # Generate report
        chain_report = builder.generate_chain_report()
        results["report"] = chain_report

        return jsonify(results), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/generate-payloads", methods=["POST"])
def generate_payloads():
    """Generate AI-powered payloads for specific vulnerability type"""
    try:
        data = request.get_json()
        payload_type = data.get("type")  # sql, xss, path_traversal, etc.
        context = data.get("context", {})
        count = data.get("count", 10)

        if not payload_type:
            return jsonify({"error": "Payload type required"}), 400

        # Initialize payload generator
        generator = PayloadGenerator()

        payloads = []
        if payload_type == "sql":
            payloads = generator.generate_sql_injection_payloads(context, count)
        elif payload_type == "xss":
            payloads = generator.generate_xss_payloads(context, count)
        elif payload_type == "auth_bypass":
            payloads = generator.generate_auth_bypass_payloads(
                context.get("auth_type", "form"), context, count
            )
        elif payload_type == "path_traversal":
            payloads = generator.generate_path_traversal_payloads(
                context.get("os_type", "linux"), context, count
            )
        elif payload_type == "ssti":
            payloads = generator.generate_ssti_payloads(
                context.get("template_engine", "unknown"), context, count
            )
        else:
            return jsonify({"error": f"Unknown payload type: {payload_type}"}), 400

        return (
            jsonify(
                {
                    "payload_type": payload_type,
                    "payloads": payloads,
                    "count": len(payloads),
                    "context": context,
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/adaptive-evade", methods=["POST"])
def adaptive_evasion():
    """Generate evaded payload variants using adaptive techniques"""
    try:
        data = request.get_json()
        original_payload = data.get("payload")
        payload_type = data.get("type")
        previous_attempts = data.get("previous_attempts", [])

        if not original_payload or not payload_type:
            return jsonify({"error": "Payload and type required"}), 400

        # Initialize adaptive evasion
        evasion = AdaptiveEvasion()

        # Generate evaded variants
        evaded_payloads = evasion.evade_payload(
            original_payload, payload_type, previous_attempts
        )

        # Get evasion stats
        stats = evasion.get_evasion_stats()

        return (
            jsonify(
                {
                    "original_payload": original_payload,
                    "evaded_payloads": evaded_payloads,
                    "evasion_stats": stats,
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan-status/<session_id>", methods=["GET"])
def get_scan_status(session_id):
    """Get real-time scan status"""
    if session_id in active_scans:
        return jsonify(active_scans[session_id]), 200
    elif session_id in scan_sessions:
        return jsonify(scan_sessions[session_id]), 200
    else:
        return jsonify({"error": "Session not found"}), 404


@app.route("/api/health", methods=["GET"])
def health_check():
    """Enhanced health check with AI service status"""
    # Check Ollama status
    ollama_status = False
    try:
        ollama_client = OllamaClient(base_url=config["ollama"]["base_url"])
        ollama_status = ollama_client.check_health()
    except:
        pass

    return (
        jsonify(
            {
                "status": "healthy",
                "service": "AI-Powered Web Security Scanner",
                "version": config["app"]["version"],
                "modules": {
                    "passive_recon": True,
                    "passive_scanner": True,
                    "active_probe": True,
                    "crawler": True,
                    "auth_scanner": True,
                    "advanced_auth_bypass": True,
                    "exploit_executor": True,
                    "attack_chain_builder": True,
                    "ollama_integration": ollama_status,
                    "payload_generator": True,
                    "adaptive_evasion": True,
                    "report_generator": True,
                },
                "ai_features": {
                    "ollama_connected": ollama_status,
                    "models_available": (
                        list(config["ollama"]["models"].values())
                        if ollama_status
                        else []
                    ),
                    "analysis_enabled": config["ai_features"]["enabled"],
                    "exploit_generation": config["ai_features"][
                        "generate_exploit_code"
                    ],
                    "attack_chains": config["ai_features"]["attack_chains"]["enabled"],
                },
                "configuration": {
                    "exploitation_enabled": config["exploitation"]["enabled"],
                    "safe_mode": config["exploitation"]["safe_mode"],
                    "waf_evasion": config["evasion"]["enabled"],
                },
            }
        ),
        200,
    )


@app.route("/reports/<path:filepath>")
def download_report(filepath):
    """Serve report files for download"""
    try:
        # Security: Prevent path traversal
        if ".." in filepath or filepath.startswith("/"):
            return jsonify({"error": "Invalid file path"}), 400

        # Construct safe file path
        file_path = os.path.join("reports", filepath)

        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify({"error": "Report file not found"}), 404

        # Determine mimetype
        if filepath.endswith(".json"):
            mimetype = "application/json"
        elif filepath.endswith(".md"):
            mimetype = "text/markdown"
        else:
            mimetype = "application/octet-stream"

        # Send file
        return send_file(file_path, mimetype=mimetype, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _calculate_severity_distribution(vulnerabilities):
    """Calculate severity distribution"""
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Info")
        if severity in distribution:
            distribution[severity] += 1
    return distribution


if __name__ == "__main__":
    print("=" * 80)
    print(" " * 15 + "AI-POWERED WEB SECURITY SCANNER v3.0")
    print("=" * 80)
    print("  Server running at: http://localhost:5000")
    print("  Press CTRL+C to stop the server")
    print("-" * 80)
    print("  Available Modules:")
    print("    ✓ Passive Reconnaissance")
    print("    ✓ Passive Vulnerability Scanner")
    print("    ✓ Active Security Probing")
    print("    ✓ Web Crawler & Attack Surface Discovery")
    print("    ✓ Authentication & Session Testing")
    print("    ✓ Advanced Authentication Bypass")
    print("    ✓ Exploit Executor")
    print("    ✓ Attack Chain Builder")
    print("    ✓ AI-Powered Analysis (Ollama)")
    print("    ✓ Intelligent Payload Generator")
    print("    ✓ Adaptive WAF Evasion")
    print("    ✓ Comprehensive Report Generation")
    print("=" * 80)
    print("\n  API Endpoints:")
    print("    POST /api/scan - Run comprehensive scan")
    print("    POST /api/ai-analyze - AI vulnerability analysis")
    print("    POST /api/exploit - Execute specific exploit")
    print("    POST /api/attack-chain - Build/execute attack chains")
    print("    POST /api/generate-payloads - Generate AI payloads")
    print("    POST /api/adaptive-evade - Generate evasion variants")
    print("    GET  /api/health - Health check")
    print("    GET  /api/scan-status/<id> - Get scan status")
    print("=" * 80)

    # Check if Ollama is running
    try:
        ollama_client = OllamaClient(base_url=config["ollama"]["base_url"])
        if ollama_client.check_health():
            print("\n  🤖 Ollama AI: CONNECTED")
            print(f"     Models: {', '.join(config['ollama']['models'].values())}")
        else:
            print("\n  ⚠️  Ollama AI: NOT CONNECTED")
            print("     Run 'ollama serve' to enable AI features")
    except:
        print("\n  ⚠️  Ollama AI: NOT AVAILABLE")

    print("\n" + "=" * 80 + "\n")

    app.run(
        debug=config["app"]["debug"],
        host=config["app"]["host"],
        port=config["app"]["port"],
    )
