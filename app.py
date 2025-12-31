"""
Flask Web Application - Security Scanner Backend
"""

from flask import Flask, render_template, request, jsonify
import traceback
from modules.passive_recon import PassiveRecon
from modules.passive_vuln_scanner import PassiveVulnScanner
from modules.active_probe import ActiveProbe
from modules.report_generator import ReportGenerator

app = Flask(__name__)

# Store scan results temporarily
scan_results = {}


@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Initialize and run security scan"""
    try:
        data = request.get_json()
        target_url = data.get('target_url', '').strip()
        scan_type = data.get('scan_type', 'full')  # 'passive' or 'full'
        
        # Validation
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        if not target_url.startswith(('http://', 'https://')):
            return jsonify({'error': 'URL must start with http:// or https://'}), 400
        
        # Initialize results
        results = {
            'target': target_url,
            'scan_type': scan_type,
            'status': 'running',
            'progress': []
        }
        
        # Phase 1: Passive Reconnaissance
        results['progress'].append('Starting passive reconnaissance...')
        recon = PassiveRecon(target_url)
        recon_results = recon.run_all_checks()
        results['recon'] = recon_results
        results['progress'].append('Passive reconnaissance completed')
        
        # Phase 2: Passive Vulnerability Scanning
        results['progress'].append('Starting passive vulnerability scan...')
        passive_scanner = PassiveVulnScanner(recon_results)
        passive_vulns = passive_scanner.run_all_checks()
        results['passive_vulnerabilities'] = passive_vulns
        results['progress'].append('Passive vulnerability scan completed')
        
        # Phase 3: Active Probing (if full scan)
        active_vulns = {'vulnerabilities': []}
        if scan_type == 'full':
            results['progress'].append('Starting active probing...')
            active_scanner = ActiveProbe(target_url)
            active_vulns = active_scanner.run_all_checks()
            results['active_vulnerabilities'] = active_vulns
            results['progress'].append('Active probing completed')
        
        # Phase 4: Generate Reports
        results['progress'].append('Generating reports...')
        report_gen = ReportGenerator(
            target_url,
            recon_results,
            passive_vulns,
            active_vulns
        )
        report_paths = report_gen.generate_all_reports()
        results['reports'] = report_paths
        results['progress'].append('Reports generated')
        
        # Calculate summary
        all_vulns = []
        if 'vulnerabilities' in passive_vulns:
            all_vulns.extend(passive_vulns['vulnerabilities'])
        if 'vulnerabilities' in active_vulns:
            all_vulns.extend(active_vulns['vulnerabilities'])
        
        severity_count = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in all_vulns:
            severity = vuln['severity']
            if severity in severity_count:
                severity_count[severity] += 1
        
        results['summary'] = {
            'total_vulnerabilities': len(all_vulns),
            'severity_distribution': severity_count,
            'vulnerabilities': all_vulns
        }
        
        results['status'] = 'completed'
        results['progress'].append('Scan completed successfully')
        
        return jsonify(results), 200
        
    except Exception as e:
        error_trace = traceback.format_exc()
        return jsonify({
            'error': str(e),
            'traceback': error_trace,
            'status': 'failed'
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Web Security Scanner'
    }), 200


if __name__ == '__main__':
    print("=" * 60)
    print("Web Security Scanner - Starting Server")
    print("=" * 60)
    print("Server running at: http://localhost:5000")
    print("Press CTRL+C to stop")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5005)