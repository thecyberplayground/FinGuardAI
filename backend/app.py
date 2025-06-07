from flask import Flask, request, jsonify
import subprocess
import threading
import os
import sys
from flask import Flask, jsonify, make_response
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import eventlet
from eventlet import greenthread
import shlex
import sqlite3
import re
import psutil
import json
import datetime
import pandas as pd
import numpy as np
import random

# Add ML directory to path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ml'))

# Import our threat detection model
try:
    from ml.threat_model import NetworkThreatDetector
    threat_detector = NetworkThreatDetector()
    HAS_ML = True
    print("[INFO] ML-based threat detection model loaded successfully!", flush=True)
except ImportError as e:
    print(f"[WARNING] ML threat detection not available: {e}", flush=True)
    HAS_ML = False

# NVD API client
try:
    from nvd.client import NVDClient
    nvd_client = NVDClient()
    HAS_NVD_CLIENT = True
    print("[INFO] NVD API client loaded successfully!", flush=True)
except ImportError as e:
    print(f"[WARNING] NVD API client not available: {e}", flush=True)
    HAS_NVD_CLIENT = False

# Environment configuration defaults
ENV_CONFIGS = {
    "dev": {
        "ports": "1-1000,8080-8090",
        "scan_type": "basic",
        "format": "json"
    },
    "test": {
        "ports": "1-5000,8000-9000",
        "scan_type": "basic",
        "format": "json"
    },
    "prod": {
        "ports": "1-1000,20-25,80,443,8080,3306,5432",
        "scan_type": "basic",
        "format": "json"
    }
}

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our ML-based threat detection modules
try:
    from ml.detect_threats import get_detector, detect_threats_in_tshark_output
    from ml.train_model import initialize_model
    from ml.nvd_threat_detector import NVDThreatDetector
    HAS_ML_MODULES = True
    print("[INFO] ML-based threat detection modules loaded successfully!", flush=True)
    
    # Import remediation module if available
    try:
        from ml.remediation import get_recommendations_for_threat
        HAS_REMEDIATION = True
        print("[INFO] Security remediation recommendation system loaded successfully!", flush=True)
    except ImportError as e:
        print(f"[WARNING] Remediation module not available: {e}. Running without security recommendations.", flush=True)
        HAS_REMEDIATION = False
except ImportError as e:
    print(f"[WARNING] ML modules not available: {e}. Running without ML threat detection.", flush=True)
    HAS_ML_MODULES = False
    HAS_REMEDIATION = False

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Import the scan bridge for integrated scanning
try:
    from scan_bridge import run_integrated_scan, get_scan_environments
    HAS_INTEGRATED_SCAN = True
    print("[INFO] Integrated scanning bridge loaded successfully!", flush=True)
except ImportError as e:
    print(f"[WARNING] Integrated scanning bridge not available: {e}", flush=True)
    HAS_INTEGRATED_SCAN = False

# Run Nmap scan in a separate thread
def run_nmap_scan(target, scan_type):
    if scan_type == 'basic':
        cmd = ["nmap", "-sS", target]
    elif scan_type == 'deep':
        cmd = ["nmap", "-A", target]
    else:
        return "Invalid scan type"
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=120)
        return result
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as ex:
        return str(ex)

@app.route('/scan/nmap', methods=['POST'])
def nmap_scan():
    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scan_type', 'basic')
    if not target:
        return jsonify({"error": "Target is required"}), 400
    def scan_thread():
        result = run_nmap_scan(target, scan_type)
        with open(f"nmap_{target}.txt", "w") as f:
            f.write(result)
    threading.Thread(target=scan_thread).start()
    return jsonify({"status": "Scan started", "target": target, "scan_type": scan_type})

@app.route('/scan/nmap/result', methods=['GET'])
def nmap_scan_result():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Target is required"}), 400
    try:
        with open(f"nmap_{target}.txt", "r") as f:
            result = f.read()
        return jsonify({"result": result})
    except FileNotFoundError:
        return jsonify({"status": "Scan not finished or target not found"}), 404

@app.route('/environment/config', methods=['GET'])
def get_environment_configs():
    """Endpoint to retrieve all environment configurations
    
    Returns a dictionary of environment configurations for dev, test, and prod environments
    """
    # Return the predefined environment configurations
    return jsonify(ENV_CONFIGS)

@app.route('/reports', methods=['GET'])
def get_reports():
    """Endpoint to retrieve all scan reports
    
    Optional query parameter:
    - timeframe: Filter by timeframe (e.g., 'week', 'month', 'year')
    """
    timeframe = request.args.get('timeframe')
    
    # Define reports directory and ensure it exists
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
    os.makedirs(report_dir, exist_ok=True)
    
    reports = []
    
    # Look for JSON reports in the reports directory
    json_reports = [f for f in os.listdir(report_dir) if f.endswith('.json') and not f.startswith('.')]
    
    for report_file in json_reports:
        try:
            with open(os.path.join(report_dir, report_file), 'r') as f:
                report_data = json.load(f)
                
                # Extract report metadata
                report_id = report_data.get('scan_id', os.path.splitext(report_file)[0])
                target = report_data.get('target', 'Unknown')
                vulnerabilities = report_data.get('vulnerabilities', [])
                scan_date = report_data.get('scan_time', None)
                
                if scan_date is None:
                    # Try to extract date from filename (format: target_YYYYMMDD_HHMMSS)
                    date_parts = report_id.split('_')[-2:]
                    if len(date_parts) >= 2 and len(date_parts[0]) == 8:
                        # Format: YYYYMMDD_HHMMSS
                        date_str = f"{date_parts[0][:4]}-{date_parts[0][4:6]}-{date_parts[0][6:8]}"
                        time_str = f"{date_parts[1][:2]}:{date_parts[1][2:4]}:{date_parts[1][4:6]}"
                        scan_date = f"{date_str}T{time_str}"
                    else:
                        # Use file modification time as fallback
                        file_mtime = os.path.getmtime(os.path.join(report_dir, report_file))
                        scan_date = datetime.datetime.fromtimestamp(file_mtime).isoformat()
                
                # Determine severity based on vulnerabilities
                severity = "low"
                if any(v.get('severity', '').lower() == 'critical' for v in vulnerabilities):
                    severity = "critical"
                elif any(v.get('severity', '').lower() == 'high' for v in vulnerabilities):
                    severity = "high"
                elif any(v.get('severity', '').lower() == 'medium' for v in vulnerabilities):
                    severity = "medium"
                
                # Get environment from report or fallback to 'prod'
                environment = report_data.get('environment', 'prod')
                
                # Build report object
                report = {
                    "id": report_id,
                    "target": target,
                    "date": scan_date,
                    "severity": severity,
                    "vulnerabilities_count": len(vulnerabilities),
                    "environment": environment,
                    "report_path": os.path.join('reports', os.path.splitext(report_file)[0] + '.html'),
                    "scan_id": report_id
                }
                reports.append(report)
        except Exception as e:
            print(f"[ERROR] Failed to process report {report_file}: {e}", flush=True)
    
    # Sort reports by date (most recent first)
    reports.sort(key=lambda x: x.get('date', ''), reverse=True)
    
    # Filter by timeframe if specified
    if timeframe:
        now = datetime.datetime.now()
        reports = [r for r in reports if _is_within_timeframe(r.get('date', ''), timeframe, now)]
    
    return jsonify(reports)

@app.route('/reports/<report_id>', methods=['GET'])
def get_report_detail(report_id):
    """Endpoint to retrieve details for a specific report"""
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
    
    # Check if format parameter is specified
    format_type = request.args.get('format', 'json')
    
    # Handle HTML report format request
    if format_type == 'html':
        # Look for HTML report file
        html_file = os.path.join(report_dir, f"{report_id}.html")
        if not os.path.exists(html_file):
            # Try to find any HTML file containing the report_id
            html_files = [f for f in os.listdir(report_dir) if f.endswith('.html') and report_id in f]
            if not html_files:
                return jsonify({"error": "HTML report not found"}), 404
            html_file = os.path.join(report_dir, html_files[0])
        
        try:
            with open(html_file, 'r', encoding='utf-8') as f:
                report_html = f.read()
            return report_html, 200, {'Content-Type': 'text/html'}
        except Exception as e:
            print(f"Error reading HTML report: {e}")
            return jsonify({"error": f"Failed to read HTML report: {str(e)}"}), 500
    
    # Default: Handle JSON report format
    json_file = os.path.join(report_dir, f"{report_id}.json")
    if not os.path.exists(json_file):
        # Try to find any JSON file containing the report_id
        json_files = [f for f in os.listdir(report_dir) if f.endswith('.json') and report_id in f]
        if not json_files:
            return jsonify({"error": "Report not found"}), 404
        json_file = os.path.join(report_dir, json_files[0])
    
    try:
        with open(json_file, 'r') as f:
            report_data = json.load(f)
        
        # Extract key details
        target = report_data.get('target', 'Unknown')
        scan_date = report_data.get('scan_time', None) or datetime.datetime.now().isoformat()
        vulnerabilities = report_data.get('vulnerabilities', [])
        environment = report_data.get('environment', 'prod')
        
        # Count vulnerabilities by severity
        critical_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'high')
        medium_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'medium')
        low_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'low')
        
        # Determine overall severity
        severity = "low"
        if critical_count > 0:
            severity = "critical"
        elif high_count > 0:
            severity = "high"
        elif medium_count > 0:
            severity = "medium"
        
        # Estimate fix time based on vulnerability counts
        estimated_fix_time = f"{critical_count * 4 + high_count * 2 + medium_count}h"
        
        # Estimate financial impact based on severity
        impact_factors = {
            "critical": 100000,
            "high": 25000,
            "medium": 5000,
            "low": 1000
        }
        estimated_financial_impact = sum(impact_factors.get(v.get('severity', 'low').lower(), 0) for v in vulnerabilities)
        
        # Create report detail object
        report_detail = {
            "id": report_id,
            "target": target,
            "date": scan_date,
            "severity": severity,
            "environment": environment,
            "scan_id": report_id,
            "vulnerabilities": vulnerabilities,
            "summary": {
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "total_count": len(vulnerabilities),
                "estimated_fix_time": estimated_fix_time,
                "estimated_financial_impact": estimated_financial_impact
            }
        }
        
        return jsonify(report_detail)
    except Exception as e:
        print(f"[ERROR] Failed to process report {report_id}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to process report: {str(e)}"}), 500

@app.route('/reports/<report_id>/export', methods=['GET'])
def export_report(report_id):
    """Endpoint to export a report in a specific format"""
    format = request.args.get('format', 'json')
    
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
    
    # Try to find the report file
    json_file = os.path.join(report_dir, f"{report_id}.json")
    if not os.path.exists(json_file):
        json_files = [f for f in os.listdir(report_dir) if f.endswith('.json') and report_id in f]
        if not json_files:
            return jsonify({"error": "Report not found"}), 404
        json_file = os.path.join(report_dir, json_files[0])
    
    try:
        # For JSON format, just return the file contents
        if format.lower() == 'json':
            with open(json_file, 'r') as f:
                report_data = json.load(f)
            return jsonify(report_data)
        
        # For PDF, check if HTML version exists and convert
        elif format.lower() == 'pdf':
            html_file = os.path.splitext(json_file)[0] + '.html'
            if os.path.exists(html_file):
                # Return HTML for now (PDF generation would be added in production)
                with open(html_file, 'r') as f:
                    html_content = f.read()
                response = make_response(html_content)
                response.headers["Content-Type"] = "text/html"
                response.headers["Content-Disposition"] = f"attachment; filename=report_{report_id}.html"
                return response
            else:
                return jsonify({"error": "HTML report not found"}), 404
        
        # For CSV, convert JSON to CSV format
        elif format.lower() == 'csv':
            with open(json_file, 'r') as f:
                report_data = json.load(f)
            
            # Extract vulnerabilities for CSV
            vulnerabilities = report_data.get('vulnerabilities', [])
            if not vulnerabilities:
                return jsonify({"error": "No vulnerability data to export"}), 404
            
            # Create CSV content
            csv_content = "Severity,Name,Description,CVE ID,Affected Component,Recommendation\n"
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                name = vuln.get('name', 'Unknown')
                description = vuln.get('description', '').replace('"', '""')
                cve_id = vuln.get('cve_id', 'N/A')
                affected_component = vuln.get('affected_component', 'Unknown')
                remediation = vuln.get('remediation', 'N/A').replace('"', '""')
                
                csv_content += f"{severity},"
                csv_content += f"\"{name}\","
                csv_content += f"\"{description}\","
                csv_content += f"{cve_id},"
                csv_content += f"\"{affected_component}\","
                csv_content += f"\"{remediation}\"\n"
            
            response = make_response(csv_content)
            response.headers["Content-Type"] = "text/csv"
            response.headers["Content-Disposition"] = f"attachment; filename=report_{report_id}.csv"
            return response
        else:
            return jsonify({"error": f"Unsupported export format: {format}"}), 400
    except Exception as e:
        print(f"[ERROR] Failed to export report {report_id}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to export report: {str(e)}"}), 500

@app.route('/remediation/<vulnerability_id>', methods=['GET'])
def get_remediation(vulnerability_id):
    """Endpoint to get remediation recommendations for a vulnerability"""
    detailed = request.args.get('detailed', 'false').lower() == 'true'
    
    try:
        # Extract CVE ID if present in vulnerability_id
        cve_match = re.search(r'CVE-\d{4}-\d+', vulnerability_id)
        cve_id = cve_match.group(0) if cve_match else None
        
        # If we have a CVE ID, get real data from NVD
        if cve_id:
            try:
                # Import NVDClient dynamically to avoid circular imports
                from ml.remediation.nvd_client import NVDClient
                
                print(f"[INFO] Fetching NVD remediation data for {cve_id}")
                nvd_client = NVDClient()
                recommendation = nvd_client.get_remediation_info(cve_id)
                
                print(f"[INFO] Retrieved remediation info for {cve_id}")
                return jsonify(recommendation)
                
            except Exception as e:
                print(f"[WARNING] Error fetching NVD data: {e}. Falling back to type-based remediation.")
                # Continue with fallback approach
        
        # Determine vulnerability type based on ID or name for fallback
        vuln_type = "unknown"
        if "sql" in vulnerability_id.lower():
            vuln_type = "sql_injection"
        elif "xss" in vulnerability_id.lower():
            vuln_type = "cross_site_scripting"
        elif "csrf" in vulnerability_id.lower():
            vuln_type = "csrf"
        elif "overflow" in vulnerability_id.lower():
            vuln_type = "buffer_overflow"
        elif "injection" in vulnerability_id.lower():
            vuln_type = "injection"
        elif "auth" in vulnerability_id.lower() or "login" in vulnerability_id.lower():
            vuln_type = "authentication"
        elif "dos" in vulnerability_id.lower() or "denial" in vulnerability_id.lower():
            vuln_type = "denial_of_service"
        
        # Generate specific recommendation based on vulnerability type
        recommendation = {
            "id": f"rec_{vulnerability_id}",
            "vulnerability_id": vulnerability_id,
            "difficulty": "medium",
            "estimated_time": "4h",
            "priority": "high",
            "cost_of_inaction": 25000
        }
        
        # Customize recommendation based on vulnerability type
        if vuln_type == "sql_injection":
            recommendation["recommendation"] = "Implement prepared statements and parameterized queries. Use an ORM framework if possible."
            recommendation["code_example"] = "# Instead of:\nquery = f'SELECT * FROM users WHERE username = \'{username}\''\n\n# Use parameterized query:\nquery = 'SELECT * FROM users WHERE username = ?'\ncursor.execute(query, (username,))"
            
        elif vuln_type == "cross_site_scripting":
            recommendation["recommendation"] = "Use context-appropriate output encoding and implement Content-Security-Policy headers."
            recommendation["code_example"] = "// Encode output before rendering:\nconst safeValue = encodeHTML(userInput);\n\n// Set CSP header:\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: [\"'self'\"],\n    scriptSrc: [\"'self'\", 'trusted-cdn.com']\n  }\n}));"
            
        elif vuln_type == "csrf":
            recommendation["recommendation"] = "Implement anti-CSRF tokens in all forms and state-changing operations."
            recommendation["code_example"] = "// Generate CSRF token for user session\napp.use(csrfProtection);\n\n// In form:\n<input type=\"hidden\" name=\"_csrf\" value=\"{{ csrfToken }}\">\n\n// Validate on submission\napp.post('/api/data', csrfProtection, function(req, res) { ... });"
            
        elif vuln_type == "buffer_overflow":
            recommendation["recommendation"] = "Use safe string handling functions and bounds checking. Consider memory-safe languages where possible."
            recommendation["code_example"] = "// Instead of:\nchar buffer[10];\nstrcpy(buffer, userInput); // Dangerous!\n\n// Use:\nchar buffer[10];\nstrncpy(buffer, userInput, sizeof(buffer) - 1);\nbuffer[sizeof(buffer) - 1] = '\\0'; // Ensure null termination"
            
        elif vuln_type == "injection":
            recommendation["recommendation"] = "Validate all inputs, use allowlists for permitted values, and sanitize data before processing."
            recommendation["code_example"] = "// Validate input against allowlist\nconst allowedValues = ['option1', 'option2', 'option3'];\nif (!allowedValues.includes(userInput)) {\n  return res.status(400).send('Invalid input');\n}\n\n// For command execution, use safer alternatives\nexec('ls ' + userDir); // DANGEROUS\nexec('ls', [userDir]); // SAFER"
            
        elif vuln_type == "authentication":
            recommendation["recommendation"] = "Implement multi-factor authentication and use secure password hashing algorithms (bcrypt/Argon2)."
            recommendation["code_example"] = "// Use a proper password hashing library\nconst bcrypt = require('bcrypt');\n\n// Hashing password\nconst hashedPassword = await bcrypt.hash(password, 10);\n\n// Verifying password\nconst isValid = await bcrypt.compare(password, hashedPassword);"
            
        elif vuln_type == "denial_of_service":
            recommendation["recommendation"] = "Implement rate limiting, request throttling, and resource allocation limits."
            recommendation["code_example"] = "// Implement rate limiting\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 100, // limit each IP to 100 requests per windowMs\n  message: 'Too many requests from this IP, please try again later'\n});\n\n// Apply to all requests\napp.use(limiter);"
            
        else:
            # Default generic recommendation
            recommendation["recommendation"] = "Update affected components to the latest secure version. Implement a vulnerability scanning and patch management process."
            recommendation["code_example"] = "# Example code for patching\nimport security_patch\n\npatch = security_patch.get_latest()\npatch.apply()"
        
        # Add detailed information if requested
        if detailed and cve_id and not "references" in recommendation:
            recommendation["references"] = [
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            ]
        
        return jsonify(recommendation)
    except Exception as e:
        print(f"[ERROR] Failed to get remediation for {vulnerability_id}: {e}", flush=True)
        return jsonify({"error": f"Failed to get remediation: {str(e)}"}), 500

# Helper function for timeframe filtering
def _is_within_timeframe(date_str, timeframe, now):
    """Check if a date string is within the specified timeframe"""
    if not date_str:
        return False
    
    try:
        # Parse ISO format date
        date = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        
        # Calculate the difference
        if timeframe == 'day':
            return (now - date).days < 1
        elif timeframe == 'week':
            return (now - date).days < 7
        elif timeframe == 'month':
            return (now - date).days < 30
        elif timeframe == 'year':
            return (now - date).days < 365
        else:
            return True  # Default to include all
    except Exception:
        return False  # If date parsing fails, exclude the report

@app.route('/scan/integrated', methods=['POST'])
def integrated_scan():
    """Endpoint for comprehensive integrated scanning using scan_bridge"""
    if not HAS_INTEGRATED_SCAN:
        return jsonify({
            "error": "Integrated scanning not available. Check server logs."
        }), 500
        
    data = request.get_json()
    if not data or not data.get('target'):
        return jsonify({"error": "Target is required"}), 400
        
    target = data.get('target')
    scan_options = {
        "ports": data.get('ports'),
        "intensity": data.get('intensity', 'normal'),
        "format": data.get('format', 'json')
    }
    env = data.get('env', 'prod')
    
    # Run the scan asynchronously
    def run_scan_thread():
        results = run_integrated_scan(target, scan_options, env)
        # Store results for later retrieval
        scan_id = f"integrated_{target}_{int(time.time())}"
        result_path = f"integrated_{scan_id}.json"
        with open(result_path, 'w') as f:
            json.dump(results, f)
        # Emit completion event via Socket.IO
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'target': target,
            'status': results['status'],
            'result_path': result_path
        })
    
    thread = threading.Thread(target=run_scan_thread)
    thread.start()
    
    return jsonify({
        "status": "Scan started",
        "target": target,
        "env": env,
        "message": "Check scan progress via Socket.IO or /scan/integrated/status endpoint"
    })

@app.route('/scan/integrated/status', methods=['GET'])
def integrated_scan_status():
    """Check status of integrated scans"""
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Target is required"}), 400
        
    # Find all result files for this target
    import glob
    result_files = glob.glob(f"integrated_{target}_*.json")
    
    if not result_files:
        return jsonify({"status": "No scan results found"}), 404
        
    # Get the most recent result
    latest_file = max(result_files, key=os.path.getctime)
    
    try:
        with open(latest_file, 'r') as f:
            result = json.load(f)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Error reading scan results: {str(e)}"}), 500
        
@app.route('/environment/config', methods=['GET'])
def environment_config():
    """Get available scan environments and their configurations"""
    if not HAS_INTEGRATED_SCAN:
        return jsonify({"error": "Environment configuration not available"}), 500
        
    environments = get_scan_environments()
    return jsonify(environments)

@socketio.on('start_scan')
def handle_start_scan(data):
    """Handle integrated scan requests from the frontend"""
    target = data.get('target')
    scan_type = data.get('scan_type', 'basic')
    env = data.get('env', 'prod')  # Environment context (dev, test, prod)
    
    if not target:
        emit('scan_output', {
            'line': 'Error: Target is required.',
            'phase': 'Initialization',
            'phase_status': 'failed'
        })
        return
    
    # Log the start of the scan
    print(f"[SCAN] Starting integrated scan of {target} (type: {scan_type}, env: {env})", flush=True)
    
    # Emit initial phase status
    emit('scan_output', {
        'line': f"Initializing scan for {target}...",
        'phase': 'Initialization',
        'phase_status': 'in_progress',
        'phase_progress': 10,
        'progress': 5
    })
    
    # Load environment-specific scan configuration
    try:
        config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config')
        config_file = os.path.join(config_dir, f"{env}.json")
        scan_config = {}
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                scan_config = json.load(f)
            print(f"[SCAN] Loaded configuration from {config_file}", flush=True)
            emit('scan_output', {
                'line': f"Using {env} environment configuration",
                'phase': 'Initialization',
                'phase_progress': 50
            })
    except Exception as e:
        print(f"[WARNING] Error loading config from {config_file}: {e}", flush=True)
        emit('scan_output', {
            'line': f"Warning: Could not load environment config. Using defaults. Error: {str(e)}",
            'phase': 'Initialization',
            'phase_progress': 30
        })
        scan_config = {}
    
    # Set scan parameters based on environment and scan type
    ports = scan_config.get('ports', "1-1000,3306,5432,8080-8090,27017,21,22,23,25,53")
    intensity = scan_config.get('intensity', "normal")
    
    # Prepare command based on scan type and environment
    import platform
    is_windows = platform.system().lower().startswith('win')
    
    # Emit phase completion for initialization
    emit('scan_output', {
        'line': f"Initialization complete. Starting port scanning...",
        'phase': 'Initialization',
        'phase_status': 'completed',
        'phase_progress': 100,
        'progress': 10,
        'phase': 'Port Scanning',
        'phase_status': 'in_progress',
        'phase_progress': 0
    })
    
    # Create a timestamp-based scan ID
    from datetime import datetime
    
    # Sanitize target for safe filename - remove http:// or https:// and replace invalid chars
    sanitized_target = target
    original_target = target
    
    # Clean target for nmap (remove http/https prefix)
    for prefix in ['http://', 'https://']:
        if target.startswith(prefix):
            target = target[len(prefix):]
            break
            
    # Also sanitize for filename
    for prefix in ['http://', 'https://']:
        if sanitized_target.startswith(prefix):
            sanitized_target = sanitized_target[len(prefix):]
            break
    
    # Replace other invalid filename characters
    sanitized_target = sanitized_target.replace('.', '_').replace('/', '_').replace('\\', '_')
    sanitized_target = sanitized_target.replace(':', '_').replace('?', '_').replace('&', '_')
    
    scan_id = f"{sanitized_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    xml_output = os.path.join("reports", f"{scan_id}_scan.xml")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    
    # Build command based on scan type and settings
    if scan_type == 'basic':
        cmd = ["nmap", "-sS", "-v", "-oX", xml_output, "-p", ports, target]
    elif scan_type == 'deep':
        cmd = ["nmap", "-A", "-vv", "--script=vuln,auth,default", "--stats-every", "2s", "-oX", xml_output, "-p", ports, target]
    else:
        emit('scan_output', {
            'line': 'Error: Invalid scan type.',
            'phase': 'Port Scanning',
            'phase_status': 'failed'
        })
        return
    
    # Add stdbuf for non-Windows platforms
    if not is_windows:
        cmd = ["stdbuf", "-oL"] + cmd
    
    # Run the scan process
    try:
        # Import the vulnerability scanner for result processing
        sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'integrated_system'))
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        try:
            # Try importing from integrated_system package
            from integrated_system.vulnerability_scanner import VulnerabilityScanner
            from integrated_system.nvd_scanner import NVDVulnerabilityScanner
            from integrated_system.enhanced_report import EnhancedReportGenerator
        except ImportError:
            # Fall back to direct import
            from vulnerability_scanner import VulnerabilityScanner
            from nvd_scanner import NVDVulnerabilityScanner
            from enhanced_report import EnhancedReportGenerator
        
        print(f"[SCAN] Running command: {' '.join(cmd)}", flush=True)
        
        # Start the scan process
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True
        )
        
        # Process and emit scan output
        with open(os.path.join(report_dir, f"nmap_{scan_id}.txt"), "w") as f:
            for line in iter(proc.stdout.readline, ''):
                f.write(line)
                
                # Extract progress information
                percent_match = re.search(r"Stats: (\d+)% done;", line)
                if percent_match:
                    port_scan_percent = int(percent_match.group(1))
                    # Map port scan percent to overall progress (port scanning is ~30% of total)
                    overall_progress = 10 + (port_scan_percent * 0.3)
                    
                    emit('scan_output', {
                        'line': line,
                        'progress': overall_progress,
                        'phase': 'Port Scanning',
                        'phase_progress': port_scan_percent
                    })
                else:
                    emit('scan_output', {'line': line})
                    
                socketio.sleep(0)  # Yield to allow other events
                
            proc.stdout.close()
            proc.wait()
        
        # Port scanning complete, move to vulnerability detection
        emit('scan_output', {
            'line': 'Port scanning complete. Processing vulnerability data...',
            'progress': 40,
            'phase': 'Port Scanning',
            'phase_status': 'completed',
            'phase_progress': 100,
            'phase': 'Vulnerability Detection',
            'phase_status': 'in_progress',
            'phase_progress': 0
        })
        
        # Process scan results using NVDVulnerabilityScanner
        try:
            # Using the NVD-enhanced vulnerability scanner instead of the original
            scanner = NVDVulnerabilityScanner(output_dir=report_dir)
            
            # Parse the XML output
            emit('scan_output', {
                'line': 'Analyzing scan results for vulnerabilities...',
                'phase': 'Vulnerability Detection',
                'phase_progress': 30,
                'progress': 50
            })
            
            scan_results = scanner._parse_nmap_output(xml_output)
            scan_results["scan_id"] = scan_id
            scan_results["target"] = target
            scan_results["scan_time"] = datetime.now().isoformat()
            
            # Extract vulnerabilities
            vulnerabilities = scan_results.get("vulnerabilities", [])
            
            emit('scan_output', {
                'line': f"Found {len(vulnerabilities)} potential vulnerabilities",
                'phase': 'Vulnerability Detection',
                'phase_progress': 100,
                'phase_status': 'completed',
                'progress': 60,
                'phase': 'NVD Processing',
                'phase_status': 'in_progress',
                'phase_progress': 0
            })
            
            # Emit vulnerability data as a separate event
            emit('vulnerability_data', {
                'vulnerabilities': vulnerabilities
            })
            
            # Use NVD-based threat detection instead of ML model
            try:
                emit('scan_output', {
                    'line': 'Processing vulnerabilities with NVD data...',
                    'phase': 'NVD Processing',
                    'phase_progress': 20,
                    'progress': 65
                })
                
                # Process the scan results with our NVD threat detector
                nvd_detector = NVDThreatDetector()
                enhanced_results = nvd_detector.detect_threats_from_scan_result(scan_results)
                
                # Update the vulnerabilities with NVD-enhanced data
                if enhanced_results and 'vulnerabilities' in enhanced_results:
                    vulnerabilities = enhanced_results.get('vulnerabilities', [])
                    scan_results['vulnerabilities'] = vulnerabilities
                    
                    if 'risk_score' in enhanced_results:
                        scan_results['risk_score'] = enhanced_results['risk_score']
                
                # Add remediation recommendations directly from NVD data
                for vuln in vulnerabilities:
                    # Ensure each vulnerability has a recommendation field from NVD
                    if not vuln.get('recommendation') and not vuln.get('remediation'):
                        # Get CVE ID if available
                        cve_id = vuln.get('cve_id')
                        if cve_id:
                            try:
                                # Try to get NVD remediation data
                                remediation = scanner.get_nvd_remediation(cve_id)
                                if remediation:
                                    vuln['remediation'] = remediation
                                    # Also set recommendation to same value for consistency
                                    vuln['recommendation'] = remediation
                            except Exception as e:
                                print(f"[NVD] Error getting remediation for {cve_id}: {e}", flush=True)
                        
                        # If no CVE-specific remediation, provide generic guidance based on vulnerability type
                        if not vuln.get('remediation') and not vuln.get('recommendation'):
                            vuln_type = vuln.get('name', '').lower()
                            # Provide realistic, security-focused remediation advice based on vulnerability type
                            if 'outdated' in vuln_type or 'version' in vuln_type:
                                vuln['remediation'] = "Update the affected service to the latest secure version and implement a regular patch management schedule."
                            elif 'ssl' in vuln_type or 'tls' in vuln_type:
                                vuln['remediation'] = "Configure the server to use only strong encryption protocols (TLS 1.2+) and disable obsolete protocols and ciphers."
                            elif 'authentication' in vuln_type or 'password' in vuln_type:
                                vuln['remediation'] = "Implement strong authentication mechanisms including multi-factor authentication and password complexity requirements."
                            elif 'xss' in vuln_type or 'script' in vuln_type:
                                vuln['remediation'] = "Implement input validation, output encoding, and Content Security Policy (CSP) headers to prevent cross-site scripting."
                            elif 'sql' in vuln_type or 'injection' in vuln_type:
                                vuln['remediation'] = "Use parameterized queries and prepared statements to prevent SQL injection attacks."
                            else:
                                vuln['remediation'] = "Review the affected service configuration, apply security hardening guidelines, and limit network exposure of the service."
                            
                            # Also set recommendation to same value for consistency
                            vuln['recommendation'] = vuln['remediation']
                
                emit('scan_output', {
                    'line': 'NVD vulnerability processing complete',
                    'phase': 'NVD Processing',
                    'phase_progress': 100,
                    'phase_status': 'completed',
                    'progress': 80,
                    'nvd_processing_complete': True,
                    'risk_score': scan_results.get('risk_score', 0)
                })
                
                # Use ML model to process vulnerabilities
                try:
                    # Import ML threat detector
                    from ml.detect_threats import ThreatDetector
                    
                    # Initialize the threat detector
                    threat_detector = ThreatDetector()
                    
                    # Process threats based on scan results
                    ml_results = threat_detector.process_scan_results(scan_results)
                    
                    # Extract ML predictions if available
                    if ml_results and 'predictions' in ml_results and ml_results['predictions']:
                        # Emit ML predictions as a separate event
                        emit('ml_results', {
                            'predictions': ml_results['predictions']
                        })
                        
                        # If financial impact is available from ML model, emit it
                        if 'financial_impact' in ml_results and ml_results['financial_impact']:
                            emit('ml_results', {
                                'financial_impact': ml_results['financial_impact']
                            })
                except Exception as ml_ex:
                    print(f"[ERROR] ML processing failed: {ml_ex}", flush=True)
                    import traceback
                    traceback.print_exc()
            except Exception as e:
                emit('scan_output', {
                    'line': 'NVD processing failed (modules not available)',
                    'phase': 'NVD Processing',
                    'phase_progress': 100,
                    'phase_status': 'completed',
                    'progress': 80
                })
            
            # Generate report
            emit('scan_output', {
                'line': 'Generating comprehensive report...',
                'phase': 'Report Generation',
                'phase_status': 'in_progress',
                'phase_progress': 10,
                'progress': 85
            })
            
            report_generator = EnhancedReportGenerator(report_dir=report_dir, env=env)
            report_path = report_generator.generate_report(
                scan_results, 
                target=target,
                report_format="html"
            )
            
            # Create JSON report for dashboard
            json_report_path = report_generator._generate_json_report(scan_results, target)
            
            emit('scan_output', {
                'line': f"Report generated: {os.path.basename(report_path)}",
                'phase': 'Report Generation',
                'phase_progress': 100,
                'phase_status': 'completed',
                'progress': 100,
                'report_path': report_path
            })
            
            # Emit proper report generated event
            emit('report_generated', {
                'report_id': scan_id,
                'html_path': report_path,
                'json_path': json_report_path
            })
            
            # Final completion
            emit('scan_complete', {
                'status': 'success',
                'message': 'Scan completed successfully',
                'report_id': scan_id
            })
            
        except Exception as parse_ex:
            print(f"[ERROR] Vulnerability processing error: {parse_ex}", flush=True)
            import traceback
            traceback.print_exc()
            emit('scan_output', {
                'line': f"Error during vulnerability processing: {str(parse_ex)}",
                'phase': 'Vulnerability Detection',
                'phase_status': 'failed'
            })
            
    except Exception as ex:
        print(f"[ERROR] Scan error: {ex}", flush=True)
        import traceback
        traceback.print_exc()
        emit('scan_output', {'line': f'Error: {str(ex)}'})

monitoring_threads = {}

@socketio.on('start_passive_monitoring')
def start_passive_monitoring(data):
    print("[SOCKETIO] Received start_passive_monitoring with data:", data, flush=True)
    host = data.get('host')
    sid = request.sid
    if not host:
        print("[SOCKETIO] No host provided, emitting error", flush=True)
        socketio.emit('passive_monitoring_error', {'reason': 'Host/IP required.'}, room=sid)
        return
    
    # Check tshark availability
    try:
        subprocess.check_output(['tshark', '-v'], stderr=subprocess.STDOUT)
        print("[SOCKETIO] Tshark is available", flush=True)
    except Exception as e:
        print("[SOCKETIO] Tshark not available:", e, flush=True)
        socketio.emit('passive_monitoring_error', {'reason': 'Tshark not available.'}, room=sid)
        return

    # Stop any existing monitor for this session
    if sid in monitoring_threads:
        monitoring_threads[sid]['active'] = False
        greenthread.sleep(0.1)  # Give it a moment to stop

    print(f"[SOCKETIO] Starting monitoring thread for host: {host}", flush=True)
    
    def run_nmap_open_ports(host):
        """Run a fast nmap scan and return (open_ports_count, open_ports_list)."""
        try:
            cmd = ["nmap", "-T4", "--top-ports", "100", host]
            print(f"[NMAP] Running nmap command: {' '.join(cmd)}", flush=True)
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=30)
            open_ports = []
            for line in result.splitlines():
                m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
                if m:
                    port = int(m.group(1))
                    proto = m.group(2)
                    service = m.group(3)
                    open_ports.append({"port": port, "proto": proto, "service": service})
            print(f"[NMAP] Found {len(open_ports)} open ports: {open_ports}", flush=True)
            return len(open_ports), open_ports
        except Exception as ex:
            print(f"[NMAP] Error running nmap: {ex}", flush=True)
            return 0, []

    def monitor():
        print(f"[MONITOR] Monitor thread started for {host}", flush=True)
        db = sqlite3.connect('monitor_stats.db')
        db.execute('''CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            host TEXT, packets INTEGER, bytes INTEGER, tcp INTEGER, udp INTEGER, icmp INTEGER, http INTEGER, dns INTEGER, top_talker TEXT, anomaly TEXT
        )''')
        prev_packets = prev_bytes = 0
        seen_ips = set()
        nmap_cycle = 0
        last_open_ports = 0
        last_open_ports_list = []
        prev_open_ports_set = set()
        
        while True:
            interface = 4  # Wi-Fi interface
            cmd = f'tshark -i {interface} -Y "ip.addr == {host}" -q -z io,stat,10 -a duration:10'
            print(f"[MONITOR] Running tshark command: {cmd}", flush=True)
            
            try:
                proc = subprocess.Popen(
                    shlex.split(cmd),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP  # For Windows
                )
                out, err = proc.communicate(timeout=20)  # Increased timeout slightly
                print(f"[MONITOR] Tshark output: {out[:200]}...", flush=True)
                if err:
                    print(f"[MONITOR] Tshark error output: {err}", flush=True)
            except subprocess.TimeoutExpired:
                proc.terminate()
                out, err = proc.communicate()
                print(f"[MONITOR] Tshark timed out, but got output: {out[:200]}...", flush=True)
                if err:
                    print(f"[MONITOR] Tshark error output: {err}", flush=True)
            except Exception as ex:
                print(f"[MONITOR] Tshark error: {str(ex)}", flush=True)
                socketio.emit('passive_monitoring_error', {'reason': f'Tshark error: {str(ex)}'}, room=sid)
                break

            packets = bytes_ = tcp = udp = icmp = http = dns = 0
            top_talker = ''
            anomaly = None
            
            # Parse io,stat table
            lines = out.split('\n')
            for line in lines:
                if line.strip().startswith('|') and 'Frames:' not in line and 'Interval:' not in line:
                    parts = [x.strip() for x in line.strip().split('|') if x.strip()]
                    if len(parts) >= 3:
                        try:
                            packets = int(parts[1].replace(',',''))
                            bytes_ = int(parts[2].replace(',',''))
                        except Exception:
                            continue

            # Check for anomalies
            if packets > 2 * prev_packets and prev_packets > 0:
                anomaly = 'Spike in packets'
            if bytes_ > 2 * prev_bytes and prev_bytes > 0:
                anomaly = 'Spike in bandwidth'

            # Run nmap every 3 cycles (every ~30s), otherwise use last value
            nmap_cycle += 1
            anomaly = None  # reset anomaly flag each cycle
            if nmap_cycle >= 3:
                last_open_ports, last_open_ports_list = run_nmap_open_ports(host)
                # Detect anomaly: new open ports since previous cycle
                current_ports_set = set((p['port'], p['proto']) for p in last_open_ports_list)
                if prev_open_ports_set and current_ports_set != prev_open_ports_set:
                    anomaly = 'Open ports changed: ' + str(list(current_ports_set - prev_open_ports_set))
                prev_open_ports_set = current_ports_set.copy()
                nmap_cycle = 0

            # Save to database
            db.execute('INSERT INTO stats (host, packets, bytes, tcp, udp, icmp, http, dns, top_talker, anomaly) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       (host, packets, bytes_, tcp, udp, icmp, http, dns, top_talker, anomaly or ''))
            db.commit()

            # --- FinGuardAI: Remote Security Health & Vulnerability Lookup ---
            # Load NVD service->CVE mapping (local, for demo)
            try:
                with open(os.path.join(os.path.dirname(__file__), 'nvd_cve_services.json'), 'r') as f:
                    nvd_cve_db = json.load(f)
            except Exception as e:
                print(f"[NVD] Could not load NVD CVE DB: {e}", flush=True)
                nvd_cve_db = {}
                
            # --- FinGuardAI: ML-Based Threat Detection ---
            # Extract packet data for threat analysis
            threat_data = {
                'detected_threats': 0,
                'threat_probability': 0.0,
                'threat_level': 'low',
                'threat_details': [],
                'risk_prediction': []
            }
            
            # Use ML threat detection if available
            if HAS_ML_MODULES and out:
                try:
                    # Use our CICIDS-trained model to detect threats
                    from ml.detect_threats import detect_threats_in_tshark_output
                    
                    # Process tshark output with our detector
                    detection_results = detect_threats_in_tshark_output(out)
                    
                    # Skip if no packets were analyzed
                    if not detection_results:
                        print(f"[ML] No packets analyzed from tshark output", flush=True)
                        detection_results = []
                    
                    # Compute overall threat metrics
                    if detection_results:
                        # Count threats (any packet with is_threat=True)
                        threat_count = sum(1 for r in detection_results if r.get('is_threat', False))
                        
                        # Get highest threat probability
                        threat_probabilities = [r.get('threat_probability', 0.0) for r in detection_results]
                        threat_proba = max(threat_probabilities) if threat_probabilities else 0.0
                        
                        # Determine threat level based on highest probability
                        threat_level = 'critical' if threat_proba > 0.9 else \
                                      'high' if threat_proba > 0.7 else \
                                      'medium' if threat_proba > 0.4 else 'low'
                        
                        # Extract details of threat packets
                        threat_details = []
                        for i, packet in enumerate(detection_results):
                            if packet.get('is_threat', False):
                                threat_details.append({
                                    'id': i + 1,
                                    'protocol': packet.get('protocol', 'unknown'),
                                    'probability': packet.get('threat_probability', 0.0),
                                    'level': packet.get('threat_level', 'low'),
                                    'src_ip': packet.get('src_ip', 'unknown'),
                                    'dest_ip': packet.get('dest_ip', 'unknown'),
                                    'packet_size': packet.get('packet_size', 0)
                                })
                        
                        # Generate risk prediction timeline (for next hour in 5-min intervals)
                        timestamps = []
                        values = []
                        current_time = datetime.datetime.now()
                        base_risk = threat_proba
                        
                        for i in range(12):  # 1 hour, 5 min intervals
                            future_time = current_time + datetime.timedelta(minutes=i*5)
                            # Add some randomness but generally follow the current risk
                            risk = min(1.0, max(0.0, base_risk + np.random.normal(0, 0.05)))
                            timestamps.append(future_time.strftime('%H:%M'))
                            values.append(round(risk * 100))
                        
                        threat_data = {
                            'detected_threats': threat_count,
                            'threat_probability': threat_proba,
                            'threat_level': threat_level,
                            'threat_details': threat_details[:10],  # Limit to 10 threats
                            'risk_prediction': [
                                {'time': t, 'value': v} for t, v in zip(timestamps, values)
                            ]
                        }
                    
                    print(f"[ML] Analyzed network traffic: detected {threat_data['detected_threats']} threats with maximum probability {threat_data['threat_probability']:.2f}", flush=True)
                except Exception as e:
                    print(f"[ML] Error during threat detection: {e}", flush=True)

            # Analyze open ports/services for security health
            risky_services = ['ftp','telnet','smb','rdp','http']
            risky_open = []
            cve_findings = []
            sec_health = 100
            for portinfo in last_open_ports_list:
                service = portinfo.get('service','').lower()
                if service in risky_services:
                    risky_open.append(service)
                    sec_health -= 15
                    # Lookup CVEs
                    for cve in nvd_cve_db.get(service, []):
                        cve_findings.append({
                            'service': service,
                            'port': portinfo['port'],
                            'cve': cve['cve'],
                            'desc': cve['desc'],
                            'severity': cve['severity']
                        })
            # More open ports = lower health
            sec_health -= max(0, (len(last_open_ports_list)-3)*2)
            # Anomaly = lower health
            if anomaly:
                sec_health -= 20
            sec_health = max(0, min(100, sec_health))
            # Risk summary
            vuln_risk = 0
            if cve_findings:
                vuln_risk = max([c['severity'] for c in cve_findings])
            # --- ML-based Threat Detection (if available) ---
            # If we already generated threat_data from the previous detection code, don't overwrite it
            if not threat_data or not threat_data.get('risk_prediction'):
                threat_data = {
                    'detected_threats': 0,
                    'threat_details': [],
                    'threat_probability': 0,
                    'threat_level': 'low',
                    'risk_prediction': [{'time': f'+{i*5}m', 'value': 5} for i in range(12)]  # Basic fallback data
                }
            
            # Try secondary ML detection if available
            if HAS_ML and not threat_data.get('detected_threats'):
                try:
                    # Create sample packet data structure for ML analysis
                    # In a real implementation, we'd use the raw tshark output directly
                    packet_data = [
                        {
                            'protocol': 'tcp',
                            'src': host,
                            'dst': top_talker if top_talker else '8.8.8.8',
                            'src_port': 12345,
                            'dst_port': 80 if 'http' in risky_open else 443,
                            'length': bytes_ // max(packets, 1),
                            'ttl': 64
                        } for _ in range(min(10, max(1, packets)))
                    ]
                    
                    # Get the detector and analyze the packet data
                    threat_analysis = threat_detector.analyze_traffic(packet_data)
                    
                    # Update threat data with ML results
                    threat_percentage = min(100, threat_analysis.get('threat_percentage', 0))
                    highest_threat = threat_analysis.get('highest_threat', 0)
                    threat_level = 'low'
                    if highest_threat > 0.8:
                        threat_level = 'critical'
                    elif highest_threat > 0.6:
                        threat_level = 'high'
                    elif highest_threat > 0.3:
                        threat_level = 'medium'
                    
                    # Fill in threat data
                    threat_data = {
                        'detected_threats': threat_analysis.get('threat_count', 0),
                        'threat_details': threat_analysis.get('detailed_results', [])[:5],  # Just send top 5 for UI
                        'threat_probability': highest_threat * 100,  # Scale to percentage
                        'threat_level': threat_level,
                        # Generate a simple prediction based on current threat level
                        'risk_prediction': [
                            max(0, min(100, highest_threat * 100 * (1 - i*0.05))) for i in range(12)
                        ]
                    }
                    
                    print(f"[ML] Analyzed {len(packet_data)} packets, detected {threat_data['detected_threats']} threats", flush=True)
                except Exception as e:
                    print(f"[ML] Error during threat detection: {e}", flush=True)
            
            # Ensure consistent data format for ML predictions
            if isinstance(threat_data.get('risk_prediction'), list) and len(threat_data['risk_prediction']) > 0:
                # If risk_prediction is just a list of numbers, convert to time/value format
                if isinstance(threat_data['risk_prediction'][0], (int, float)):
                    threat_data['risk_prediction'] = [
                        {'time': f'+{i*5}m', 'value': v} for i, v in enumerate(threat_data['risk_prediction'])
                    ]
            else:
                # Provide fallback risk prediction data
                threat_data['risk_prediction'] = [
                    {'time': f'+{i*5}m', 'value': max(5, min(40, i*3))} for i in range(12)
                ]
            
            # Ensure threat_details is a list
            if not isinstance(threat_data.get('threat_details'), list):
                threat_data['threat_details'] = []
                
            # Emit update with combined data
            socketio.emit('passive_stats_update', {
                'host': host,
                'packets': packets,
                'bytes': bytes_,
                'tcp': tcp,
                'udp': udp,
                'icmp': icmp,
                'http': http,
                'dns': dns,
                'top_talker': top_talker,
                'anomaly': anomaly,
                'open_ports': last_open_ports,
                'open_ports_list': last_open_ports_list,
                'security_health': sec_health,
                'risky_services': risky_open,
                'cve_findings': cve_findings,
                'last_scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'vulnerability_risk': vuln_risk,
                # ML-based threat detection results
                'predicted_threats': threat_data['detected_threats'],
                'threat_probability': threat_data['threat_probability'],
                'threat_level': threat_data['threat_level'],
                'threat_details': threat_data['threat_details'],
                'risk_prediction': threat_data['risk_prediction'],
                # Include remediation recommendations if available
                'remediation': threat_data.get('remediation', {})
            }, room=sid)


            prev_packets, prev_bytes = packets, bytes_
            
            # Check if we should stop
            if not monitoring_threads.get(sid, {}).get('active', False):
                print(f"[MONITOR] Stopping monitor thread for {host}", flush=True)
                break

            # Use eventlet's sleep
            greenthread.sleep(10)

        db.close()
        print(f"[MONITOR] Monitor thread exited for {host}", flush=True)

    # Use eventlet's green thread
    monitoring_threads[sid] = {'active': True}
    t = greenthread.spawn(monitor)
    t.link(lambda gt: monitoring_threads.pop(sid, None))  # Clean up when thread ends

@socketio.on('stop_passive_monitoring')
def stop_passive_monitoring():
    sid = request.sid
    if sid in monitoring_threads:
        monitoring_threads[sid]['active'] = False
        del monitoring_threads[sid]

# Initialize and train threat detection model on startup
if __name__ == '__main__':
    # Determine environment
    env = os.environ.get('FINGUARD_ENV', 'prod')
    print(f"[INFO] Starting FinGuardAI in {env} environment", flush=True)
    
    # Load environment-specific configuration
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config')
    config_file = os.path.join(config_dir, f"{env}.json")
    
    config = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            print(f"[INFO] Loaded configuration from {config_file}", flush=True)
        except Exception as e:
            print(f"[WARNING] Error loading config from {config_file}: {e}", flush=True)
    
    # Initialize the ML threat detection model using CICIDS dataset model
    if HAS_ML_MODULES:
        try:
            print("[ML] Initializing threat detection model with CICIDS dataset...", flush=True)
            
            # Use detect_threats.py module with our trained model
            from ml.detect_threats import get_detector
            
            # Get the threat detector, which will load our trained model
            detector = get_detector()
            
            # Check if model is loaded
            if not detector.is_model_loaded():
                print("[ML] No existing model found, training new model with CICIDS dataset...", flush=True)
                
                # Import training script for CICIDS data
                from ml.train_model_with_cicids import train_threat_detection_model
                
                # Train model
                model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
                os.makedirs(model_dir, exist_ok=True)
                model_path = os.path.join(model_dir, 'threat_detection_model.joblib')
                
                model, accuracy, features = train_threat_detection_model(model_output_path=model_path)
                print(f"[ML] Model trained with accuracy: {accuracy:.4f}", flush=True)
                
                # Reload the detector to use the new model
                detector = get_detector(model_path)
            else:
                print("[ML] Loaded existing threat detection model", flush=True)
                
            # Test model with real-time generated data rather than static test data
            try:
                # Import data generator module
                from ml.enhanced_training_data import generate_synthetic_packet
                
                # Generate a dynamic test packet using the same generator used for training
                test_packet = generate_synthetic_packet(attack_type="normal")
                
                # Test the model with the generated packet
                test_result = detector.detect_threat(test_packet)
                print(f"[ML] Model test successful: {test_result['threat_probability']:.2f} probability of threat", flush=True)
            except Exception as test_err:
                print(f"[ML] Model test skipped: {test_err}", flush=True)
            
        except Exception as e:
            print(f"[ML] Error initializing ML model: {e}", flush=True)
    
    # Set host and port based on environment
    host = config.get('host', '0.0.0.0')
    port = config.get('port', 5003)  # Changed to 5003 to avoid any port conflicts
    debug = env != 'prod'  # Debug mode only in non-production environments
    
    # Start the server
    print(f"[INFO] Starting server on {host}:{port} (debug={debug})", flush=True)
    socketio.run(app, host=host, port=port, debug=debug)
