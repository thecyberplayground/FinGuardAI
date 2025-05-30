from flask import Flask, request, jsonify
import subprocess
import threading
import os
import sys
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

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our ML-based threat detection modules
try:
    from ml.detect_threats import get_detector, detect_threats_in_tshark_output
    from ml.train_model import initialize_model
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
    target = data.get('target')
    scan_type = data.get('scan_type', 'basic')
    if not target:
        emit('scan_output', {'line': 'Error: Target is required.'})
        return
    import platform
    is_windows = platform.system().lower().startswith('win')
    if scan_type == 'basic':
        cmd = ["nmap", "-sS", "-v", target]
    elif scan_type == 'deep':
        cmd = ["nmap", "-A", "-vv", "--stats-every", "2s", target]
    else:
        emit('scan_output', {'line': 'Error: Invalid scan type.'})
        return
    if not is_windows:
        cmd = ["stdbuf", "-oL"] + cmd
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True
        )
        with open(f"nmap_{target}.txt", "w") as f:
            import re
            for line in iter(proc.stdout.readline, ''):
                f.write(line)
                percent_match = re.search(r"Stats: (\d+)% done;", line)
                if percent_match:
                    percent = int(percent_match.group(1))
                    emit('scan_output', {'line': line, 'progress': percent})
                else:
                    emit('scan_output', {'line': line})
                socketio.sleep(0)
            proc.stdout.close()
            proc.wait()
        emit('scan_output', {'line': 'SCAN_COMPLETE', 'progress': 100})
    except Exception as ex:
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
            if HAS_ML_MODULES and tshark_output:
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
            threat_data = {
                'detected_threats': 0,
                'threat_details': [],
                'threat_probability': 0,
                'threat_level': 'low',
                'risk_prediction': [0]*12  # Placeholder for future ML
            }
            
            if HAS_ML:
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
    port = config.get('port', 5001)
    debug = env != 'prod'  # Debug mode only in non-production environments
    
    # Start the server
    print(f"[INFO] Starting server on {host}:{port} (debug={debug})", flush=True)
    socketio.run(app, host=host, port=port, debug=debug)
