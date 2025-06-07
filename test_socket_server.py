#!/usr/bin/env python3
"""
FinGuardAI - Test Socket.IO Server

This is a minimal test server to validate Socket.IO communication with the frontend.
"""

from flask import Flask
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import time
import json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("finguardai.test.socket")

# Create Flask app
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")
    emit('connection_status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('start_scan')
def handle_start_scan(data):
    """Handle scan requests from the frontend - simplified test version"""
    target = data.get('target')
    scan_type = data.get('scan_type', 'basic')
    environment = data.get('environment', 'dev')
    
    if not target:
        emit('scan_error', {
            'error': 'Target IP or hostname is required.'
        })
        return
    
    logger.info(f"[TEST] Starting simulated scan of {target} (type: {scan_type}, env: {environment})")
    
    # Simulate initialization phase
    emit('scan_progress', {
        'phase': 'Initialization',
        'phase_progress': 10,
        'overall_progress': 5,
        'message': f"Initializing scan for {target}..."
    })
    socketio.sleep(1)
    
    emit('scan_progress', {
        'phase': 'Initialization',
        'phase_progress': 50,
        'overall_progress': 8,
        'message': f"Using {environment} environment configuration"
    })
    socketio.sleep(1)
    
    # For backward compatibility with the old hook
    emit('scan_output', {
        'line': f"Initialization complete. Starting port scanning...",
        'progress': 10
    })
    
    # Complete initialization phase
    emit('scan_progress', {
        'phase': 'Initialization',
        'phase_progress': 100,
        'overall_progress': 10,
        'message': "Initialization complete. Starting port scanning..."
    })
    socketio.sleep(0.5)
    
    # Start port scanning phase
    emit('scan_progress', {
        'phase': 'Port Scanning',
        'phase_progress': 0,
        'overall_progress': 10,
        'message': "Starting port scan..."
    })
    
    # Simulate port scanning progress
    for progress in range(0, 101, 20):
        emit('scan_progress', {
            'phase': 'Port Scanning',
            'phase_progress': progress,
            'overall_progress': 10 + (progress * 0.3),
            'message': f"Scanning ports... {progress}% complete"
        })
        socketio.sleep(0.5)
    
    # Complete port scanning phase
    emit('scan_progress', {
        'phase': 'Port Scanning',
        'phase_progress': 100,
        'overall_progress': 40,
        'message': 'Port scanning complete. Processing vulnerability data...'
    })
    socketio.sleep(1)
    
    # Start vulnerability detection phase
    emit('scan_progress', {
        'phase': 'Vulnerability Detection',
        'phase_progress': 0,
        'overall_progress': 40,
        'message': 'Starting vulnerability analysis...'
    })
    
    # Simulate vulnerability detection
    emit('scan_progress', {
        'phase': 'Vulnerability Detection',
        'phase_progress': 50,
        'overall_progress': 50,
        'message': 'Analyzing scan results for vulnerabilities...'
    })
    socketio.sleep(1)
    
    # Create sample vulnerabilities
    vulnerabilities = [
        {
            "id": "CVE-2021-44228",
            "name": "Log4Shell",
            "description": "Remote code execution vulnerability in Log4j",
            "severity": "critical",
            "cve_id": "CVE-2021-44228",
            "affected_component": "Apache Log4j",
            "remediation": "Update to Log4j 2.15.0 or higher"
        },
        {
            "id": "CVE-2021-3449",
            "name": "OpenSSL Null Pointer Dereference",
            "description": "Denial of service vulnerability in OpenSSL",
            "severity": "medium",
            "cve_id": "CVE-2021-3449",
            "affected_component": "OpenSSL",
            "remediation": "Update OpenSSL to 1.1.1k or higher"
        },
        {
            "id": "CVE-2022-22965",
            "name": "Spring4Shell",
            "description": "Remote code execution vulnerability in Spring Framework",
            "severity": "high",
            "cve_id": "CVE-2022-22965",
            "affected_component": "Spring Framework",
            "remediation": "Update to Spring Framework 5.3.18 or higher"
        }
    ]
    
    # Complete vulnerability detection phase and emit vulnerabilities
    emit('scan_progress', {
        'phase': 'Vulnerability Detection',
        'phase_progress': 100,
        'overall_progress': 60,
        'message': f"Found {len(vulnerabilities)} potential vulnerabilities"
    })
    socketio.sleep(0.5)
    
    # Emit vulnerability data
    emit('vulnerability_data', {
        'vulnerabilities': vulnerabilities
    })
    socketio.sleep(0.5)
    
    # Start ML processing phase
    emit('scan_progress', {
        'phase': 'ML Processing',
        'phase_progress': 0,
        'overall_progress': 60,
        'message': 'Starting ML analysis...'
    })
    
    # Simulate ML processing
    emit('scan_progress', {
        'phase': 'ML Processing',
        'phase_progress': 50,
        'overall_progress': 70,
        'message': 'Processing data with ML models...'
    })
    socketio.sleep(1)
    
    # Create ML predictions
    ml_predictions = [
        {
            "confidence": 0.92,
            "severity": "critical",
            "recommendation": "Apply patch for Log4Shell immediately. This vulnerability can lead to remote code execution."
        },
        {
            "confidence": 0.78,
            "severity": "high",
            "recommendation": "Update Spring Framework to the latest version to mitigate Spring4Shell vulnerability."
        },
        {
            "confidence": 0.65,
            "severity": "medium",
            "recommendation": "Apply patches for OpenSSL to prevent denial of service attacks."
        }
    ]
    
    # Create financial impact assessment
    financial_impact = {
        "total_cost": 125000,
        "breakdown": {
            "remediation": 25000,
            "downtime": 30000,
            "data_loss": 50000,
            "reputation": 20000
        },
        "currency": "USD"
    }
    
    # Complete ML processing phase
    emit('scan_progress', {
        'phase': 'ML Processing',
        'phase_progress': 100,
        'overall_progress': 80,
        'message': 'ML processing complete'
    })
    socketio.sleep(0.5)
    
    # Emit ML results
    emit('ml_results', {
        'predictions': ml_predictions,
        'financial_impact': financial_impact
    })
    socketio.sleep(0.5)
    
    # Start report generation phase
    emit('scan_progress', {
        'phase': 'Report Generation',
        'phase_progress': 0,
        'overall_progress': 80,
        'message': 'Starting report generation...'
    })
    
    # Simulate report generation
    emit('scan_progress', {
        'phase': 'Report Generation',
        'phase_progress': 50,
        'overall_progress': 90,
        'message': 'Generating comprehensive report...'
    })
    socketio.sleep(1)
    
    # Generate sample report paths
    report_id = f"scan_{target.replace('.', '_')}_{int(time.time())}"
    html_path = f"reports/{report_id}.html"
    json_path = f"reports/{report_id}.json"
    
    # Complete report generation phase
    emit('scan_progress', {
        'phase': 'Report Generation',
        'phase_progress': 100,
        'overall_progress': 100,
        'message': f"Report generation complete"
    })
    socketio.sleep(0.5)
    
    # Emit report info
    emit('report_generated', {
        'report_id': report_id,
        'html_path': html_path,
        'json_path': json_path
    })
    socketio.sleep(0.5)
    
    # Final completion
    emit('scan_complete', {})
    logger.info(f"[TEST] Simulated scan completed for {target}")
    
    # For backward compatibility
    emit('scan_output', {
        'line': 'SCAN_COMPLETE',
        'progress': 100
    })

@socketio.on('cancel_scan')
def handle_cancel_scan():
    """Handle scan cancellation requests"""
    logger.info(f"[TEST] Scan cancellation requested")
    
    # Emit progress update with cancellation
    emit('scan_progress', {
        'phase': 'Cancelled',
        'phase_progress': 100,
        'overall_progress': 100,
        'message': 'Scan cancelled by user'
    })
    
    # Emit scan error
    emit('scan_error', {
        'error': 'Scan was cancelled by user'
    })
    
    # For backward compatibility
    emit('scan_output', {
        'line': 'Scan cancelled by user',
        'progress': 100
    })

if __name__ == '__main__':
    # Import request here to avoid circular import issues
    from flask import request
    
    print("[INFO] Starting FinGuardAI Test Socket.IO Server")
    port = int(os.environ.get('PORT', 5001))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    print(f"[INFO] Server running at http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)
