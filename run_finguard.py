#!/usr/bin/env python3
"""
FinGuardAI - Integrated Launcher

This script launches the complete FinGuardAI system including:
- Web API server
- Vulnerability scanner
- ML-based threat detection
- Report generation
"""

import os
import sys
import json
import argparse
import subprocess
import threading
import logging
import time
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("finguardai.launcher")

def kill_previous_processes():
    """Kill any previously running FinGuardAI processes"""
    try:
        # For Windows
        import platform
        if platform.system().lower() == 'windows':
            subprocess.run("taskkill /F /IM nmap.exe /T", shell=True, 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # For Linux/Mac
            subprocess.run("pkill -f nmap", shell=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.debug(f"Error killing previous processes: {e}")

def load_config(env="prod"):
    """Load environment configuration"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config", f"{env}.json")
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logger.info(f"Loaded configuration from {config_path}")
        return config
    except Exception as e:
        logger.warning(f"Error loading config from {config_path}: {e}")
        logger.warning("Using default configuration")
        return {}

def check_prereqs():
    """Check prerequisites for running FinGuardAI"""
    # Check if nmap is installed
    try:
        nmap_version = subprocess.check_output(["nmap", "--version"], 
                                            stderr=subprocess.STDOUT, 
                                            text=True)
        logger.info(f"Nmap detected: {nmap_version.split()[2]}")
    except:
        logger.error("Nmap not found. Please install Nmap: https://nmap.org/download.html")
        return False
    
    # Ensure report directories exist
    paths = ["reports", "backend/scan_results", "backend/models"]
    for path in paths:
        Path(path).mkdir(exist_ok=True, parents=True)
    
    return True

def run_backend_server(env, port=5001):
    """Run the backend Flask server"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(script_dir, "backend", "app.py")
    
    # Set environment variable for configuration
    env_vars = os.environ.copy()
    env_vars["FINGUARD_ENV"] = env
    env_vars["PYTHONUNBUFFERED"] = "1"  # Ensure Python output is unbuffered
    
    logger.info(f"Starting FinGuardAI backend server on port {port} in {env} environment...")
    try:
        # Run with Python's verbose error reporting
        cmd = [sys.executable, "-v", app_path]
        logger.info(f"Running command: {' '.join(cmd)}")
        
        # Start the process with full output capture
        process = subprocess.Popen(
            cmd, 
            env=env_vars,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Monitor the process output for confirmation that server is running
        server_started = False
        for line in iter(process.stdout.readline, ''):
            print(line, end='')
            if "Starting server on" in line:
                logger.info("Backend server started successfully")
                server_started = True
                break
            # Check for common error patterns
            elif "Error:" in line or "Exception:" in line or "Traceback" in line:
                logger.error(f"Detected error during startup: {line.strip()}")
        
        # If we've exited the loop without seeing the startup message, check if process is still running
        if not server_started and process.poll() is not None:
            logger.error(f"Server process exited with code {process.returncode} before confirming startup")
            # Try to get any remaining output
            remaining_output = process.stdout.read()
            if remaining_output:
                print("Remaining output:")
                print(remaining_output)
        
        return process
    except Exception as e:
        logger.error(f"Error starting backend server: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    parser = argparse.ArgumentParser(
        description="FinGuardAI - Integrated Security Platform",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--env", "-e",
                      choices=["dev", "test", "prod"],
                      default="prod",
                      help="Environment to use for configuration")
    parser.add_argument("--port", "-p",
                      type=int,
                      default=5001,
                      help="Port to run the server on")
    args = parser.parse_args()
    
    # Kill any previous processes
    kill_previous_processes()
    
    # Check prerequisites
    if not check_prereqs():
        sys.exit(1)
    
    # Load configuration
    config = load_config(args.env)
    
    # Start the backend server
    server_process = run_backend_server(args.env, args.port)
    
    if not server_process:
        logger.error("Failed to start backend server")
        sys.exit(1)
    
    # Print information about how to use the system
    url = f"http://localhost:{args.port}"
    logger.info(f"\n{'='*50}\nFinGuardAI is running!")
    logger.info(f"API Server: {url}")
    logger.info(f"Web Dashboard: {url}/dashboard (if configured)")
    logger.info(f"API Endpoints:")
    logger.info(f"  - Scan: POST {url}/scan/nmap")
    logger.info(f"  - Scan Status: GET {url}/scan/nmap/result?target=<target>")
    logger.info(f"  - Threat Detection: POST {url}/detect")
    logger.info(f"{'='*50}\n")
    
    # Keep the main process running
    try:
        while True:
            if server_process.poll() is not None:
                logger.error("Backend server has stopped unexpectedly")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down FinGuardAI...")
        if server_process:
            server_process.terminate()
    
if __name__ == "__main__":
    main()
