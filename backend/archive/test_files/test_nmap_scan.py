import requests
import time
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
scan_type = "basic"

# Step 1: Trigger scan
resp = requests.post("http://127.0.0.1:5001/scan/nmap", json={"target": target, "scan_type": scan_type})
print("Trigger Scan Response:", resp.status_code, resp.json())

# Step 2: Poll for result
for i in range(10):
    time.sleep(5)
    result_resp = requests.get(f"http://127.0.0.1:5001/scan/nmap/result?target={target}")
    print(f"Attempt {i+1} - Status: {result_resp.status_code}")
    if result_resp.status_code == 200:
        print("Scan Result:\n", result_resp.json()["result"][:500], "... (truncated)")
        break
    else:
        print(result_resp.json())
else:
    print("Scan did not finish in time.")
