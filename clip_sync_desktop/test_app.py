import subprocess
import time
import urllib.request
import json
import sys

# Start app.py
print("Starting app.py...")
proc = subprocess.Popen([sys.executable, "app.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

# Wait for server to start
time.sleep(3)

endpoints = [
    "/",
    "/api/status",
    "/api/settings",
    "/api/transfers",
    "/api/security",
    "/api/peers"
]

base_url = "http://127.0.0.1:5000"

results = []

try:
    for ep in endpoints:
        print(f"Testing {ep}...")
        req = urllib.request.Request(base_url + ep, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req) as response:
                status = response.status
                body = response.read().decode('utf-8')
                results.append((ep, status, "OK"))
                print(f"[PASS] {ep} -> {status}")
        except urllib.error.HTTPError as e:
            results.append((ep, e.code, str(e)))
            print(f"[FAIL] {ep} -> {e.code}")
        except Exception as e:
            results.append((ep, "Error", str(e)))
            print(f"[FAIL] {ep} -> {e}")
finally:
    # Kill the server
    proc.terminate()
    proc.wait()
    print("\n--- Output of app.py ---")
    print(proc.stdout.read())

print("\n--- TEST RESULTS ---")
all_passed = True
for ep, status, msg in results:
    if status != 200:
        all_passed = False
    print(f"{ep}: {status} {msg}")

if all_passed:
    print("ALL TESTS PASSED")
else:
    print("SOME TESTS FAILED")
