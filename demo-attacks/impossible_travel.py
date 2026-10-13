#!/usr/bin/env python3
"""
DEMO SCENARIO: Impossible Geographic Travel Velocity Anomaly
Simulates two consecutive logins for 'admin' from London and Tokyo within 2 seconds.
Target Endpoint: POST http://localhost:5000/api/login
Expected Server Response: Haversine distance (~9,560 km) over 2 seconds exceeds airliner speed (>900 km/h).
Triggers 'IMPOSSIBLE_TRAVEL' rule with CRITICAL severity.
"""

import json
import time
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:5000/api/login"

def send_login(city, ip, device_name):
    payload = {
        "username": "admin",
        "password": "Secr3tP@ss!",
        "is_simulation": True,
        "city": city,
        "ip": ip,
        "device_fingerprint": "fp-admin-workstation-lin-01",
        "device_name": device_name
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(BASE_URL, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read().decode())
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        body = json.loads(e.read().decode()) if e.headers.get_content_type() == "application/json" else {}

    eval_data = body.get("evaluation", {})
    rules = [r["code"] for r in eval_data.get("triggered_rules", [])]
    classification = eval_data.get("classification", "UNKNOWN")
    risk = eval_data.get("risk_score", 0)

    print(f"📍 Location: {city} ({ip})")
    print(f"   HTTP Status: {status} | Verdict: {classification} (Risk: {risk}/100)")
    if rules:
        print(f"   🚨 Triggered Rules: {', '.join(rules)}")
    print("-" * 65)

def main():
    print("=" * 65)
    print("✈️  SIMULATING IMPOSSIBLE TRAVEL VELOCITY ANOMALY")
    print("Log in from London, then 2 seconds later from Tokyo (~9,560 km away)")
    print("=" * 65)

    print("\n[Step 1] Logging in from London, UK...")
    send_login("London", "185.86.151.11", "Admin Laptop")

    print("[Step 2] Waiting 2 seconds...")
    time.sleep(2)

    print("[Step 3] Logging in from Tokyo, Japan...")
    send_login("Tokyo", "133.242.18.9", "Admin Laptop")

    print("\n✅ Impossible travel test completed! Notice the CRITICAL alarm on http://localhost:5000")

if __name__ == "__main__":
    main()
