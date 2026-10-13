#!/usr/bin/env python3
"""
DEMO SCENARIO: Anonymous Tor Exit Node / Proxy Login Attempt
Simulates an authentication attempt originating from a known anonymizing Tor exit relay (185.220.101.5).
Target Endpoint: POST http://localhost:5000/api/login
Expected Server Response: Triggers 'TOR_EXIT_NODE' threat classification.
"""

import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:5000/api/login"
TOR_IP = "185.220.101.5"

def main():
    print("=" * 65)
    print("🧅 SIMULATING ANONYMIZING TOR EXIT NODE LOGIN")
    print(f"Origin IP: {TOR_IP} (Frankfurt, DE - Tor Relay)")
    print("=" * 65)

    payload = {
        "username": "admin",
        "password": "WrongPassword999",
        "is_simulation": True,
        "ip": TOR_IP,
        "city": "Frankfurt",
        "device_fingerprint": "fp-tor-browser-anon",
        "device_name": "Tor Browser 13.0 on Linux"
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

    print(f"HTTP Status: {status} | Verdict: {classification} (Risk: {risk}/100)")
    print(f"🚨 Triggered Rules: {', '.join(rules)}")
    print(f"Evaluation: {body.get('message')}")
    print("\n✅ Check the GeoIP map on http://localhost:5000 for the red radar pulse in Frankfurt!")

if __name__ == "__main__":
    main()
