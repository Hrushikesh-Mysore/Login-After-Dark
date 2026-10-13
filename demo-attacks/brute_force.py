#!/usr/bin/env python3
"""
DEMO SCENARIO: Brute-Force Password Spray Attack
Simulates an automated attacker spraying rapid password guesses against the 'admin' account.
Target Endpoint: POST http://localhost:5000/api/login
Expected Server Response: Threat Engine detects multiple rapid failures in sliding window,
triggers 'BRUTE_FORCE' rule with HIGH/CRITICAL severity.
"""

import json
import time
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:5000/api/login"
PASSWORDS = ["123456", "admin123", "P@ssword1", "roottoor", "Secr3tP@ss!"]

def send_login(username, password, count):
    payload = {
        "username": username,
        "password": password,
        "is_simulation": True,
        "ip": "198.51.100.99",
        "city": "Moscow",
        "device_fingerprint": "fp-brute-force-bot-01",
        "device_name": "Hydra Brute-Forcer v9.2"
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

    print(f"[{count}/5] Attempting '{username}' with pass '{password}'...")
    print(f"      HTTP Status: {status} | Verdict: {classification} (Risk: {risk}/100)")
    if rules:
        print(f"      🚨 Triggered Rules: {', '.join(rules)}")
    print("-" * 65)

def main():
    print("=" * 65)
    print("⚔️  SIMULATING BRUTE-FORCE PASSWORD ATTACK")
    print(f"Target: {BASE_URL}")
    print("Watch the live SOC Command Center dashboard update in real time!")
    print("=" * 65)

    for i, pwd in enumerate(PASSWORDS, 1):
        send_login("admin", pwd, i)
        time.sleep(0.8)

    print("\n✅ Attack sequence finished. Check the dashboard at http://localhost:5000")

if __name__ == "__main__":
    main()
