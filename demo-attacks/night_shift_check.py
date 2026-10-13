#!/usr/bin/env python3
"""
DEMO SCENARIO: Shift Policy Comparison ("Work After Dark")
Demonstrates the core innovation of Login After Dark:
1. Authorized Night Worker ('night_analyst') logging in at 03:00 AM -> Cleared as SAFE (0 risk points).
2. Unauthorized Day Worker ('admin') logging in at 03:00 AM -> Flagged as SHIFT_VIOLATION.
"""

import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:5000/api/login"

def test_login(username, password, hour, desc):
    payload = {
        "username": username,
        "password": password,
        "is_simulation": True,
        "simulated_hour": hour,
        "city": "New York",
        "device_fingerprint": f"fp-{username}-workstation",
        "device_name": f"{username} Laptop"
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

    print(f"[{desc}]")
    print(f"User: {username} | Time: 03:00 AM (After Dark)")
    print(f"HTTP Status: {status} | Verdict: {classification} (Risk: {risk}/100)")
    print(f"Rules: {', '.join(rules)}")
    print("-" * 65)

def main():
    print("=" * 65)
    print("🌙 DEMO: SHIFT SCHEDULE POLICY INTELLIGENCE")
    print("Comparing Night-Shift Operator vs Day-Shift Worker at 03:00 AM")
    print("=" * 65)

    # 1. night_analyst at 3 AM -> Approved night shift
    test_login("night_analyst", "NightOwl99!", 3, "Test 1: Approved Night Worker (Should be SAFE)")

    # 2. admin at 3 AM -> Day worker shift violation
    test_login("admin", "Secr3tP@ss!", 3, "Test 2: Day Worker After Hours (Should be SUSPICIOUS)")

    print("✅ Notice how night-shift employees work without false alarms!")

if __name__ == "__main__":
    main()
