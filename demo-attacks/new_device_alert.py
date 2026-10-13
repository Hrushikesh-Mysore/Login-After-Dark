#!/usr/bin/env python3
"""
DEMO SCENARIO: Unrecognized New Device Intrusion
Simulates a login from an unrecognized computer, triggering an instant mobile push alert.
Target Endpoint: POST http://localhost:5000/api/login
Expected Server Response: Triggers 'NEW_DEVICE_DETECTED' rule, adds an intrusion alert
to the mobile companion app queue, and allows 1-click [Authorize] or [Block].
"""

import json
import time
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:5000/api/login"
ALERTS_URL = "http://127.0.0.1:5000/api/mobile/alerts?username=admin"

def main():
    print("=" * 65)
    print("📱 SIMULATING UNRECOGNIZED DEVICE INTRUSION")
    print("An unknown laptop attempts to log into the 'admin' account.")
    print("=" * 65)

    random_fp = f"fp-attacker-macbook-{int(time.time())}"
    payload = {
        "username": "admin",
        "password": "Secr3tP@ss!",
        "is_simulation": True,
        "city": "Frankfurt",
        "ip": "84.115.22.4",
        "device_fingerprint": random_fp,
        "device_name": "Unrecognized MacBook Air M3 (Frankfurt)"
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
    alert_dispatched = eval_data.get("alert_dispatched", False)

    print(f"HTTP Status: {status} | Verdict: {classification} (Risk: {risk}/100)")
    print(f"Triggered Rules: {', '.join(rules)}")
    print(f"Mobile Push Alert Dispatched: {'🔔 YES!' if alert_dispatched else '❌ NO'}")

    print("\n👉 Check the Mobile Companion App at http://localhost:5000/mobile")
    print("You will see the interactive prompt to [Authorize & Trust] or [Block & Lock] this device!")

if __name__ == "__main__":
    main()
