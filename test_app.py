import unittest
import json
import time
from datetime import datetime
from app import app
from database import (
    init_db,
    seed_default_data,
    clear_logs,
    get_user_by_username,
    get_pending_alerts,
    get_device
)

class EnterpriseLoginAfterDarkTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        init_db()
        seed_default_data()
        clear_logs()

    def test_night_shift_worker_no_false_positive(self):
        """Feature 1: Night-shift employee (night_analyst) logging in at 03:00 AM is recognized as SAFE."""
        res = self.client.post("/api/login", json={
            "username": "night_analyst",
            "password": "NightOwl99!",
            "simulated_hour": 3,
            "city": "New York",
            "device_fingerprint": "fp-night-laptop-mac-01",
            "device_name": "Night Owl Ops MacBook"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        eval_data = data["evaluation"]
        rule_codes = [r["code"] for r in eval_data["triggered_rules"]]
        self.assertIn("AUTHORIZED_NIGHT_SHIFT", rule_codes)
        self.assertNotIn("SHIFT_VIOLATION", rule_codes)
        self.assertEqual(eval_data["classification"], "SAFE")

    def test_day_shift_worker_unauthorized_night_login(self):
        """Feature 2: Day-shift employee (admin) logging in at 03:00 AM triggers SHIFT_VIOLATION."""
        res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "simulated_hour": 3,
            "city": "New York",
            "device_fingerprint": "fp-admin-workstation-lin-01",
            "device_name": "Admin Primary Workstation"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        eval_data = data["evaluation"]
        rule_codes = [r["code"] for r in eval_data["triggered_rules"]]
        self.assertIn("SHIFT_VIOLATION", rule_codes)
        self.assertEqual(eval_data["classification"], "SUSPICIOUS")

    def test_new_device_generates_mobile_push_alert(self):
        """Feature 3: Unrecognized device triggers NEW_DEVICE_DETECTED and creates a pending mobile alert."""
        unknown_fp = f"fp-unrecognized-hacker-{int(time.time())}"
        res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "simulated_hour": 14,
            "city": "Frankfurt",
            "device_fingerprint": unknown_fp,
            "device_name": "Kali Linux Attacker Machine"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        eval_data = data["evaluation"]
        rule_codes = [r["code"] for r in eval_data["triggered_rules"]]
        self.assertIn("NEW_DEVICE_DETECTED", rule_codes)
        self.assertTrue(eval_data["alert_dispatched"])

        # Check that alert was saved in SQLite
        pending = get_pending_alerts("admin")
        self.assertTrue(any(a["device_fingerprint"] == unknown_fp for a in pending))

    def test_mobile_alert_block_action_enforces_lockout(self):
        """Feature 4: Blocking a device via Mobile Companion API rejects subsequent logins."""
        unknown_fp = f"fp-blocked-test-{int(time.time())}"
        
        # 1. Login from new device creates alert
        login_res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "device_fingerprint": unknown_fp,
            "device_name": "Suspicious Chrome on Windows"
        })
        alert_id = login_res.get_json()["evaluation"]["alert_id"]
        self.assertIsNotNone(alert_id)

        # 2. User blocks the device via mobile companion app
        action_res = self.client.post("/api/mobile/action", json={
            "alert_id": alert_id,
            "action": "BLOCK"
        })
        self.assertEqual(action_res.status_code, 200)

        # 3. Subsequent login attempt from this blocked device must be rejected (HTTP 403)
        blocked_res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "device_fingerprint": unknown_fp,
            "device_name": "Suspicious Chrome on Windows"
        })
        self.assertEqual(blocked_res.status_code, 403)
        self.assertIn("BLOCKED_DEVICE", [r["code"] for r in blocked_res.get_json()["evaluation"]["triggered_rules"]])

    def test_impossible_travel_detection(self):
        """Feature 5: Logins from London and Tokyo in rapid succession trigger IMPOSSIBLE_TRAVEL."""
        # 1. Login in London
        self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "city": "London",
            "device_fingerprint": "fp-admin-workstation-lin-01"
        })

        # 2. Login immediately in Tokyo
        res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "city": "Tokyo",
            "device_fingerprint": "fp-admin-workstation-lin-01"
        })
        data = res.get_json()
        rule_codes = [r["code"] for r in data["evaluation"]["triggered_rules"]]
        self.assertIn("IMPOSSIBLE_TRAVEL", rule_codes)
        self.assertEqual(data["evaluation"]["classification"], "CRITICAL")

    def test_web_routes(self):
        """Verify web routes render properly."""
        r_index = self.client.get("/")
        self.assertEqual(r_index.status_code, 200)
        self.assertIn(b"LOGIN AFTER DARK", r_index.data)

        r_mobile = self.client.get("/mobile")
        self.assertEqual(r_mobile.status_code, 200)
        self.assertIn(b"SECURITY GUARDIAN", r_mobile.data)

if __name__ == "__main__":
    unittest.main()
