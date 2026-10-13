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

    def test_session_management_and_logout(self):
        """Phase 1: Test authenticated session lifecycle and logout."""
        # Check initial unauthenticated state
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        self.assertFalse(me_res.get_json()["authenticated"])

        # Authenticate successfully
        login_res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "device_fingerprint": "fp-admin-workstation-lin-01"
        })
        self.assertEqual(login_res.status_code, 200)

        # Check authenticated session
        me_auth = self.client.get("/api/auth/me")
        self.assertEqual(me_auth.status_code, 200)
        me_data = me_auth.get_json()
        self.assertTrue(me_data["authenticated"])
        self.assertEqual(me_data["user"]["username"], "admin")

        # Logout
        logout_res = self.client.post("/api/auth/logout")
        self.assertEqual(logout_res.status_code, 200)

        # Verify session is cleared
        me_after = self.client.get("/api/auth/me")
        self.assertFalse(me_after.get_json()["authenticated"])

    def test_anti_spoofing_ip_enforcement(self):
        """Phase 1: In production mode (not simulation), client cannot spoof IP address."""
        res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "ip": "8.8.8.8",
            "is_simulation": False
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["evaluation"]["ip"], "127.0.0.1")

    def test_rate_limiter_unit(self):
        """Phase 1: Test SlidingWindowRateLimiter limits rapid calls."""
        from rate_limiter import SlidingWindowRateLimiter
        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=10)
        allowed1, _ = limiter.is_allowed("test-client")
        allowed2, _ = limiter.is_allowed("test-client")
        allowed3, _ = limiter.is_allowed("test-client")
        allowed4, retry_after = limiter.is_allowed("test-client")
        self.assertTrue(allowed1)
        self.assertTrue(allowed2)
        self.assertTrue(allowed3)
        self.assertFalse(allowed4)
        self.assertGreater(retry_after, 0)

    def test_web_routes(self):
        """Verify web routes render properly."""
        r_index = self.client.get("/")
        self.assertEqual(r_index.status_code, 200)
        self.assertIn(b"LOGIN AFTER DARK", r_index.data)

        r_mobile = self.client.get("/mobile")
        self.assertEqual(r_mobile.status_code, 200)
        self.assertIn(b"SECURITY GUARDIAN", r_mobile.data)

    def test_sse_event_stream(self):
        """Phase 3: Verify SSE event stream endpoint yields event-stream and initial handshake."""
        from event_stream import event_dispatcher
        # Direct subscription & broadcast test
        q = event_dispatcher.subscribe()
        event_dispatcher.broadcast("TEST_EVENT", {"hello": "world"})
        msg = q.get(timeout=2.0)
        self.assertIn("TEST_EVENT", msg)
        self.assertIn("hello", msg)
        event_dispatcher.unsubscribe(q)

        # Test HTTP endpoint
        res = self.client.get("/api/events/stream")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/event-stream", res.headers.get("Content-Type", ""))

    def test_shift_gradient_deviation(self):
        """Phase 5: Time-gradient shift deviation differentiates marginal overtime vs extreme night access."""
        # Admin shift: 09:00 - 18:00
        # Marginal overtime: 19:00 (1 hour deviation) -> weight 15, LOW severity
        res_marginal = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "simulated_hour": 19,
            "device_fingerprint": "fp-admin-workstation-lin-01"
        })
        self.assertEqual(res_marginal.status_code, 200)
        data_marginal = res_marginal.get_json()["evaluation"]
        rule_marginal = next(r for r in data_marginal["triggered_rules"] if r["code"] == "SHIFT_VIOLATION")
        self.assertEqual(rule_marginal["severity"], "LOW")
        self.assertEqual(rule_marginal["weight"], 15)

        # Extreme off-hours: 03:00 (6 hours deviation) -> weight 35, MEDIUM severity
        res_extreme = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "simulated_hour": 3,
            "device_fingerprint": "fp-admin-workstation-lin-01"
        })
        self.assertEqual(res_extreme.status_code, 200)
        data_extreme = res_extreme.get_json()["evaluation"]
        rule_extreme = next(r for r in data_extreme["triggered_rules"] if r["code"] == "SHIFT_VIOLATION")
        self.assertEqual(rule_extreme["severity"], "MEDIUM")
        self.assertEqual(rule_extreme["weight"], 35)

    def test_new_location_historical_baseline(self):
        """Phase 5: Historical baseline detects unfamiliar login location for established user."""
        # Baseline login 1 in New York
        self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "city": "New York",
            "simulated_hour": 10,
            "device_fingerprint": "fp-admin-workstation-lin-01"
        })

        # Subsequent login from Frankfurt (after reasonable time, e.g. 15 hours later so no impossible travel)
        # We simulate this with direct evaluation or passing location
        from detection_engine import evaluate_enterprise_threat
        from database import get_recent_logs, get_user_by_username
        user = get_user_by_username("admin")
        recent = get_recent_logs(20)

        # Craft attempt 15 hours later
        fake_time = datetime.now().replace(hour=11)
        # Ensure latest log is > 12h ago in epoch to not trigger impossible travel
        for r in recent:
            r["epoch"] = time.time() - (15 * 3600)

        risk, classif, rules = evaluate_enterprise_threat(
            user_record=user,
            username="admin",
            ip="198.51.100.44",
            auth_success=True,
            device_info={"fingerprint": "fp-admin-workstation-lin-01", "name": "Admin PC", "is_known": True, "is_blocked": False},
            location_info={"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lon": 8.6821},
            attempt_time=fake_time,
            recent_logs=recent
        )
        rule_codes = [r["code"] for r in rules]
        self.assertIn("NEW_LOCATION_ANOMALY", rule_codes)

    def test_geoip_resolver_resolution(self):
        """Phase 5: GeoIP resolver handles cache, private IPs, and city hints."""
        from geoip_resolver import resolve_ip_location, is_private_ip
        # Loopback / Private IP
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.50"))
        self.assertFalse(is_private_ip("8.8.8.8"))

        geo_local = resolve_ip_location("192.168.1.10")
        self.assertEqual(geo_local["city"], "Internal Office")

        geo_hint = resolve_ip_location("8.8.8.8", city_hint="Tokyo")
        self.assertEqual(geo_hint["city"], "Tokyo")

if __name__ == "__main__":
    unittest.main()
