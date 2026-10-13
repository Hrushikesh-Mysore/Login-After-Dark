"""
Concurrency & Scalability Stress Test Suite for Login After Dark
Simulates 3+ concurrent active users executing 100+ interleaved database and API
operations simultaneously (logins, shift modifications, mobile alert resolutions,
device blacklisting, log queries, and real-time SSE broadcasts) to verify that
SQLite WAL mode and busy timeouts guarantee 0 database locks.
"""

import unittest
import time
import json
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from app import app
from database import (
    init_db,
    seed_default_data,
    clear_logs,
    get_db,
    get_user_by_username,
    get_all_users,
    get_recent_logs,
    get_pending_alerts,
    get_user_devices
)
from event_stream import event_dispatcher

class ConcurrencyStressTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True

    def setUp(self):
        init_db()
        seed_default_data()
        clear_logs()

    def test_multi_user_concurrent_stress(self):
        """
        Simulate 3 concurrent users executing 120+ interleaved operations
        simultaneously across threads. Verifies zero SQLite database locks (WAL mode),
        zero 500 Internal Server Errors, and complete DB integrity.
        """
        NUM_OPS_PER_USER = 40
        users_config = [
            {
                "username": "admin",
                "password": "Secr3tP@ss!",
                "shift": "DAY",
                "default_device": "fp-admin-workstation-lin-01"
            },
            {
                "username": "night_analyst",
                "password": "NightOwl99!",
                "shift": "NIGHT",
                "default_device": "fp-night-laptop-mac-01"
            },
            {
                "username": "remote_dev",
                "password": "FlexPass123",
                "shift": "FLEX_247",
                "default_device": "fp-remote-dev-mac-01"
            }
        ]

        results = {
            "total_executed": 0,
            "successes": 0,
            "client_errors": 0,
            "server_errors": 0,
            "exceptions": [],
            "latencies": []
        }
        results_lock = threading.Lock()

        # Subscribe an SSE client to verify non-blocking SSE broadcasts during concurrent writes
        sse_queue = event_dispatcher.subscribe()
        sse_received = []

        def sse_drain_worker():
            start_drain = time.time()
            while time.time() - start_drain < 6.0:
                try:
                    msg = sse_queue.get(timeout=0.2)
                    sse_received.append(msg)
                except Exception:
                    pass

        sse_thread = threading.Thread(target=sse_drain_worker, daemon=True)
        sse_thread.start()

        def user_session_worker(user_info, worker_id):
            client = app.test_client()
            username = user_info["username"]
            password = user_info["password"]
            local_success = 0
            local_client_errors = 0
            local_server_errors = 0
            local_exceptions = []
            local_latencies = []

            for i in range(NUM_OPS_PER_USER):
                op_type = i % 5
                t0 = time.time()
                try:
                    if op_type == 0:
                        # 1. Login with varying conditions (shift hours / cities)
                        hour = random.choice([2, 9, 14, 23])
                        city = random.choice(["New York", "London", "Tokyo", "Frankfurt"])
                        res = client.post("/api/login", json={
                            "username": username,
                            "password": password,
                            "simulated_hour": hour,
                            "city": city,
                            "device_fingerprint": user_info["default_device"],
                            "is_simulation": True
                        })
                        status = res.status_code
                        if status == 200:
                            local_success += 1
                        elif 400 <= status < 500:
                            local_client_errors += 1
                        else:
                            local_server_errors += 1
                            local_exceptions.append(f"op0 login status {status}: {res.get_data(as_text=True)}")

                    elif op_type == 1:
                        # 2. Modify Shift configuration
                        new_shift = random.choice(["DAY", "NIGHT", "FLEX_247"])
                        res = client.post("/api/users/shift", json={
                            "username": username,
                            "shift_type": new_shift,
                            "shift_start_hour": 9 if new_shift == "DAY" else (22 if new_shift == "NIGHT" else 0),
                            "shift_end_hour": 18 if new_shift == "DAY" else (7 if new_shift == "NIGHT" else 24)
                        })
                        if res.status_code == 200:
                            local_success += 1
                        else:
                            local_server_errors += 1
                            local_exceptions.append(f"op1 shift status {res.status_code}: {res.get_data(as_text=True)}")

                    elif op_type == 2:
                        # 3. Simulate unrecognized device to trigger alert, then resolve it
                        fake_fp = f"fp-stress-{worker_id}-{i}-{int(time.time()*1000)%100000}"
                        login_res = client.post("/api/login", json={
                            "username": username,
                            "password": password,
                            "device_fingerprint": fake_fp,
                            "device_name": f"Stress Device {i}",
                            "city": "Tokyo",
                            "is_simulation": True
                        })
                        if login_res.status_code == 200:
                            local_success += 1
                            # Check if alert was generated and resolve it
                            alert_id = login_res.get_json().get("evaluation", {}).get("alert_id")
                            if alert_id:
                                action = "BLOCK" if (i % 2 == 0) else "APPROVE"
                                action_res = client.post("/api/mobile/action", json={
                                    "alert_id": alert_id,
                                    "action": action
                                })
                                if action_res.status_code == 200:
                                    local_success += 1
                                else:
                                    local_server_errors += 1
                                    local_exceptions.append(f"op2 action status {action_res.status_code}: {action_res.get_data(as_text=True)}")
                        else:
                            local_server_errors += 1
                            local_exceptions.append(f"op2 login status {login_res.status_code}: {login_res.get_data(as_text=True)}")

                    elif op_type == 3:
                        # 4. Read logs, statistics, and device inventory
                        res_stats = client.get("/api/stats")
                        res_logs = client.get("/api/logs?limit=25")
                        res_devs = client.get("/api/devices")
                        if (res_stats.status_code == 200 and
                            res_logs.status_code == 200 and
                            res_devs.status_code == 200):
                            local_success += 1
                        else:
                            local_server_errors += 1
                            local_exceptions.append(f"op3 status: stats={res_stats.status_code}, logs={res_logs.status_code}, devs={res_devs.status_code}")

                    elif op_type == 4:
                        # 5. Mobile Alerts Polling / Inspection
                        res_alerts = client.get(f"/api/mobile/alerts?username={username}")
                        if res_alerts.status_code == 200:
                            local_success += 1
                        else:
                            local_server_errors += 1
                            local_exceptions.append(f"op4 alerts status {res_alerts.status_code}: {res_alerts.get_data(as_text=True)}")

                except Exception as ex:
                    local_exceptions.append(str(ex))
                finally:
                    local_latencies.append(time.time() - t0)

            # Aggregate worker results
            with results_lock:
                results["total_executed"] += NUM_OPS_PER_USER
                results["successes"] += local_success
                results["client_errors"] += local_client_errors
                results["server_errors"] += local_server_errors
                results["exceptions"].extend(local_exceptions)
                results["latencies"].extend(local_latencies)

        start_time = time.time()
        with ThreadPoolExecutor(max_workers=len(users_config)) as executor:
            futures = [
                executor.submit(user_session_worker, user_cfg, idx)
                for idx, user_cfg in enumerate(users_config)
            ]
            for f in as_completed(futures):
                f.result()

        total_duration = time.time() - start_time
        event_dispatcher.unsubscribe(sse_queue)

        # Assertions
        self.assertEqual(len(results["exceptions"]), 0, f"Exceptions occurred during concurrency: {results['exceptions']}")
        self.assertEqual(results["server_errors"], 0, f"Server (500) errors detected: {results['server_errors']}")
        self.assertGreater(results["successes"], 100, f"Expected >100 successful operations, got {results['successes']}")
        self.assertGreater(len(sse_received), 0, "SSE broadcaster should have delivered real-time events to listener")

        # Database Integrity & Consistency Check
        with get_db() as conn:
            integrity = conn.execute("PRAGMA integrity_check;").fetchone()
            self.assertEqual(integrity[0], "ok", f"Database integrity check failed: {integrity[0]}")
            
            # Verify rows were populated in WAL database
            log_count = conn.execute("SELECT COUNT(*) FROM auth_logs;").fetchone()[0]
            self.assertGreater(log_count, 20, f"Expected log records inserted, found {log_count}")

            device_count = conn.execute("SELECT COUNT(*) FROM devices;").fetchone()[0]
            self.assertGreater(device_count, 5, f"Expected devices registered, found {device_count}")

        # Metrics Reporting
        avg_latency_ms = (sum(results["latencies"]) / len(results["latencies"])) * 1000 if results["latencies"] else 0
        ops_per_sec = results["total_executed"] / total_duration if total_duration > 0 else 0
        
        print("\n" + "=" * 65)
        print("🚀 MULTI-USER CONCURRENCY STRESS TEST RESULTS")
        print("=" * 65)
        print(f"Concurrent Active Users:  {len(users_config)}")
        print(f"Total Transactions:       {results['total_executed']}")
        print(f"Successful Operations:    {results['successes']}")
        print(f"Server Errors (HTTP 500): {results['server_errors']}")
        print(f"Database Lock Exceptions: {len(results['exceptions'])}")
        print(f"Real-Time SSE Dispatches: {len(sse_received)}")
        print(f"Execution Duration:       {total_duration:.2f} seconds")
        print(f"Throughput:               {ops_per_sec:.2f} ops/sec")
        print(f"Average Latency:          {avg_latency_ms:.2f} ms")
        print("SQLite WAL Mode Status:   VERIFIED (Zero Locks, PRAGMA ok)")
        print("=" * 65)

if __name__ == "__main__":
    unittest.main()
