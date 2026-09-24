import sqlite3
import os
import json
import time
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "auth_security.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Users table with shift/time-frame configuration
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            role TEXT DEFAULT 'Analyst',
            shift_type TEXT DEFAULT 'DAY',  -- 'DAY', 'NIGHT', 'FLEX_247', 'CUSTOM'
            shift_start_hour INTEGER DEFAULT 9,
            shift_end_hour INTEGER DEFAULT 18,
            is_locked INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # 2. Devices table (multi-device tracking & fingerprinting)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_fingerprint TEXT NOT NULL,
            device_name TEXT NOT NULL,
            device_type TEXT DEFAULT 'Desktop',  -- 'Desktop', 'Mobile', 'Tablet'
            browser TEXT,
            os TEXT,
            is_trusted INTEGER DEFAULT 1,
            is_blocked INTEGER DEFAULT 0,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE(user_id, device_fingerprint)
        );
        """)

        # 3. Security Alerts table (mobile companion alerts for new devices)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            device_fingerprint TEXT NOT NULL,
            device_name TEXT NOT NULL,
            ip TEXT NOT NULL,
            location TEXT NOT NULL,
            severity TEXT DEFAULT 'HIGH',
            status TEXT DEFAULT 'PENDING',  -- 'PENDING', 'APPROVED', 'BLOCKED'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        """)

        # 4. Authentication Logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            epoch REAL NOT NULL,
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            country TEXT DEFAULT 'United States',
            city TEXT DEFAULT 'New York',
            lat REAL DEFAULT 40.7128,
            lon REAL DEFAULT -74.0060,
            device_name TEXT,
            device_fingerprint TEXT,
            is_new_device INTEGER DEFAULT 0,
            auth_success INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            triggered_rules_json TEXT,
            details TEXT
        );
        """)
        conn.commit()

def seed_default_data():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if users exist
        cursor.execute("SELECT COUNT(*) as count FROM users")
        if cursor.fetchone()["count"] == 0:
            # Seed default users
            # 1. admin: Standard Day Shift (09:00 - 18:00)
            cursor.execute("""
                INSERT INTO users (username, password_hash, display_name, role, shift_type, shift_start_hour, shift_end_hour)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "admin",
                generate_password_hash("Secr3tP@ss!"),
                "Administrator",
                "SecOps Lead",
                "DAY",
                9,
                18
            ))
            admin_id = cursor.lastrowid

            # 2. night_analyst: Night Shift Worker (22:00 - 07:00 / 10 PM - 7 AM)
            cursor.execute("""
                INSERT INTO users (username, password_hash, display_name, role, shift_type, shift_start_hour, shift_end_hour)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "night_analyst",
                generate_password_hash("NightOwl99!"),
                "Night-Shift SOC Guard",
                "Threat Responder",
                "NIGHT",
                22,
                7
            ))
            night_id = cursor.lastrowid

            # 3. remote_dev: 24/7 Flex clearance (Anytime)
            cursor.execute("""
                INSERT INTO users (username, password_hash, display_name, role, shift_type, shift_start_hour, shift_end_hour)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "remote_dev",
                generate_password_hash("FlexPass123"),
                "Global SRE Engineer",
                "DevOps",
                "FLEX_247",
                0,
                24
            ))

            # 4. alice: Day Shift
            cursor.execute("""
                INSERT INTO users (username, password_hash, display_name, role, shift_type, shift_start_hour, shift_end_hour)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "alice",
                generate_password_hash("CyberPass123"),
                "Alice Johnson",
                "Security Analyst",
                "DAY",
                9,
                18
            ))

            # Register Default Known Trusted Devices
            # Admin's trusted primary desktop
            cursor.execute("""
                INSERT INTO devices (user_id, device_fingerprint, device_name, device_type, browser, os, is_trusted, is_blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                admin_id,
                "fp-admin-workstation-lin-01",
                "Admin Primary Workstation",
                "Desktop",
                "Chrome 122",
                "Linux Ubuntu",
                1,
                0
            ))

            # Night Analyst's trusted laptop
            cursor.execute("""
                INSERT INTO devices (user_id, device_fingerprint, device_name, device_type, browser, os, is_trusted, is_blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                night_id,
                "fp-night-laptop-mac-01",
                "Night Owl Ops MacBook",
                "Desktop",
                "Firefox 123",
                "macOS Sonoma",
                1,
                0
            ))

            conn.commit()

# --- Database Query Helpers ---

def get_user_by_username(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

def get_user_by_id(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()

def verify_user_password(username, password):
    user = get_user_by_username(username)
    if not user:
        return False, None
    if user["is_locked"]:
        return False, "ACCOUNT_LOCKED"
    if check_password_hash(user["password_hash"], password):
        return True, user
    return False, None

def get_all_users():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, display_name, role, shift_type, shift_start_hour, shift_end_hour, is_locked FROM users ORDER BY id ASC")
        return [dict(row) for row in cursor.fetchall()]

def update_user_shift(user_id, shift_type, start_hour, end_hour):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET shift_type = ?, shift_start_hour = ?, shift_end_hour = ?
            WHERE id = ?
        """, (shift_type, start_hour, end_hour, user_id))
        conn.commit()

def get_user_devices(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE user_id = ? ORDER BY id DESC", (user_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_device(user_id, fingerprint):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE user_id = ? AND device_fingerprint = ?", (user_id, fingerprint))
        row = cursor.fetchone()
        return dict(row) if row else None

def register_device(user_id, fingerprint, device_name, device_type="Desktop", browser="Chrome", os_name="Linux", is_trusted=1, is_blocked=0):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO devices (user_id, device_fingerprint, device_name, device_type, browser, os, is_trusted, is_blocked, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id, device_fingerprint) DO UPDATE SET
                device_name = excluded.device_name,
                browser = excluded.browser,
                os = excluded.os,
                last_seen = CURRENT_TIMESTAMP
        """, (user_id, fingerprint, device_name, device_type, browser, os_name, is_trusted, is_blocked))
        conn.commit()

def set_device_block_status(device_id, is_blocked):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE devices SET is_blocked = ?, is_trusted = ? WHERE id = ?", (is_blocked, 0 if is_blocked else 1, device_id))
        conn.commit()

def create_device_alert(user_id, username, fingerprint, device_name, ip, location, severity="HIGH"):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO device_alerts (user_id, username, device_fingerprint, device_name, ip, location, severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')
        """, (user_id, username, fingerprint, device_name, ip, location, severity))
        conn.commit()
        return cursor.lastrowid

def get_pending_alerts(username=None):
    with get_db() as conn:
        cursor = conn.cursor()
        if username:
            cursor.execute("SELECT * FROM device_alerts WHERE username = ? AND status = 'PENDING' ORDER BY id DESC", (username,))
        else:
            cursor.execute("SELECT * FROM device_alerts WHERE status = 'PENDING' ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]

def get_all_alerts(limit=50):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM device_alerts ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]

def resolve_alert(alert_id, action):
    # action: 'APPROVE' or 'BLOCK'
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM device_alerts WHERE id = ?", (alert_id,))
        alert = cursor.fetchone()
        if not alert:
            return False, "Alert not found"

        user_id = alert["user_id"]
        fingerprint = alert["device_fingerprint"]

        if action == "APPROVE":
            cursor.execute("UPDATE device_alerts SET status = 'APPROVED', resolved_at = CURRENT_TIMESTAMP WHERE id = ?", (alert_id,))
            cursor.execute("""
                UPDATE devices SET is_trusted = 1, is_blocked = 0 WHERE user_id = ? AND device_fingerprint = ?
            """, (user_id, fingerprint))
            conn.commit()
            return True, "Device authorized and trusted successfully"
        elif action == "BLOCK":
            cursor.execute("UPDATE device_alerts SET status = 'BLOCKED', resolved_at = CURRENT_TIMESTAMP WHERE id = ?", (alert_id,))
            cursor.execute("""
                UPDATE devices SET is_trusted = 0, is_blocked = 1 WHERE user_id = ? AND device_fingerprint = ?
            """, (user_id, fingerprint))
            conn.commit()
            return True, "Device blocked. Access revoked."
        return False, "Invalid action"

def record_log(entry):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO auth_logs (
                timestamp, epoch, username, ip, country, city, lat, lon,
                device_name, device_fingerprint, is_new_device, auth_success,
                risk_score, classification, triggered_rules_json, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry["timestamp"],
            entry["epoch"],
            entry["username"],
            entry["ip"],
            entry.get("country", "Unknown"),
            entry.get("city", "Unknown"),
            entry.get("lat", 0.0),
            entry.get("lon", 0.0),
            entry.get("device_name", "Unknown Device"),
            entry.get("device_fingerprint", "none"),
            1 if entry.get("is_new_device") else 0,
            1 if entry["auth_success"] else 0,
            entry["risk_score"],
            entry["classification"],
            json.dumps(entry.get("triggered_rules", [])),
            entry.get("details", "")
        ))
        conn.commit()
        return cursor.lastrowid

def get_recent_logs(limit=100):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM auth_logs ORDER BY id DESC LIMIT ?", (limit,))
        logs = []
        for row in cursor.fetchall():
            d = dict(row)
            d["auth_success"] = bool(d["auth_success"])
            d["is_new_device"] = bool(d["is_new_device"])
            d["triggered_rules"] = json.loads(d["triggered_rules_json"] or "[]")
            logs.append(d)
        return logs

def get_stats():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM auth_logs")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as critical_count FROM auth_logs WHERE classification = 'CRITICAL'")
        critical_count = cursor.fetchone()["critical_count"]

        cursor.execute("SELECT COUNT(*) as suspicious_count FROM auth_logs WHERE classification = 'SUSPICIOUS'")
        suspicious_count = cursor.fetchone()["suspicious_count"]

        cursor.execute("SELECT COUNT(*) as safe_count FROM auth_logs WHERE classification = 'SAFE'")
        safe_count = cursor.fetchone()["safe_count"]

        cursor.execute("SELECT COUNT(*) as pending_alerts FROM device_alerts WHERE status = 'PENDING'")
        pending_alerts = cursor.fetchone()["pending_alerts"]

        cursor.execute("SELECT COUNT(*) as total_devices FROM devices")
        total_devices = cursor.fetchone()["total_devices"]

        cursor.execute("SELECT COUNT(*) as blocked_devices FROM devices WHERE is_blocked = 1")
        blocked_devices = cursor.fetchone()["blocked_devices"]

        # Parse rule triggers from recent 200 logs
        cursor.execute("SELECT triggered_rules_json FROM auth_logs ORDER BY id DESC LIMIT 200")
        rule_counts = {
            "SHIFT_VIOLATION": 0,
            "NEW_DEVICE_DETECTED": 0,
            "IMPOSSIBLE_TRAVEL": 0,
            "BRUTE_FORCE": 0,
            "BURST_VELOCITY": 0,
            "BLOCKED_DEVICE": 0,
            "TOR_EXIT_NODE": 0
        }
        for row in cursor.fetchall():
            rules = json.loads(row["triggered_rules_json"] or "[]")
            for r in rules:
                code = r.get("code")
                if code in rule_counts:
                    rule_counts[code] += 1

        return {
            "total_attempts": total,
            "threats_detected": critical_count + suspicious_count,
            "critical_count": critical_count,
            "suspicious_count": suspicious_count,
            "safe_count": safe_count,
            "pending_alerts": pending_alerts,
            "total_devices": total_devices,
            "blocked_devices": blocked_devices,
            "rule_counts": rule_counts
        }

def clear_logs():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM auth_logs")
        cursor.execute("DELETE FROM device_alerts")
        conn.commit()

# Initialize upon import
init_db()
seed_default_data()
