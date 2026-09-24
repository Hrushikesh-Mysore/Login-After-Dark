import os
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify

from database import (
    get_user_by_username,
    get_user_by_id,
    verify_user_password,
    get_all_users,
    update_user_shift,
    get_user_devices,
    get_device,
    register_device,
    set_device_block_status,
    create_device_alert,
    get_pending_alerts,
    get_all_alerts,
    resolve_alert,
    record_log,
    get_recent_logs,
    get_stats,
    clear_logs
)
from detection_engine import (
    evaluate_enterprise_threat,
    GEO_LOCATIONS,
    KNOWN_MALICIOUS_IPS
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'enterprise-login-after-dark-secure-key-2026'

# --- Web Page Routes ---

@app.route("/")
def index():
    """Desktop Enterprise SOC Threat Command Center."""
    return render_template("index.html")

@app.route("/mobile")
def mobile_view():
    """Dedicated Mobile Companion Security App for Smartphones."""
    return render_template("mobile.html")

# --- Authentication & Threat Detection API ---

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    custom_ip = (data.get("ip") or "").strip()
    client_ip = custom_ip if custom_ip else (request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1")
    
    simulated_hour = data.get("simulated_hour")
    city_selection = data.get("city") or "New York"
    
    device_fp = data.get("device_fingerprint") or "fp-client-browser-default"
    device_name = data.get("device_name") or "Web Browser"
    device_type = data.get("device_type") or "Desktop"
    browser = data.get("browser") or "Chrome"
    os_name = data.get("os") or "Linux"

    # Geo coordinates (supports live GPS from laptops/phones or preset cities)
    custom_lat = data.get("lat")
    custom_lon = data.get("lon")
    if custom_lat is not None and custom_lon is not None:
        try:
            lat_val = float(custom_lat)
            lon_val = float(custom_lon)
            city_name = data.get("city_name") or (f"Live GPS ({lat_val:.2f}, {lon_val:.2f})" if city_selection == "GPS" else city_selection)
            country_name = data.get("country_name") or "Local Device GPS"
            geo = {
                "country": country_name,
                "city": city_name,
                "lat": lat_val,
                "lon": lon_val
            }
        except (ValueError, TypeError):
            geo = GEO_LOCATIONS.get(city_selection, GEO_LOCATIONS["New York"])
    else:
        geo = GEO_LOCATIONS.get(city_selection, GEO_LOCATIONS["New York"])

    # Determine attempt time
    now = datetime.now()
    if simulated_hour is not None and str(simulated_hour) != "real":
        try:
            hour_val = int(simulated_hour)
            attempt_time = now.replace(hour=hour_val, minute=22, second=15)
        except (ValueError, TypeError):
            attempt_time = now
    else:
        attempt_time = now

    # Verify user & credentials
    user_record = get_user_by_username(username)
    is_valid_pw, auth_user = verify_user_password(username, password)
    auth_success = is_valid_pw and (auth_user is not None)

    # Check device status in DB
    existing_device = None
    if user_record:
        existing_device = get_device(user_record["id"], device_fp)

    is_device_known = existing_device is not None
    is_device_blocked = existing_device["is_blocked"] == 1 if existing_device else False

    # Blocked devices cannot authenticate regardless of password
    if is_device_blocked:
        auth_success = False

    device_info = {
        "fingerprint": device_fp,
        "name": device_name,
        "is_known": is_device_known,
        "is_blocked": is_device_blocked
    }

    # Query recent logs for sliding window analysis
    recent_logs = get_recent_logs(limit=50)

    # Evaluate threat
    risk_score, classification, triggered_rules = evaluate_enterprise_threat(
        user_record=user_record,
        username=username,
        ip=client_ip,
        auth_success=auth_success,
        device_info=device_info,
        location_info=geo,
        attempt_time=attempt_time,
        recent_logs=recent_logs
    )

    is_new_device = not is_device_known and user_record is not None
    created_alert_id = None

    # Handle New Device Alert Registration
    if is_new_device and user_record:
        # Register in devices table as untrusted/pending
        register_device(
            user_id=user_record["id"],
            fingerprint=device_fp,
            device_name=device_name,
            device_type=device_type,
            browser=browser,
            os_name=os_name,
            is_trusted=0,
            is_blocked=0
        )
        # Create Push Alert for the mobile companion
        created_alert_id = create_device_alert(
            user_id=user_record["id"],
            username=username,
            fingerprint=device_fp,
            device_name=device_name,
            ip=client_ip,
            location=f"{geo['city']}, {geo['country']}",
            severity="HIGH" if classification == "CRITICAL" else "MEDIUM"
        )
    elif is_device_known and user_record and auth_success:
        # Update last seen timestamp
        register_device(
            user_id=user_record["id"],
            fingerprint=device_fp,
            device_name=device_name,
            device_type=device_type,
            browser=browser,
            os_name=os_name,
            is_trusted=existing_device["is_trusted"],
            is_blocked=existing_device["is_blocked"]
        )

    # Record Log Entry in SQLite
    log_entry = {
        "timestamp": attempt_time.strftime("%Y-%m-%d %H:%M:%S"),
        "time_display": attempt_time.strftime("%H:%M:%S"),
        "epoch": time.time(),
        "username": username if username else "[empty]",
        "ip": client_ip,
        "country": geo["country"],
        "city": geo["city"],
        "lat": geo["lat"],
        "lon": geo["lon"],
        "device_name": device_name,
        "device_fingerprint": device_fp,
        "is_new_device": is_new_device,
        "auth_success": auth_success,
        "risk_score": risk_score,
        "classification": classification,
        "triggered_rules": triggered_rules,
        "details": f"Login attempt for user '{username}' from {device_name} ({geo['city']}, {geo['country']})."
    }
    record_log(log_entry)

    # Generate user-facing message
    if is_device_blocked:
        message = "Access Denied: This device has been blocked by security policy."
        http_code = 403
    elif auth_success:
        message = "Authentication successful. Access granted."
        http_code = 200
    else:
        message = "Authentication failed. Invalid credentials."
        http_code = 401

    return jsonify({
        "status": "success" if auth_success else "failed",
        "message": message,
        "evaluation": {
            "risk_score": risk_score,
            "classification": classification,
            "triggered_rules": triggered_rules,
            "timestamp": log_entry["timestamp"],
            "ip": client_ip,
            "location": geo,
            "device": device_info,
            "is_new_device": is_new_device,
            "alert_dispatched": created_alert_id is not None,
            "alert_id": created_alert_id
        }
    }), http_code

# --- Management & Operational APIs ---

@app.route("/api/stats", methods=["GET"])
def api_stats():
    return jsonify(get_stats())

@app.route("/api/logs", methods=["GET"])
def api_logs():
    return jsonify(get_recent_logs(limit=100))

@app.route("/api/users", methods=["GET"])
def api_users():
    return jsonify(get_all_users())

@app.route("/api/users/shift", methods=["POST"])
def api_update_shift():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    shift_type = data.get("shift_type", "DAY")
    start_hour = int(data.get("shift_start_hour", 9))
    end_hour = int(data.get("shift_end_hour", 18))

    if not user_id:
        return jsonify({"error": "User ID required"}), 400

    update_user_shift(user_id, shift_type, start_hour, end_hour)
    return jsonify({"status": "success", "message": "User shift schedule updated"})

@app.route("/api/devices", methods=["GET"])
def api_devices():
    username = request.args.get("username")
    if username:
        user = get_user_by_username(username)
        if not user:
            return jsonify([])
        return jsonify(get_user_devices(user["id"]))
    
    # Return all devices across all users
    users = get_all_users()
    all_devs = []
    for u in users:
        devs = get_user_devices(u["id"])
        for d in devs:
            d["username"] = u["username"]
            all_devs.append(d)
    return jsonify(all_devs)

@app.route("/api/devices/action", methods=["POST"])
def api_device_action():
    data = request.get_json() or {}
    device_id = data.get("device_id")
    action = data.get("action")  # 'BLOCK' or 'TRUST'

    if not device_id or not action:
        return jsonify({"error": "device_id and action required"}), 400

    if action == "BLOCK":
        set_device_block_status(device_id, is_blocked=1)
        return jsonify({"status": "success", "message": "Device blocked successfully"})
    elif action == "TRUST":
        set_device_block_status(device_id, is_blocked=0)
        return jsonify({"status": "success", "message": "Device marked as trusted"})
    return jsonify({"error": "Invalid action"}), 400

# --- Mobile Companion App APIs ---

@app.route("/api/mobile/alerts", methods=["GET"])
def api_mobile_alerts():
    username = request.args.get("username")
    return jsonify(get_pending_alerts(username))

@app.route("/api/mobile/action", methods=["POST"])
def api_mobile_action():
    data = request.get_json() or {}
    alert_id = data.get("alert_id")
    action = data.get("action") # 'APPROVE' or 'BLOCK'

    if not alert_id or not action:
        return jsonify({"error": "alert_id and action required"}), 400

    success, msg = resolve_alert(alert_id, action)
    if success:
        return jsonify({"status": "success", "message": msg})
    return jsonify({"error": msg}), 400

# --- Attack & Demonstration Scenarios ---

@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json() or {}
    scenario = data.get("scenario")

    if scenario == "night_shift_authorized":
        # Feature: Night-Shift worker login during night (03:15 AM)
        # Expected: Clean baseline, NO false-positive!
        user = get_user_by_username("night_analyst")
        t = datetime.now().replace(hour=3, minute=15, second=10)
        geo = GEO_LOCATIONS["New York"]
        dev_info = {"fingerprint": "fp-night-laptop-mac-01", "name": "Night Owl Ops MacBook", "is_known": True, "is_blocked": False}
        
        risk, classif, rules = evaluate_enterprise_threat(
            user_record=user, username="night_analyst", ip="10.0.4.15", auth_success=True,
            device_info=dev_info, location_info=geo, attempt_time=t, recent_logs=get_recent_logs(20)
        )
        entry = {
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"), "epoch": time.time(),
            "username": "night_analyst", "ip": "10.0.4.15", "country": geo["country"],
            "city": geo["city"], "lat": geo["lat"], "lon": geo["lon"],
            "device_name": dev_info["name"], "device_fingerprint": dev_info["fingerprint"],
            "is_new_device": False, "auth_success": True, "risk_score": risk,
            "classification": classif, "triggered_rules": rules,
            "details": "Authorized night-shift login by night_analyst at 03:15 AM. Approved schedule."
        }
        record_log(entry)
        return jsonify({"scenario": scenario, "result": entry})

    elif scenario == "after_dark_unauthorized":
        # Feature: Day-worker (admin) logging in during off-hours (03:15 AM)
        # Expected: SHIFT_VIOLATION anomaly flagged!
        user = get_user_by_username("admin")
        t = datetime.now().replace(hour=3, minute=15, second=10)
        geo = GEO_LOCATIONS["Frankfurt"]
        dev_info = {"fingerprint": "fp-admin-workstation-lin-01", "name": "Admin Primary Workstation", "is_known": True, "is_blocked": False}
        
        risk, classif, rules = evaluate_enterprise_threat(
            user_record=user, username="admin", ip="198.51.100.44", auth_success=True,
            device_info=dev_info, location_info=geo, attempt_time=t, recent_logs=get_recent_logs(20)
        )
        entry = {
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"), "epoch": time.time(),
            "username": "admin", "ip": "198.51.100.44", "country": geo["country"],
            "city": geo["city"], "lat": geo["lat"], "lon": geo["lon"],
            "device_name": dev_info["name"], "device_fingerprint": dev_info["fingerprint"],
            "is_new_device": False, "auth_success": True, "risk_score": risk,
            "classification": classif, "triggered_rules": rules,
            "details": "Unauthorized off-hours access attempt by day-shift worker 'admin'."
        }
        record_log(entry)
        return jsonify({"scenario": scenario, "result": entry})

    elif scenario == "new_device_intrusion":
        # Feature: Attacker tries logging into admin's account from an unknown device
        # Expected: NEW_DEVICE_DETECTED + Push Alert to Mobile!
        user = get_user_by_username("admin")
        t = datetime.now()
        geo = GEO_LOCATIONS["Moscow"]
        unknown_fp = f"fp-unrecognized-hacker-{int(time.time())}"
        unknown_name = "Firefox on Linux (Unknown)"
        dev_info = {"fingerprint": unknown_fp, "name": unknown_name, "is_known": False, "is_blocked": False}
        
        risk, classif, rules = evaluate_enterprise_threat(
            user_record=user, username="admin", ip="203.0.113.88", auth_success=False,
            device_info=dev_info, location_info=geo, attempt_time=t, recent_logs=get_recent_logs(20)
        )
        register_device(user["id"], unknown_fp, unknown_name, "Desktop", "Firefox", "Linux", is_trusted=0, is_blocked=0)
        alert_id = create_device_alert(user["id"], "admin", unknown_fp, unknown_name, "203.0.113.88", f"{geo['city']}, {geo['country']}", "HIGH")
        
        entry = {
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"), "epoch": time.time(),
            "username": "admin", "ip": "203.0.113.88", "country": geo["country"],
            "city": geo["city"], "lat": geo["lat"], "lon": geo["lon"],
            "device_name": unknown_name, "device_fingerprint": unknown_fp,
            "is_new_device": True, "auth_success": False, "risk_score": risk,
            "classification": classif, "triggered_rules": rules,
            "details": f"Intrusion attempt from new unrecognized device. Dispatched mobile push alert #{alert_id}."
        }
        record_log(entry)
        return jsonify({"scenario": scenario, "result": entry, "alert_id": alert_id})

    elif scenario == "impossible_travel":
        # Feature: User logs in from London, then 5 seconds later from Tokyo
        user = get_user_by_username("admin")
        t1 = datetime.now()
        geo1 = GEO_LOCATIONS["London"]
        entry1 = {
            "timestamp": t1.strftime("%Y-%m-%d %H:%M:%S"), "epoch": time.time() - 300,
            "username": "admin", "ip": "81.2.69.142", "country": geo1["country"],
            "city": geo1["city"], "lat": geo1["lat"], "lon": geo1["lon"],
            "device_name": "Workstation", "device_fingerprint": "fp-admin-workstation-lin-01",
            "is_new_device": False, "auth_success": True, "risk_score": 10,
            "classification": "SAFE", "triggered_rules": [],
            "details": "Legitimate login from London corporate office."
        }
        record_log(entry1)

        # Login 2: Tokyo
        geo2 = GEO_LOCATIONS["Tokyo"]
        dev_info2 = {"fingerprint": "fp-admin-workstation-lin-01", "name": "Workstation", "is_known": True, "is_blocked": False}
        risk2, classif2, rules2 = evaluate_enterprise_threat(
            user_record=user, username="admin", ip="133.242.0.1", auth_success=True,
            device_info=dev_info2, location_info=geo2, attempt_time=datetime.now(), recent_logs=get_recent_logs(20)
        )
        entry2 = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "epoch": time.time(),
            "username": "admin", "ip": "133.242.0.1", "country": geo2["country"],
            "city": geo2["city"], "lat": geo2["lat"], "lon": geo2["lon"],
            "device_name": "Workstation", "device_fingerprint": "fp-admin-workstation-lin-01",
            "is_new_device": False, "auth_success": True, "risk_score": risk2,
            "classification": classif2, "triggered_rules": rules2,
            "details": "Simulated sudden geographic jump to Tokyo."
        }
        record_log(entry2)
        return jsonify({"scenario": scenario, "result": entry2})

    elif scenario == "brute_force":
        # 4 failed attempts in rapid succession
        user = get_user_by_username("admin")
        geo = GEO_LOCATIONS["San Francisco"]
        for p in ["123456", "admin1", "secret", "root"]:
            risk, classif, rules = evaluate_enterprise_threat(
                user_record=user, username="admin", ip="192.168.1.18", auth_success=False,
                device_info={"fingerprint": "fp-brute-scanner", "name": "Python Script", "is_known": False, "is_blocked": False},
                location_info=geo, attempt_time=datetime.now(), recent_logs=get_recent_logs(20)
            )
            record_log({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "epoch": time.time(),
                "username": "admin", "ip": "192.168.1.18", "country": geo["country"],
                "city": geo["city"], "lat": geo["lat"], "lon": geo["lon"],
                "device_name": "Python Script", "device_fingerprint": "fp-brute-scanner",
                "is_new_device": True, "auth_success": False, "risk_score": risk,
                "classification": classif, "triggered_rules": rules,
                "details": f"Brute force attempt with password '{p}'."
            })
        return jsonify({"scenario": scenario, "message": "Brute-force attack generated."})

    return jsonify({"error": "Unknown scenario"}), 400

@app.route("/api/clear", methods=["POST"])
def api_clear():
    clear_logs()
    return jsonify({"status": "cleared", "message": "Audit logs and alert queues cleared."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
