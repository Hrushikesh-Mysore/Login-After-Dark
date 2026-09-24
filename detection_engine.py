import math
import time
from datetime import datetime

# Known Simulated Malicious / Tor Exit Node IPs for live demos
KNOWN_MALICIOUS_IPS = {
    "185.220.101.5": "Tor Exit Node (Frankfurt, DE)",
    "198.51.100.44": "Known Bulletproof Proxy (Amsterdam, NL)",
    "162.247.74.200": "Tor Relay (Reykjavik, IS)",
    "203.0.113.88": "Automated Attack Scanner (Moscow, RU)"
}

# City coordinate lookups for live GeoIP map demonstration
GEO_LOCATIONS = {
    "New York": {"country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    "London": {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278},
    "Tokyo": {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
    "Frankfurt": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    "Sydney": {"country": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
    "San Francisco": {"country": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194},
    "Singapore": {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    "Moscow": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173}
}

def haversine_distance_km(lat1, lon1, lat2, lon2):
    """Calculates great-circle distance between two points in km."""
    R = 6371.0 # Earth radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def evaluate_enterprise_threat(
    user_record,
    username,
    ip,
    auth_success,
    device_info,
    location_info,
    attempt_time,
    recent_logs
):
    """
    Evaluates authentication attempt across all 6 core detection pillars:
    1. Shift & Schedule Policy (Night-Worker Support vs Off-Hours Violation)
    2. Multi-Device Tracking & Unrecognized Device Alert
    3. Impossible Travel / Geographic Velocity Anomaly
    4. Brute-Force & Targeted Credential Spraying
    5. Request Burst / High-Velocity Bot Behavior
    6. High-Risk Network / Tor Exit Node
    """
    triggered_rules = []
    risk_score = 0
    now_epoch = time.time()
    hour = attempt_time.hour
    
    # ------------------------------------------------------------------
    # Pillar 1: Shift & Schedule Policy (Empowering Night-Shift Workers!)
    # ------------------------------------------------------------------
    if user_record:
        shift_type = user_record["shift_type"]
        start_hour = user_record["shift_start_hour"]
        end_hour = user_record["shift_end_hour"]

        if shift_type == "FLEX_247":
            is_on_shift = True
        elif start_hour < end_hour:
            # Daytime shift (e.g. 09:00 - 18:00)
            is_on_shift = (start_hour <= hour < end_hour)
        else:
            # Overnight shift (e.g. 22:00 - 07:00 / Night Owl)
            is_on_shift = (hour >= start_hour or hour < end_hour)

        if is_on_shift:
            if shift_type == "NIGHT":
                triggered_rules.append({
                    "code": "AUTHORIZED_NIGHT_SHIFT",
                    "name": "Authorized Night-Shift Access",
                    "description": f"Verified legitimate off-hours work for {user_record['display_name']} ({start_hour:02d}:00 - {end_hour:02d}:00 shift). False-positive prevented.",
                    "severity": "INFO",
                    "weight": 0
                })
        else:
            triggered_rules.append({
                "code": "SHIFT_VIOLATION",
                "name": "Shift Schedule Violation Anomaly",
                "description": f"Authentication at {attempt_time.strftime('%H:%M:%S')} is outside approved {shift_type} shift schedule ({start_hour:02d}:00 - {end_hour:02d}:00).",
                "severity": "MEDIUM",
                "weight": 35
            })
            risk_score += 35
    else:
        # Non-existent user
        if not auth_success:
            risk_score += 20

    # ------------------------------------------------------------------
    # Pillar 2: Multi-Device Detection & Alerting
    # ------------------------------------------------------------------
    device_fingerprint = device_info.get("fingerprint", "unknown-fp")
    device_name = device_info.get("name", "Unknown Browser")
    is_device_known = device_info.get("is_known", False)
    is_device_blocked = device_info.get("is_blocked", False)

    if is_device_blocked:
        triggered_rules.append({
            "code": "BLOCKED_DEVICE",
            "name": "Blocked Device Intrusion Attempt",
            "description": f"Access rejected. Device '{device_name}' [{device_fingerprint}] was previously blocked by security policy or mobile companion app.",
            "severity": "CRITICAL",
            "weight": 70
        })
        risk_score += 70

    elif not is_device_known and user_record:
        triggered_rules.append({
            "code": "NEW_DEVICE_DETECTED",
            "name": "Unrecognized Device Fingerprint",
            "description": f"First-time authentication from device '{device_name}' [{device_fingerprint}]. Dispatched security push alert to registered mobile device.",
            "severity": "HIGH",
            "weight": 40
        })
        risk_score += 40

    # ------------------------------------------------------------------
    # Pillar 3: Impossible Travel / Geographic Velocity Anomaly
    # ------------------------------------------------------------------
    curr_lat = location_info.get("lat", 40.7128)
    curr_lon = location_info.get("lon", -74.0060)
    curr_city = location_info.get("city", "New York")

    # Find previous successful or recent login for this user
    user_past_logs = [l for l in recent_logs if l["username"] == username]
    if user_past_logs:
        last_log = user_past_logs[0] # latest
        last_lat = last_log.get("lat")
        last_lon = last_log.get("lon")
        last_epoch = last_log.get("epoch", now_epoch)
        last_city = last_log.get("city", "Unknown")

        if last_lat is not None and last_lon is not None:
            distance_km = haversine_distance_km(last_lat, last_lon, curr_lat, curr_lon)
            time_diff_sec = max(0.5, now_epoch - last_epoch)
            time_diff_hours = time_diff_sec / 3600.0

            # If within 12 hours and moved a significant distance (> 200 km)
            if time_diff_hours < 12.0 and distance_km > 200:
                velocity_kmh = distance_km / time_diff_hours
                if velocity_kmh > 900.0:  # Exceeds commercial airliner speed (~900 km/h)
                    minutes = time_diff_sec / 60.0
                    triggered_rules.append({
                        "code": "IMPOSSIBLE_TRAVEL",
                        "name": "Impossible Travel Velocity Anomaly",
                        "description": f"Consecutive logins detected across {distance_km:.0f} km in {minutes:.1f} minutes ({velocity_kmh:.0f} km/h) between {last_city} and {curr_city}.",
                        "severity": "CRITICAL",
                        "weight": 65
                    })
                    risk_score += 65

    # ------------------------------------------------------------------
    # Pillar 4: Brute-Force & Targeted Credential Spraying
    # ------------------------------------------------------------------
    # Sliding 3-minute window (180s)
    recent_failures = [
        l for l in recent_logs
        if (now_epoch - l["epoch"] <= 180)
        and not l["auth_success"]
        and (l["username"] == username or l["ip"] == ip)
    ]
    total_failures = len(recent_failures) + (1 if not auth_success else 0)

    if total_failures >= 3 and not auth_success:
        triggered_rules.append({
            "code": "BRUTE_FORCE",
            "name": "Brute-Force Attack Pattern",
            "description": f"Excessive authentication failures ({total_failures} failures in past 180s). Possible automated password cracking.",
            "severity": "HIGH",
            "weight": 50
        })
        risk_score += 50
    elif total_failures >= 3 and auth_success:
        triggered_rules.append({
            "code": "SUSPICIOUS_RECOVERY",
            "name": "Compromise After Brute-Force Wave",
            "description": f"Successful login immediately following {len(recent_failures)} failed attempts within 3 minutes.",
            "severity": "CRITICAL",
            "weight": 60
        })
        risk_score += 60

    # ------------------------------------------------------------------
    # Pillar 5: High-Velocity Burst Anomaly
    # ------------------------------------------------------------------
    recent_ip_requests = [
        l for l in recent_logs
        if (now_epoch - l["epoch"] <= 10) and (l["ip"] == ip)
    ]
    burst_count = len(recent_ip_requests) + 1
    if burst_count >= 4:
        triggered_rules.append({
            "code": "BURST_VELOCITY",
            "name": "High-Velocity Bot Burst",
            "description": f"Abnormal spike of {burst_count} requests in 10s from IP {ip}. Characteristic of credential stuffing bots.",
            "severity": "HIGH",
            "weight": 40
        })
        risk_score += 40

    # ------------------------------------------------------------------
    # Pillar 6: High-Risk Network / Tor Exit Node
    # ------------------------------------------------------------------
    if ip in KNOWN_MALICIOUS_IPS:
        proxy_desc = KNOWN_MALICIOUS_IPS[ip]
        triggered_rules.append({
            "code": "TOR_EXIT_NODE",
            "name": "High-Risk Anonymizing Network",
            "description": f"Request originated from known anonymizing gateway or Tor exit node: {proxy_desc}.",
            "severity": "HIGH",
            "weight": 45
        })
        risk_score += 45

    # Determine classification
    risk_score = min(100, max(0, risk_score))
    if risk_score >= 65:
        classification = "CRITICAL"
    elif risk_score >= 30:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    return risk_score, classification, triggered_rules
