# Login After Dark — Enterprise SOC & Mobile Threat Defense 🌙🛡️

An enterprise-grade authentication anomaly intelligence and real-time SOC command center built with **Python Flask** and **SQLite**.

The platform is designed to identify suspicious authentication behavior, protect against multi-device account takeover, support authorized night-shift employees without false positives, detect impossible geographic travel, and empower users with a **Mobile Security Companion App** featuring 1-click **[Authorize]** and **[Block Device]** push alerts.

---

## 🌟 Key Capabilities & Architectural Enhancements

### 1. Persistent SQLite Database (`database.py`)
- **Password Hashing**: Stored using `werkzeug.security` (PBKDF2-SHA256).
- **Tables**:
  - `users`: User credentials, display names, roles, and personalized shift windows (`DAY`, `NIGHT`, `FLEX_247`).
  - `devices`: Tracks client fingerprints, device names, types (Desktop/Mobile), browser/OS, and trust/block status.
  - `device_alerts`: Live push notification queue for unrecognized devices attempting access.
  - `auth_logs`: Historical audit trail with IP, geographic coordinates (Lat/Lon/City/Country), device details, risk scores, and anomaly tags.

### 2. The 6-Pillar Threat Detection Engine (`detection_engine.py`)
| Pillar | Detection Mechanism | Severity |
| :--- | :--- | :--- |
| **1. Shift & Schedule Policy** | Compares login time against the employee's assigned shift. **Night-shift workers are cleared automatically as legitimate**, while unauthorized off-hours access is flagged. | `INFO` (Authorized) / `MEDIUM` (Violation) |
| **2. Multi-Device Defense** | Detects unrecognized device fingerprints. Generates an instant push alert to the registered mobile companion app. | `HIGH` |
| **3. Blocked Device Lockout** | Immediately halts login attempts from blacklisted devices (HTTP 403). | `CRITICAL` |
| **4. Impossible Travel Velocity** | Calculates geographic distance and elapsed time between logins using the Haversine formula. Flags velocities exceeding airliner speed ($>900$ km/h). | `CRITICAL` |
| **5. Brute-Force Spraying** | Tracks repeated failed attempts ($\ge 3$) in a sliding 3-minute window per user/IP. | `HIGH` / `CRITICAL` |
| **6. Request Burst / Bot Anomaly** | Flags abnormal spikes ($\ge 4$ attempts in $< 10$ seconds) from a single IP. | `HIGH` |

### 3. Employee Shift & Time-Frame Scheduler ("Work After Dark")
- In typical security systems, 3:00 AM logins are blindly flagged as threats.
- In **Login After Dark**, employees have configurable shift schedules:
  - **Standard Day Shift**: `09:00 – 18:00` (off-hours flagged after dark).
  - **Night-Shift Operator**: `22:00 – 07:00` (working after dark is verified as approved baseline).
  - **24/7 Flex clearance**: Round-the-clock clearance (SREs, Global Devs).

### 4. Interactive Global GeoIP Threat Map
- Embedded **Leaflet.js** world map with a dark cybersecurity theme.
- Plots incoming authentication nodes across New York, London, Tokyo, Frankfurt, Moscow, and Sydney with glowing radar pings.

### 5. Mobile Companion App (`/mobile`) & Embedded Phone Simulator
- Openable on smartphones at `http://<your-ip>:5000/mobile` or toggled right inside the desktop dashboard via the **📱 Show Mobile Simulator** button.
- When an unrecognized device attempts to log in, the mobile phone vibrates with an instant alert:
  > **⚠️ UNRECOGNIZED DEVICE ATTEMPT**  
  > *Account: admin*  
  > *Device: Firefox on Linux*  
  > *Location: Moscow, Russia*  
  > *[✓ Authorize & Trust]   [✕ Block & Lock]*
- Clicking **[Block]** immediately blacklists the device in SQLite and blocks all future login attempts from that fingerprint!

---

## 📁 Project Structure

```text
login-after-dark/
├── app.py                     # Flask Web Application & REST API Endpoints
├── database.py                # SQLite Database Management & Password Hashing
├── detection_engine.py        # 6-Pillar Anomaly & Threat Detection Algorithms
├── requirements.txt           # Dependencies (Flask >= 3.0.0, Werkzeug)
├── test_app.py                # Automated Integration & Security Tests
│
├── templates/
│   ├── index.html             # Desktop SOC Command Center (Map, Dashboard, Devices, Shifts)
│   └── mobile.html            # Standalone Mobile Companion Security App
│
└── static/
    ├── css/
    │   ├── style.css          # SOC Command Center Cyber Theme & Phone Frame Styling
    │   └── mobile.css         # Clean iOS/Android Mobile Companion Stylesheet
    └── js/
        ├── app.js             # Desktop SOC Controller, Leaflet Map, Real-time Sync
        └── mobile.js          # Mobile Companion Controller & Push Notification Engine
```

---

## 🚀 Quickstart & Setup

### 1. Create Virtual Environment & Install Dependencies
```bash
cd /home/hrushi/.gemini/antigravity/scratch/login-after-dark
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```
- **Desktop SOC Command Center**: Open [`http://127.0.0.1:5000`](http://127.0.0.1:5000)
- **Mobile Companion App**: Open [`http://127.0.0.1:5000/mobile`](http://127.0.0.1:5000/mobile)

### 3. Run Automated Tests
```bash
python -m unittest test_app.py
```
*(All 6 unit tests verify multi-device alerts, shifts, impossible travel, and device blocking in $< 1$s).*

---

## 🧪 Demonstration & Test Scenarios

### Default Persistent Users (Stored in SQLite)
| Username | Password | Role | Shift Schedule |
| :--- | :--- | :--- | :--- |
| `admin` | `Secr3tP@ss!` | SecOps Lead | Day Shift (09:00 – 18:00) |
| `night_analyst` | `NightOwl99!` | Threat Responder | **Night Shift (22:00 – 07:00)** |
| `remote_dev` | `FlexPass123` | Global SRE | 24/7 Flex (Anytime) |
| `alice` | `CyberPass123` | Security Analyst | Day Shift (09:00 – 18:00) |

### Testing with 1-Click Buttons
1. **🌙 Night-Shift (Authorized)**:
   - Simulates `night_analyst` logging in at **03:15 AM**.
   - **Result**: `SAFE` (0 risk points). Proves that night workers are verified without false alarms!
2. **⚠️ Unauthorized Night Login**:
   - Simulates day-worker `admin` logging in at **03:15 AM**.
   - **Result**: `SUSPICIOUS` (`SHIFT_VIOLATION` flagged).
3. **📱 New Device Intrusion**:
   - Simulates an attacker trying to log in as `admin` from an unrecognized device in Moscow.
   - **Result**: Flags `NEW_DEVICE_DETECTED` and immediately triggers a push notification on the mobile app.
   - In the mobile view or embedded phone simulator, click **[✕ Block & Lock]** to blacklist the device.
4. **✈️ Impossible Travel**:
   - Simulates two consecutive logins from **London** and **Tokyo** within seconds.
   - **Result**: `CRITICAL` threat flagged due to impossible velocity ($>900$ km/h).
5. **⚔️ Brute-Force Spray**:
   - Fires 4 consecutive wrong passwords against user `admin`.
   - **Result**: `CRITICAL` threat flagged for automated password cracking.

---

## 📡 REST API Reference

- `POST /api/login`: Accepts credentials, device fingerprint, location city, and timestamp hour. Evaluates threat and records log in SQLite.
- `GET /api/stats`: Returns aggregated counts (Total Logins, Threats, Pending Device Alerts, Registered Devices).
- `GET /api/logs`: Returns historical audit trail in reverse-chronological order.
- `GET /api/devices`: Returns device inventory and trust status.
- `POST /api/devices/action`: Set trust or block status on a device (`BLOCK` / `TRUST`).
- `GET /api/users`: Returns users and their assigned shift schedules.
- `POST /api/users/shift`: Updates an employee's shift configuration.
- `GET /api/mobile/alerts`: Returns pending device alerts for a user.
- `POST /api/mobile/action`: Approves or blocks an unrecognized device (`APPROVE` / `BLOCK`).
- `POST /api/simulate`: Triggers automated demonstration scenarios.
- `POST /api/clear`: Resets logs and alert queues.
