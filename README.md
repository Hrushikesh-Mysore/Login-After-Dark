# Login After Dark — Enterprise SOC & Mobile Threat Defense 🌙🛡️

An enterprise-grade authentication anomaly intelligence platform and real-time SOC command center built with **Python Flask** and **SQLite (WAL Mode)**.

The platform detects suspicious authentication behavior, protects against multi-device account takeover, supports authorized night-shift employees without false alarms, identifies impossible travel velocity, and empowers users with a real-time **Instagram Lite Mobile Companion PWA** featuring 1-click **[Authorize]** and **[Block Device]** push defense.

---

## 🌟 Architecture & Core Innovations

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   Desktop SOC Dashboard / Mobile PWA                   │
│   • Hardware Entropy Fingerprint (SHA-256)   • HTML5 Web Notifications │
│   • Dynamic Geolocation & Live Map            • SSE Push Stream (<100ms)│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / SSE
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Flask Backend Architecture                      │
│   • Sliding-Window Rate Limiter (25 req/min)  • Secure Cookie Sessions │
│   • Server IP Anti-Spoofing                   • EventStream Pub/Sub    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
         ┌──────────────────────────┴──────────────────────────┐
         ▼                                                     ▼
┌────────────────────────────────┐            ┌────────────────────────────────┐
│   Dynamic Threat Engine        │            │   SQLite WAL Concurrency       │
│ • Circular Time-Gradient Shift │            │ • PRAGMA journal_mode = WAL    │
│ • Historical Location Baseline │            │ • PRAGMA busy_timeout = 5000   │
│ • GeoIP Resolver with Cache    │            │ • Multi-Thread Safe Context Mgr│
│ • 0–100 Weighted Risk Scoring  │            │ • Indexed Lookups              │
└────────────────────────────────┘            └────────────────────────────────┘
```

### 1. SQLite High-Concurrency & WAL Engine (`database.py`)
- **Write-Ahead Logging (WAL)**: `PRAGMA journal_mode = WAL` enables non-blocking simultaneous reads and writes.
- **Busy Timeout Protection**: `PRAGMA busy_timeout = 5000` prevents database locking under burst concurrency.
- **Thread-Safe Context Manager**: `get_db()` guarantees connection closing and zero resource leaks.
- **Indexes**: Query performance indexed across `auth_logs(username, epoch)`, `device_alerts(user_id, status)`, and `devices(user_id, device_fingerprint)`.
- **Stress-Tested**: Validated under 3 concurrent active users executing 120+ simultaneous transactions with 0 database locks.

### 2. Real-Time Push & Zero-Polling Architecture (`event_stream.py`)
- **Server-Sent Events (SSE)**: Built-in event bus (`/api/events/stream`) dispatches authentication logs, intrusion alerts, and shift changes with sub-100ms latency.
- **Zero Client Polling**: Both desktop dashboard and mobile view operate without `setInterval` polling loops.
- **Mobile Push & Haptics**: Uses HTML5 Web Notification API (`Notification.requestPermission()`) and vibration feedback (`navigator.vibrate`) for instant device intrusion alerts.

### 3. Dynamic Anomaly Detection Engine (`detection_engine.py`)
| Pillar | Detection Mechanism | Severity |
| :--- | :--- | :--- |
| **1. Shift & Schedule Policy** | Continuous circular time-gradient calculates deviation from shift window. Night workers (`night_analyst`) at 03:00 AM are **SAFE** (0 risk), marginal overtime (+1h) is low risk, and off-hours night access is flagged. | `INFO` (Approved) / `LOW` / `MEDIUM` |
| **2. Historical Location Baseline** | Profiles past successful logins (`NEW_LOCATION_ANOMALY`). Unfamiliar locations trigger elevated risk while maintaining night-shift clearance. | `MEDIUM` |
| **3. Multi-Device Defense** | Detects unrecognized device fingerprints and fires instant mobile push alerts with 1-click authorize or block. | `HIGH` |
| **4. Blocked Device Lockout** | Immediately rejects logins from blacklisted device fingerprints with HTTP 403. | `CRITICAL` |
| **5. Impossible Travel Velocity** | Calculates geographic distance and elapsed time between logins via Haversine formula. Flags velocities exceeding airliner speed (>900 km/h). | `CRITICAL` |
| **6. Brute-Force & Bot Bursts** | Tracks rapid failed attempts ($\ge 3$ within sliding window) and burst velocities ($\ge 4$ attempts within 10 seconds). | `HIGH` / `CRITICAL` |
| **7. Anonymizing Tor Relays** | Identifies logins originating from known anonymizing Tor exit relays. | `CRITICAL` |

### 4. Client Hardware Entropy Fingerprinting (`static/js/fingerprint.js`)
- Generates 64-character cryptographic SHA-256 hashes using Canvas 2D render tests, WebGL GPU context strings, screen metrics, and system entropy via the Web Crypto API.
- Replaces mock dropdowns with genuine hardware telemetry.

### 5. Instagram Lite Mobile Companion PWA (`/mobile`)
- Mobile security interface featuring:
  - **Stories Status Rings**: Visual threat status and active shift clearance indicator.
  - **Live Security Feed**: Real-time card feed of incoming authentications and alerts.
  - **Bottom Navigation**: Quick switching between Feed, Alerts, Devices, and Shift Settings.
  - **Web App Manifest**: Home-screen installable (`manifest.json`) without Android Studio.

---

## 📁 Project Structure

```text
login-after-dark/
├── app.py                     # Flask Web Application, Session Mgmt & REST APIs
├── database.py                # SQLite WAL Database, Context Managers & Seeding
├── detection_engine.py        # 7-Pillar Dynamic Threat Scoring & Baseline Profiling
├── rate_limiter.py            # Sliding Window Token Limiter for Login Protection
├── event_stream.py            # Server-Sent Events (SSE) Real-Time Pub/Sub Bus
├── geoip_resolver.py          # Dynamic IP-to-Location Resolver with In-Memory Caching
├── requirements.txt           # Python Dependencies
├── test_app.py                # Core Functional & Threat Engine Unit Tests (13 tests)
├── test_concurrency.py        # Multi-User Concurrency Stress Test Suite (3 users, 120 ops)
│
├── demo-attacks/              # Interactive & Automated Threat Simulation Scripts
│   ├── run_demo.py            # Interactive Console Launcher for All Attacks
│   ├── brute_force.py         # Automated Password Spray Simulation
│   ├── impossible_travel.py   # London -> Tokyo Transcontinental Velocity Test
│   ├── new_device_alert.py    # Unrecognized Machine Intrusion & Mobile Alert Test
│   ├── night_shift_check.py   # Authorized Night Operator vs Day Worker Check
│   ├── tor_exit_node.py       # Anonymous Tor Exit Relay Simulation
│   └── README.md              # Demonstration Guide
│
├── templates/
│   ├── index.html             # Desktop SOC Command Center & Collapsible Sandbox
│   └── mobile.html            # Standalone Instagram Lite Mobile Companion App
│
└── static/
    ├── manifest.json          # PWA Web App Manifest for Mobile Home Screen Install
    ├── css/
    │   ├── style.css          # SOC Command Center Cyber Theme & Phone Frame Styling
    │   └── mobile.css         # Modern Instagram-Style Mobile Companion Stylesheet
    └── js/
        ├── app.js             # Desktop SOC Controller, Leaflet Map & SSE Listener
        ├── mobile.js          # Mobile Companion Controller, Web Push & Haptics
        └── fingerprint.js     # Cryptographic Canvas/Hardware Entropy Fingerprinter
```

---

## 🚀 Quickstart & Setup

### 1. Set Up Virtual Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```
* **Desktop SOC Command Center**: Open [`http://127.0.0.1:5000`](http://127.0.0.1:5000)
* **Mobile Companion App**: Open [`http://127.0.0.1:5000/mobile`](http://127.0.0.1:5000/mobile)

### 3. Run the Automated Test Suites
Run the complete unit, functional, and security test suite:
```bash
./venv/bin/python -m unittest discover -s . -p "test_*.py"
```

Run the multi-user concurrency stress test (simulates 3 concurrent active users under 120+ operations):
```bash
./venv/bin/python test_concurrency.py
```

---

## ⚔️ Interactive Threat Attack Demos (`demo-attacks/`)

An interactive launcher is included to demonstrate threat detection in real-time on the SOC dashboard and mobile app:

```bash
./venv/bin/python demo-attacks/run_demo.py
```

Or run individual scenarios directly against the running server:
* **Brute-Force Spraying**: `./venv/bin/python demo-attacks/brute_force.py`
* **Impossible Travel**: `./venv/bin/python demo-attacks/impossible_travel.py`
* **Unrecognized Device**: `./venv/bin/python demo-attacks/new_device_alert.py`
* **Night Shift Policy**: `./venv/bin/python demo-attacks/night_shift_check.py`
* **Tor Exit Relay**: `./venv/bin/python demo-attacks/tor_exit_node.py`

---

## 👥 Default Users (Persistent SQLite)

| Username | Password | Role | Shift Schedule |
| :--- | :--- | :--- | :--- |
| `admin` | `Secr3tP@ss!` | SecOps Lead | **Day Shift** (09:00 – 18:00) |
| `night_analyst` | `NightOwl99!` | Threat Responder | **Night Shift** (22:00 – 07:00) |
| `remote_dev` | `FlexPass123` | Global SRE | **24/7 Flex** (Round-the-clock) |
| `alice` | `CyberPass123` | Security Analyst | **Day Shift** (09:00 – 18:00) |

---

## 📡 REST API Reference

### Real-Time & Session Endpoints
* `GET /api/events/stream`: Real-time Server-Sent Events (SSE) broadcast channel.
* `GET /api/auth/me`: Current session inspection and user identity check.
* `POST /api/auth/logout`: Terminates active authenticated session.

### Core Threat & Authentication APIs
* `POST /api/login`: Evaluates credentials, client fingerprint, IP, and shift policy. Records audit entry.
* `GET /api/stats`: Aggregated metrics (total logins, threat counts, pending alerts, device inventory).
* `GET /api/logs`: Historical audit logs (supports `?limit=N`).
* `GET /api/devices`: Registered device inventory with trust and block statuses.
* `POST /api/devices/action`: Set device status (`BLOCK` / `TRUST`).
* `GET /api/users`: Registered user accounts and active shift configurations.
* `POST /api/users/shift`: Updates employee shift schedule (`user_id` or `username`, `shift_type`, `shift_start_hour`, `shift_end_hour`).
* `GET /api/mobile/alerts`: Pending device alerts for mobile notification queue.
* `POST /api/mobile/action`: Mobile authorization action (`APPROVE` / `BLOCK`).
* `POST /api/clear`: Resets historical audit logs and alert queues.
