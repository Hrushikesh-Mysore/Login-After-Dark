# Architectural Improvement & Hardening Plan

This document defines the step-by-step roadmap to transform **Login After Dark** into a secure, scalable (2–3 concurrent users without locking), reliable, and real-time authentication anomaly defense system.

---

## 📊 Phase Summary

| Phase | Title | Status | Scope |
| :---: | :--- | :---: | :--- |
| **0** | Baseline & Diagnostic Setup | ✅ **COMPLETED** | Venv setup, test verification, codebase & flaw audit |
| **1** | Security Hardening & Session Management | ✅ **COMPLETED** | Environment configs, secure sessions, rate limiting, anti-spoofing |
| **2** | SQLite Concurrency & Reliability | ✅ **COMPLETED** | WAL mode, busy timeout, connection context managers, indexing |
| **3** | Real-Time Push (SSE) & WebPush Notifications | ✅ **COMPLETED** | Server-Sent Events, instant alert dispatch, browser notification API |
| **4** | Real Device Telemetry & Browser Fingerprinting | ✅ **COMPLETED** | Hardware/Canvas entropy fingerprinting, real GPS/IP resolution |
| **5** | Dynamic Detection Engine & Anomaly Scoring | ✅ **COMPLETED** | User behavioral baseline, dynamic scoring, IP geo-resolution |
| **6** | Integration Verification & Scalability Stress Test | ✅ **COMPLETED** | Concurrency stress testing (3 users, 120 ops), attack suite verification, documentation |

---

## 🔍 Detailed Breakdown of Phases

### ✅ Phase 0: Baseline & Diagnostic Setup (DONE)
- **Completed**:
  1. Set up clean Python virtual environment and installed dependencies.
  2. Verified baseline functionality and ran unit test suite (`test_app.py`).
  3. Performed full codebase security & architectural audit.
  4. Created `progress.md` tracking initial flaws and target checklist.

---

### ✅ Phase 1: Security Hardening & Session Architecture (DONE)
- **Completed**:
  1. **Safe Configuration**: Secret key dynamically initialized or sourced from `SECRET_KEY`; `debug=False` by default on network interfaces.
  2. **Real Authentication Sessions**: Secure HTTPOnly SameSite cookies, session tracking for user authentication (`/api/auth/me`).
  3. **Access Control & Logout**: Implemented `@login_required` decorators and session termination endpoint (`/api/auth/logout`).
  4. **Strict IP Detection & Anti-Spoofing**: Production authentication strictly binds to genuine connection IP (`request.remote_addr` / trusted proxies), preventing custom client IP forging.
  5. **In-Memory Rate Limiting**: Added `rate_limiter.py` with sliding window token limiter (25 req/min) protecting `/api/login` against brute force.

---

### ✅ Phase 2: SQLite Concurrency & Reliability (DONE)
- **Completed**:
  1. **WAL Mode Activation**: `PRAGMA journal_mode = WAL;` enabled for concurrent non-blocking reads and writes.
  2. **Busy Timeout**: `PRAGMA busy_timeout = 5000;` prevents database lock crashes during simultaneous writes.
  3. **Thread-Safe Context Manager**: Refactored `get_db()` with `@contextmanager` and guaranteed connection closing (0 resource warnings).
  4. **Performance Indexing**: Added SQLite indexes on `auth_logs(username, epoch)`, `device_alerts(user_id, status)`, and `devices(user_id, device_fingerprint)`.
  5. **Stress Verified**: Passed 5-thread concurrent execution (75 simultaneous queries) without lock contention.
  6. **Interactive Attack Suite**: Created `demo-attacks/` folder with 5 standalone runnable Python threat scripts and interactive runner (`run_demo.py`).
  7. **Instagram Lite Mobile PWA**: Built `/mobile` with stories status rings, live audit post cards, bottom navigation, and home-screen install (`manifest.json`) without Android Studio.

---

### ✅ Phase 3: Real-Time Event Streaming & WebPush Notifications (DONE)
- **Completed**:
  1. **Server-Sent Events (SSE)**: Built `event_stream.py` pub/sub dispatcher and `/api/events/stream` HTTP endpoint with keepalive heartbeat.
  2. **Zero-Polling Frontend**: Replaced 3-4s HTTP polling in `app.js` and `mobile.js` with real-time `EventSource` listeners (<100ms push latency).
  3. **Browser Push & Haptics**: Integrated HTML5 Web Notification API and `navigator.vibrate` alert triggers for instant out-of-tab mobile alerts.
  4. **Test Suite Expansion**: Added unit tests for SSE stream handshake and event broadcast in `test_app.py` (10/10 tests pass).

---

### ✅ Phase 4: Genuine Client Telemetry & Browser Fingerprinting (DONE)
- **Completed**:
  1. **Cryptographic Fingerprinting**: Built `static/js/fingerprint.js` utilizing Canvas 2D, WebGL renderer, and system entropy hashed via Web Crypto SHA-256.
  2. **Clean UI Separation**: Redesigned dashboard login form to automatically capture genuine hardware telemetry and GPS by default, cleanly isolating simulation overrides into a collapsible testing accordion.
  3. **Real Client Data Flow**: Production sign-in requests now send real SHA-256 hardware fingerprints and genuine connection IPs directly to SQLite.

---

### ✅ Phase 5: Dynamic Detection Engine & Anomaly Scoring (DONE)
- **Completed**:
  1. **Continuous Time-Gradient Shift Deviation**: Replaced rigid binary shift evaluation with a 24-hour circular distance calculation. Differentiates marginal overtime (+1h -> LOW risk, weight 15) from moderate overtime (+2–3h -> MEDIUM risk, weight 25) and extreme middle-of-the-night off-hours (+6h -> MEDIUM risk, weight 35).
  2. **Dynamic User Historical Baseline (`NEW_LOCATION_ANOMALY`)**: Profiles previous successful authentications for the user. Flags first-time logins from unfamiliar geographic locations while preserving authorized night-shift immunity.
  3. **Dynamic GeoIP Lookup Engine (`geoip_resolver.py`)**: Seamless cascade combining in-memory caching, offline corporate office detection for private/LAN IPs, live external HTTP GeoIP queries with 1.2s timeout, and preset simulation fallbacks.
  4. **Automated Unit Verification**: Added comprehensive unit test coverage (`test_shift_gradient_deviation`, `test_new_location_historical_baseline`, `test_geoip_resolver_resolution`). 13/13 unit tests pass.

---

### ✅ Phase 6: Integration Verification & Scalability Stress Test (DONE)
- **Completed**:
  1. **Multi-User Concurrency Stress Test**: Built [`test_concurrency.py`](file:///home/hrushikesh/Projects/Personal/Login-After-Dark/test_concurrency.py) simulating 3 simultaneous active users performing 120 interleaved operations (logins, shift mutations, mobile alert resolutions, device checks, and real-time SSE dispatches).
  2. **Zero Lock Contention**: Verified SQLite WAL mode and busy timeouts guaranteed 0 database locks, 0 server (500) errors, and PRAGMA integrity check `ok`.
  3. **Demo Attacks Validation**: Verified all 5 attack scenarios in [`demo-attacks/`](file:///home/hrushikesh/Projects/Personal/Login-After-Dark/demo-attacks/) against the hardened live server.
  4. **Documentation & Operational Polish**: Updated [`README.md`](file:///home/hrushikesh/Projects/Personal/Login-After-Dark/README.md) and [`progress.md`](file:///home/hrushikesh/Projects/Personal/Login-After-Dark/progress.md).
  5. **Automated Test Coverage**: 14/14 automated tests pass cleanly.

---

## 🏁 Project Status: All Phases Fully Completed!
The entire roadmap from Phase 0 to Phase 6 has been successfully developed, stress-tested, and verified.
