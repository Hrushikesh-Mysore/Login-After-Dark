# Project Progress & Architecture Evolution Checklist

This document tracks the initial state of the **Login After Dark** application, architectural gaps identified, and the phased improvements implemented.

---

## 1. Initial State Checklist (What Was There Before)

### Security & Architecture
- [x] **Hardcoded Secret Key**: Flask app used a static secret key in `app.py`.
- [x] **Insecure Server Runtime**: `debug=True` bound to `0.0.0.0` (exposing remote debugger console to the local network).
- [x] **No Session Management**: Logging in did not establish an authenticated session, cookie, or JWT; dashboard and mobile views were completely unauthenticated.
- [x] **Spoofable Client Telemetry**: Backend blindly trusted client-supplied `ip` and `device_fingerprint` in JSON payload.
- [x] **No Rate Limiting**: `/api/login` and API endpoints had no request throttling.

### Database & Concurrency
- [x] **SQLite Lock Vulnerability**: Default SQLite rollback journal mode without WAL mode or busy timeouts.
- [x] **Unclosed Database Connections**: Connections were created in functions without guaranteed cleanup, triggering Python 3.13 `ResourceWarning: unclosed database`.
- [x] **Missing Indexes**: Audit logs and alert tables lacked lookup indexes for fast real-time queries.

### Real-Time & Mobile Alerting
- [x] **No True Push Notifications**: Mobile page relied on client-side HTTP polling every 3 seconds (`setInterval`).
- [x] **No Web Push / Background Alerts**: If the browser tab was closed or minimized, no system alerts were received.
- [x] **Fake Mobile App**: Mobile companion was just a web page with CSS phone styling; no Service Worker or Web App Manifest.

### Anomaly & Threat Detection Engine
- [x] **Static Rule Engine ("Fake AI")**: No statistical baseline or dynamic scoring; static point additions (+35, +40, +65).
- [x] **Hardcoded 8-City Geo Lookup**: Only recognized 8 cities hardcoded in a dictionary; any real location outside these was unknown.
- [x] **Hardcoded 4-IP Threat List**: Malicious IPs were restricted to 4 mock addresses.

### UI & UX
- [x] **Simulation Dropdowns Mixed with Login**: Login form had dropdowns forcing users to manually choose their location, device, and hour, rather than capturing real client telemetry.
- [x] **No Real User Experience**: No real authenticated dashboard state after successful login.

---

## 2. Evolution & Fixes Checklist (Phased Progress)

### Phase 0: Baseline Assessment & Virtual Environment Setup
- [x] Created Python virtual environment (`venv`).
- [x] Installed all required dependencies (`Flask`, `Werkzeug`, `Jinja2`, `MarkupSafe`, `click`, `blinker`).
- [x] Executed and passed initial unit test suite (`test_app.py`).
- [x] Conducted in-depth architecture audit and flaw analysis.
- [x] Initialized tracking documents (`progress.md` and `plan.md`).

### Phase 1: Security Hardening & Session Architecture
- [x] Environment variable configuration (`.env` / system env) for `SECRET_KEY` and debug modes.
- [x] Remove `debug=True` binding on `0.0.0.0` in production/demo mode.
- [x] Implement secure cookie sessions (HTTPOnly, SameSite, Secure) for authenticated users.
- [x] Implement real authentication routes (`/api/auth/me`, `/api/auth/logout`) with access control decorators.
- [x] Enforce server-side IP extraction (prevent client spoofing of `ip` parameter in production login).
- [x] Add rate limiting (`rate_limiter.py` sliding window limiter) to prevent brute-force spraying.

### Phase 2: Database Concurrency & Reliability
- [x] Configure SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL`).
- [x] Set `PRAGMA busy_timeout = 5000` to prevent database locks under concurrent access.
- [x] Refactor connection lifecycle into robust `@contextmanager` ensuring 100% closed connections (eliminated all ResourceWarnings).
- [x] Add indexes on `auth_logs(username, epoch)`, `device_alerts(user_id, status)`, and `devices(user_id, device_fingerprint)`.
- [x] Verified with multi-threaded stress test: 5 concurrent workers executing 75 queries simultaneously without locks.
- [x] Created `demo-attacks/` folder with standalone runnable scripts (`brute_force.py`, `impossible_travel.py`, `new_device_alert.py`, `night_shift_check.py`, `tor_exit_node.py`, and interactive `run_demo.py`).
- [x] Transformed `/mobile` into an **Instagram Lite PWA** interface (stories status rings, live security post feed, bottom navigation, 1-tap shift switcher, `manifest.json` for home screen install without Android Studio).

### Phase 3: Real-Time Communication & Web Push Notifications
- [x] Implement Server-Sent Events (SSE) `/api/events/stream` (`event_stream.py`) for real-time log and alert broadcasting (<100ms latency).
- [x] Eliminate 3-second HTTP polling loops from both desktop dashboard and mobile page (replaced by EventSource stream listener).
- [x] Add HTML5 Web Notification API (`Notification.requestPermission()`) on the mobile companion page.
- [x] Add audio/haptic vibration triggers (`navigator.vibrate`) when an unrecognized device attempts login.
- [x] Added unit tests for SSE pub/sub and HTTP stream in `test_app.py` (10/10 tests passing).

### Phase 4: Genuine Client Telemetry & Device Fingerprinting
- [x] Implement client-side canvas/hardware entropy fingerprinting script (`fingerprint.js` with SHA-256 Web Crypto hash).
- [x] Add automatic real browser geolocation resolution with graceful IP-based fallback.
- [x] Separate the "Real Login Portal" from the "Threat Simulator Sandbox" (clean UI distinction with collapsible simulation accordion).

### Phase 5: Detection Engine Modernization & Dynamic Scoring
- [x] Implement dynamic user behavioral baseline (historical location profiling `NEW_LOCATION_ANOMALY`).
- [x] Continuous time-gradient shift deviation calculation (differentiating marginal overtime +1h vs extreme off-hours access).
- [x] Expand GeoIP lookup engine with IP-based geolocation resolver and in-memory caching (`geoip_resolver.py`).
- [x] Weighted anomaly risk matrix with normalized 0–100 scoring and clear tier thresholds.
- [x] Expanded test suite with Phase 5 verification tests (13/13 passing tests).

### Phase 6: Testing, Scalability Verification & Polish
- [x] Concurrency stress test simulating 3 simultaneous users executing 120+ interleaved operations (logins, shift updates, mobile alert resolutions, and SSE reads) with 0 database locks (`test_concurrency.py`).
- [x] Verified zero 500 errors, zero lock contention, PRAGMA ok database integrity, and ~70 ops/sec throughput.
- [x] End-to-end verification of `demo-attacks/` suite against live backend server.
- [x] System documentation & operational README update.
- [x] Full automated test suite passes (15/15 tests passing).

### Phase 7: Mission Control Launcher, Mobile PWA Install Station & 1-Click Execution Suite
- [x] **One-Click Automated Launcher Script (`launch.sh`)**: Starts backend with dependency checks, determines local LAN IP, auto-opens browser to Mission Control, and sets graceful Ctrl+C server trap.
- [x] **Root Launch File (`LAUNCHER.html`)**: Double-clickable HTML file with direct localhost links, dynamic server health detection, mobile installation guide, and browser-driven scenario triggers.
- [x] **Desktop Shortcut (`LoginAfterDark.desktop`)**: Standard Linux desktop entry for 1-click startup from desktop / file manager.
- [x] **Mission Control Web Portal (`/launcher` & `templates/launcher.html`)**: Cyberpunk SOC control hub connecting the desktop dashboard, mobile PWA, network discovery, and batch threat triggers.
- [x] **1-Click Batch Execution Suite (`/api/simulate/run-all`)**: Fires all 6 enterprise security scenarios sequentially (Night Shift, Brute Force, Tor Exit Node, Impossible Travel, Shift Violation, New Device Intrusion with Mobile Push Alert) with live progression tracking.
- [x] **Zero-Android-Studio Mobile Installation Station**: Client-side QR code generator (`qrcode.min.js`) pointing to local Wi-Fi LAN IP, with step-by-step guides for Android Chrome & iOS Safari.
- [x] **PWA Service Worker & App Manifest (`sw.js` & `static/img/`)**: Standalone display mode, offline cache, 192x192 & 512x512 app icons, and vibration alert integration.

