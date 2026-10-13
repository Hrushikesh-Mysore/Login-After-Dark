# 🛡️ Login After Dark — Threat Demonstration Suite

This folder contains standalone runnable demonstration scripts that fire simulated authentication threats against your running server (`http://localhost:5000/api/login`).

No dependencies outside standard Python 3 are required.

---

## ⚡ How to Run

Make sure your app is running:
```bash
python app.py
```

Then in another terminal window, navigate here or run any scenario directly:

### 1. Interactive Menu (Easiest)
```bash
python demo-attacks/run_demo.py
```

### 2. Run Individual Attack Demos

| Scenario | Command | Expected Result |
| :--- | :--- | :--- |
| **Brute-Force Spray** | `python demo-attacks/brute_force.py` | 5 rapid incorrect passwords trigger `BRUTE_FORCE` rule with HIGH/CRITICAL threat. |
| **Impossible Travel** | `python demo-attacks/impossible_travel.py` | Logins from London and Tokyo in 2s trigger `IMPOSSIBLE_TRAVEL` (>900 km/h airline speed). |
| **New Device Intrusion** | `python demo-attacks/new_device_alert.py` | Unrecognized laptop triggers `NEW_DEVICE_DETECTED` and fires a push alert on `/mobile`. |
| **Night Shift Policy** | `python demo-attacks/night_shift_check.py` | Shows 3:00 AM login is **SAFE** for night worker, but **SUSPICIOUS** for day worker. |
| **Tor Exit Node** | `python demo-attacks/tor_exit_node.py` | Login from 185.220.101.5 triggers `TOR_EXIT_NODE` threat in Frankfurt. |

---

## 📱 Verifying Results
1. Watch the **Desktop SOC Dashboard** at [`http://localhost:5000`](http://localhost:5000) update live logs and map pins.
2. Watch the **Mobile Companion App** at [`http://localhost:5000/mobile`](http://localhost:5000/mobile) display new device alerts.
