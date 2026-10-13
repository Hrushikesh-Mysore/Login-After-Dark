#!/usr/bin/env python3
"""
Interactive Attack & Anomaly Scenario Launcher
Run this script to select and fire any threat demonstration against the running application.
"""

import os
import sys
import subprocess

DEMOS = [
    ("1", "Brute-Force Password Spray Attack", "brute_force.py"),
    ("2", "Impossible Geographic Travel Velocity (London -> Tokyo)", "impossible_travel.py"),
    ("3", "Unrecognized Device Intrusion (Fires Mobile Push Alert)", "new_device_alert.py"),
    ("4", "Night-Shift Policy Comparison (Authorized vs Unauthorized)", "night_shift_check.py"),
    ("5", "Anonymous Tor Exit Node Login (Frankfurt)", "tor_exit_node.py"),
    ("6", "Run All Demos in Sequence", "ALL")
]

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    print("\n" + "=" * 65)
    print("🌙 LOGIN AFTER DARK — INTERACTIVE DEMO ATTACK SUITE")
    print("=" * 65)
    print("Make sure the app is running at http://localhost:5000\n")

    for key, name, _ in DEMOS:
        print(f"  [{key}] {name}")
    print("  [0] Exit")

    print("=" * 65)
    choice = input("Select a scenario to execute [1-6]: ").strip()

    if choice == "0":
        print("Exiting.")
        sys.exit(0)

    selected = next((d for d in DEMOS if d[0] == choice), None)
    if not selected:
        print("Invalid selection.")
        sys.exit(1)

    _, name, script_name = selected
    print(f"\n🚀 Running: {name}...\n")

    if script_name == "ALL":
        for _, n, s in DEMOS[:-1]:
            print(f"\n---> Executing {n}...")
            subprocess.run([sys.executable, os.path.join(script_dir, s)])
    else:
        subprocess.run([sys.executable, os.path.join(script_dir, script_name)])

if __name__ == "__main__":
    main()
