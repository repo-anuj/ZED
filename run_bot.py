#!/usr/bin/env python3
"""
ZED Attack Simulator Bot CLI
Allows standalone adversary emulation from the command line or via script.
Automatically activates the project virtual environment.
"""

import sys
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BASE_DIR / ".venv" / "bin" / "python"

if VENV_PYTHON.exists() and sys.executable != str(VENV_PYTHON):
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON)] + sys.argv)

import argparse
import time
from zed.bot.attack_simulator import bot

def main():
    parser = argparse.ArgumentParser(description="ZED Attack Simulator Bot")
    parser.add_argument("--scenario", "-s", type=int, choices=[1, 2, 3, 4, 5, 6],
                        help="Run specific attack scenario (1: Web Shell, 2: Cron, 3: Ransomware, 4: Beacon, 5: Brute Force, 6: Zero-Day)")
    parser.add_argument("--all", "-a", action="store_true",
                        help="Run all 6 attack scenarios in sequence with delay")

    args = parser.parse_args()

    print("""
======================================================================
  [!] ZED ADVERSARY EMULATION BOT (STANDALONE CLI)
  Safe Testing Lab for Linux Mint
======================================================================
    """)

    if args.all:
        print("[*] Running full suite of 6 attack scenarios...")
        for sc in range(1, 7):
            print(f"\n---> Commencing Scenario {sc}...")
            res = bot.run_scenario(sc)
            print(f"---> Result: {res}")
            time.sleep(2)
        print("\n[+] Full adversary emulation complete. Check web interface or zed.db for alerts.")
        return

    if args.scenario:
        res = bot.run_scenario(args.scenario)
        print(f"\n[+] Scenario {args.scenario} Execution Finished: {res}")
        return

    # Interactive CLI Menu
    while True:
        print("\nChoose an attack scenario to simulate:")
        print("  [1] Web Shell Spawning Bash (T1059.004)")
        print("  [2] Rogue Scheduled Task / Cron Persistence (T1053.003)")
        print("  [3] Ransomware File Rapid Rename / Encryption (T1486)")
        print("  [4] Periodic Command & Control Outbound Beaconing (T1071.001)")
        print("  [5] Authentication Brute Force Dictionary Attack (T1110.001)")
        print("  [6] ★ SIMULATED ZERO-DAY (Signature Evasion / ML Proof)")
        print("  [7] Run All Scenarios Sequentially")
        print("  [0] Exit")

        try:
            choice = input("\nroot@zed-attacker:~$ ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting attack simulator.")
            break

        if choice == "0":
            break
        elif choice in ["1", "2", "3", "4", "5", "6"]:
            sc_id = int(choice)
            res = bot.run_scenario(sc_id)
            print(f"\nScenario {sc_id} output: {res}")
        elif choice == "7":
            for sc in range(1, 7):
                bot.run_scenario(sc)
                time.sleep(1.5)
        else:
            print("Invalid selection. Enter 0-7.")

if __name__ == "__main__":
    main()
