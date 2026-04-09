#!/usr/bin/env python3
"""
TeamCyberOps Suite V5
Elite Bug Bounty Framework — AI-Powered — Production Ready
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

# ── Headless / display check ──────────────────────────────────────
import os
if not os.environ.get("DISPLAY") and sys.platform != "win32":
    os.environ.setdefault("DISPLAY", ":0")

def main():
    from app.core.database import init_db
    init_db()

    from app.ui.login import LoginWindow
    login = LoginWindow()

    if login.user:
        from app.ui.app_window import App
        App(login.user)
    else:
        print("[!] Login cancelled or failed.")
        sys.exit(0)

if __name__ == "__main__":
    main()
