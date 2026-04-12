#!/usr/bin/env python3
"""
TeamCyberOps Suite V5
Elite Bug Bounty Framework — AI-Powered — Production Ready
"""
import sys, os, threading
sys.path.insert(0, os.path.dirname(__file__))

# ── Suppress harmless CTk/Tkinter shutdown noise ──────────────────────────────
# These errors appear when window closes while CTk internal after() timers
# are still pending. They are 100% harmless — cosmetic terminal noise only.
_NOISE = (
    "main thread is not in main loop",
    "invalid command name",
    "application has been destroyed",
    "check_dpi_scaling",
)

_orig_excepthook = sys.excepthook
def _clean_excepthook(exc_type, exc_val, exc_tb):
    if any(s in str(exc_val) for s in _NOISE):
        return
    _orig_excepthook(exc_type, exc_val, exc_tb)
sys.excepthook = _clean_excepthook

_orig_thread_hook = threading.excepthook
def _clean_thread_hook(args):
    if any(s in str(args.exc_value) for s in _NOISE):
        return
    _orig_thread_hook(args)
threading.excepthook = _clean_thread_hook

# Intercept Tcl background errors written to stderr (numeric ID spam)
import io as _io
class _StderrFilter(_io.TextIOWrapper):
    """Filter known harmless Tcl after()-on-closed-window stderr spam."""
    def __init__(self, wrapped): self._w = wrapped
    def write(self, s):
        if any(x in s for x in _NOISE + ('"after" script',)):
            return len(s)
        return self._w.write(s)
    def flush(self):  self._w.flush()
    def fileno(self): return self._w.fileno()
sys.stderr = _StderrFilter(sys.__stderr__)
# ─────────────────────────────────────────────────────────────────────────────

# ── Headless / display check ──────────────────────────────────────────────────
if not os.environ.get("DISPLAY") and sys.platform != "win32":
    os.environ.setdefault("DISPLAY", ":0")


def main():
    from app.core.database import init_db, sync_logs_to_projects
    init_db()

    # Sync any logs/<project>/ folders → DB before UI starts
    try:
        added = sync_logs_to_projects()
        if added:
            print(f"[*] Synced {len(added)} project(s) from logs/: {', '.join(added)}")
    except Exception as _e:
        print(f"[!] Log sync warning: {_e}")

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
