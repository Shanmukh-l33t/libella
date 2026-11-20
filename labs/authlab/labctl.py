"""Start an AuthLab instance in-process on an ephemeral port (tests, benchmark).

Loading app.py twice under different module names gives each copy its own Flask
app and session store, so vuln and hardened run side by side.
"""
import importlib.util
import os
import threading
from pathlib import Path

from werkzeug.serving import make_server

APP_PATH = Path(__file__).with_name("app.py")


def start_lab(mode: str):
    """-> (base_url, server). Call server.shutdown() when done."""
    prev = os.environ.get("LAB_MODE")
    os.environ["LAB_MODE"] = mode
    try:
        spec = importlib.util.spec_from_file_location(f"authlab_{mode}", APP_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        if prev is None:
            os.environ.pop("LAB_MODE", None)
        else:
            os.environ["LAB_MODE"] = prev
    srv = make_server("127.0.0.1", 0, mod.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_port}", srv
