"""Start/stop a CloudLab twin out-of-process on an ephemeral port.

Each twin gets its own Python process because moto keeps one global backend per
account id: two servers in one interpreter would see each other's data.
"""
import subprocess
import sys
from pathlib import Path

SERVER = Path(__file__).with_name("server.py")
START_TIMEOUT_S = 60


def start_lab(mode: str, port: int = 0, region: str = "us-east-1") -> tuple[str, subprocess.Popen]:
    """-> (endpoint_url, process). Call stop_lab(process) when done."""
    proc = subprocess.Popen(
        [sys.executable, str(SERVER), "--mode", mode, "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    deadline = START_TIMEOUT_S
    while deadline > 0:
        line = proc.stdout.readline()
        if not line and proc.poll() is not None:
            raise RuntimeError(f"cloudlab {mode} exited during startup ({proc.returncode})")
        if line.startswith("READY "):
            return line.split(" ", 1)[1].strip(), proc
        deadline -= 1
    stop_lab(proc)
    raise RuntimeError(f"cloudlab {mode} did not become ready in {START_TIMEOUT_S}s")


def stop_lab(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    if proc.stdout:
        proc.stdout.close()


def creds() -> dict:
    """Dummy credentials: moto accepts any, nothing here is a real secret."""
    return {"access_key_id": "cloudlab", "secret_access_key": "cloudlab"}
