"""Cost of the anonymous health probe vs the authenticated inventory route.

Prints median/p95 latency and payload size for GET /api/health (public) and
GET /api/tools (token). No network, no tools executed.
"""
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from fastapi.testclient import TestClient

from libella.api import App, create_api

N = 200


def bench(client, path, headers=None):
    first = client.get(path, headers=headers)
    ts = []
    for _ in range(N):
        t0 = time.perf_counter()
        client.get(path, headers=headers)
        ts.append((time.perf_counter() - t0) * 1000)
    ts.sort()
    return statistics.median(ts), ts[int(N * 0.95) - 1], len(first.content)


def main():
    app = App(tempfile.mkdtemp())
    client = TestClient(create_api(app))
    token = {"Authorization": f"Bearer {app.token}"}
    print(f"tools registered: {len(app.registry.tools)}")
    for label, path, headers in (("health (public)", "/api/health", None),
                                 ("tools  (token)", "/api/tools", token)):
        med, p95, size = bench(client, path, headers)
        print(f"{label}: median {med:.2f} ms  p95 {p95:.2f} ms  payload {size} bytes")


if __name__ == "__main__":
    main()
