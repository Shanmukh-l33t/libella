"""Performance measurement: real CPU/RSS/wall-clock for a full assessment.

Runs the deterministic PairLab assessment while sampling process RSS and
CPU. Writes benchmark_runs/perf.json. No invented numbers.
"""
import json
import resource
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.api import App

ROOT = Path(__file__).parent.parent


def rss_mb() -> float:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


def main():
    app = App(ROOT / "benchmark_runs" / "perf")
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
             "categories": ["recon", "web", "api", "infra"], "rate_limit_rps": 20}
    eid = "eng_perf"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, "Perf measurement", "safe_active", "draft", json.dumps(scope), "{}",
         json.dumps({"max_duration_s": 900}), time.time()))
    peak = [0.0]
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            peak[0] = max(peak[0], rss_mb())
            time.sleep(0.2)

    t = threading.Thread(target=sampler, daemon=True)
    t.start()
    r0 = resource.getrusage(resource.RUSAGE_SELF)
    wall0 = time.time()
    app.orchestrator().start(eid, mode="deterministic")
    wall = time.time() - wall0
    r1 = resource.getrusage(resource.RUSAGE_SELF)
    c1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    stop.set()
    t.join(timeout=2)
    findings = app.pipeline.list(eid)
    out = {
        "target": "PairLab vuln (deterministic + nuclei)",
        "wall_seconds": round(wall, 1),
        "cpu_user_seconds": round(r1.ru_utime - r0.ru_utime, 2),
        "cpu_system_seconds": round(r1.ru_stime - r0.ru_stime, 2),
        "scanner_children_cpu_seconds": round((c1.ru_utime + c1.ru_stime), 2),
        "peak_rss_mb_platform_process": round(peak[0], 1),
        "findings": len(findings),
        "validated": sum(1 for f in findings if f["state"] == "validated"),
        "tool_calls": app.db.one("SELECT COUNT(*) n FROM tool_calls WHERE engagement_id=?", (eid,))["n"],
        "llm_tokens": 0, "llm_cost_usd": 0,
        "evidence_objects": app.evidence.verify_chain(eid)["checked"],
    }
    (ROOT / "benchmark_runs" / "perf.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
