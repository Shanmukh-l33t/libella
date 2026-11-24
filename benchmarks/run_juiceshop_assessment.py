"""Juice Shop assessment: measure Libella's reach on an unfamiliar, authorised, self-hosted lab.

Start the lab first (local container only, port 8861):
    docker run -d --rm -p 8861:3000 --name libella-juice bkimminich/juice-shop
Run: python benchmarks/run_juiceshop_assessment.py [--data-dir DIR] [--out FILE]

No ground truth is fed to the engine. The engagement is created through the real HTTP API
route; the run is deterministic with nuclei made unavailable. Findings are read from SQLite.
"""
import argparse
import collections
import json
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

import libella  # noqa: E402
import libella.tools.runner as runner  # noqa: E402
from libella.api import App, create_api  # noqa: E402

BASE = "http://127.0.0.1:8861"  # the only port this harness may touch
CONFIRMED = ("validated", "reported", "retested_persists")

# Juice Shop's public challenge categories, reported against after the run (never fed to the engine).
CATEGORIES = {
    "Injection": {"CWE-89", "CWE-943", "CWE-77", "CWE-78", "CWE-94"},
    "Broken Access Control": {"CWE-284", "CWE-639", "CWE-862", "CWE-863", "CWE-285", "CWE-425"},
    "Cross Site Scripting": {"CWE-79"},
    "Broken Authentication": {"CWE-287", "CWE-307", "CWE-521", "CWE-798", "CWE-640", "CWE-1390"},
    "Sensitive Data Exposure": {"CWE-200", "CWE-538", "CWE-548", "CWE-532", "CWE-312", "CWE-359"},
    "Security Misconfiguration": {"CWE-16", "CWE-693", "CWE-942", "CWE-1021", "CWE-614", "CWE-1004", "CWE-346"},
    "Improper Input Validation": {"CWE-20", "CWE-434", "CWE-22", "CWE-1284"},
    "XXE": {"CWE-611"},
    "Insecure Deserialization": {"CWE-502"},
    "Vulnerable Components": {"CWE-1104", "CWE-937", "CWE-1035"},
    "Cryptographic Issues": {"CWE-327", "CWE-328", "CWE-330", "CWE-326", "CWE-916"},
    "Unvalidated Redirects": {"CWE-601"},
    "Broken Anti Automation": {"CWE-799", "CWE-770", "CWE-307"},
    "Security through Obscurity": {"CWE-656"},
    "Server-Side Request Forgery": {"CWE-918"},
}


def preflight():
    with urllib.request.urlopen(BASE, timeout=10) as r:
        assert r.status == 200, f"lab not ready: HTTP {r.status}"
    assert str(ROOT) in libella.__file__, f"libella imported from {libella.__file__}, not this worktree"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--out", default=str(ROOT / "benchmark_runs/juiceshop_results.json"))
    args = ap.parse_args()
    preflight()

    real_resolve = runner.resolve_binary  # captured before patching

    def no_nuclei(name):
        return None if name == "nuclei" else real_resolve(name)
    runner.resolve_binary = no_nuclei

    from starlette.testclient import TestClient
    data_dir = Path(args.data_dir or tempfile.mkdtemp(prefix="juiceshop_run_"))
    app = App(data_dir)
    client = TestClient(create_api(app), headers={"Authorization": f"Bearer {app.token}"})
    r = client.post("/api/engagements", json={
        "name": "OWASP Juice Shop (local lab)", "profile": "safe_active",
        "scope": {"targets": [{"kind": "url", "value": BASE}],
                  "categories": ["recon", "web", "api"], "rate_limit_rps": 10},
        "budgets": {"max_duration_s": 900}})
    r.raise_for_status()
    eid = r.json()["id"]

    t0 = time.time()
    error = None
    try:
        app.orchestrator().start(eid, mode="deterministic")
    except Exception as e:  # a crash is a result, not something to hide
        error = f"{type(e).__name__}: {e}"
    wall = round(time.time() - t0, 1)

    db = app.db
    eng = db.one("SELECT status, status_detail FROM engagements WHERE id=?", (eid,))
    findings = db.query("SELECT * FROM findings WHERE engagement_id=? ORDER BY severity, cwe", (eid,))
    degr = [json.loads(d["payload_json"]) for d in
            db.query("SELECT payload_json FROM events WHERE engagement_id=? AND kind='degradation'", (eid,))]
    n_ex = db.one("SELECT COUNT(*) n FROM exchanges WHERE engagement_id=?", (eid,))["n"]
    by_cwe = collections.Counter((f["cwe"], f["state"]) for f in findings)
    found_cwes = {f["cwe"] for f in findings}
    missed = [c for c, cwes in CATEGORIES.items() if not cwes & found_cwes]

    rows = []
    for f in findings:
        ids = json.loads(f["evidence_ids_json"] or "[]")
        proof = [db.one("SELECT method, url, status FROM exchanges WHERE evidence_id=?", (i,)) for i in ids]
        rows.append({"id": f["id"], "title": f["title"], "cwe": f["cwe"], "severity": f["severity"],
                     "state": f["state"], "endpoint": f["endpoint"], "proof": [p for p in proof if p]})
    out = {"image_note": "bkimminich/juice-shop:latest", "target": BASE, "data_dir": str(data_dir),
           "engagement": eid, "engagement_status": eng["status"], "status_detail": eng["status_detail"],
           "run_error": error, "wall_clock_s": wall, "exchanges": n_ex, "findings_total": len(findings),
           "validated": sum(f["state"] in CONFIRMED for f in findings),
           "observed_only": sum(f["state"] not in CONFIRMED for f in findings),
           "by_cwe_state": {f"{c} {s}": n for (c, s), n in sorted(by_cwe.items(), key=str)},
           "categories_without_a_finding": missed, "degradations": degr, "findings": rows,
           "chain": app.evidence.verify_chain(eid)}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2, default=str))
    print(json.dumps({k: v for k, v in out.items() if k != "findings"}, indent=2, default=str))
    for f in rows:
        print(f"{f['id']} {f['state']:10} {f['severity']:8} {f['cwe']} {f['title']} @ {f['endpoint']}")


if __name__ == "__main__":
    main()
