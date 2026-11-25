"""HoldLab benchmark: holdout twin, deterministic mode, NO operator hints, nuclei disabled.

Usage: python benchmarks/run_holdlab.py [--mode vuln|hardened|both] [--links bare|query]
Starts the labs itself on 8831 (vuln) / 8832 (hardened) and stops them at the end.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
from libella.api import App  # noqa: E402
import libella.tools.runner as runner_mod  # noqa: E402

GT = json.loads((ROOT / "labs/holdlab/ground_truth.json").read_text())
PORTS = {"vuln": 8831, "hardened": 8832}
_orig_resolve = runner_mod.resolve_binary
# without nuclei the run measures native discovery and finishes in minutes
runner_mod.resolve_binary = lambda name: None if name == "nuclei" else _orig_resolve(name)


def _norm(endpoint: str) -> str:
    """Path without query or a trailing numeric object id, so any invoice id matches the seed."""
    path = endpoint.split("://", 1)[-1].split("/", 1)[-1].split("?")[0].rstrip("/")
    return "/" + path.rsplit("/", 1)[0] if path.rsplit("/", 1)[-1].isdigit() else "/" + path


def start_lab(mode: str, links: str) -> subprocess.Popen:
    env = {**os.environ, "LAB_MODE": mode, "LAB_PORT": str(PORTS[mode]), "LAB_LINKS": links}
    p = subprocess.Popen([sys.executable, str(ROOT / "labs/holdlab/app.py")], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORTS[mode]}/status", timeout=1)
            return p
        except OSError:
            time.sleep(0.2)
    p.kill()
    raise RuntimeError(f"holdlab {mode} did not start")


def run_one(mode: str, data_dir: Path, links: str) -> dict:
    base = f"http://127.0.0.1:{PORTS[mode]}"
    app = App(data_dir / f"{mode}_{links}")
    scope = {"targets": [{"kind": "url", "value": base}],
             "categories": ["recon", "web", "api", "infra"],
             "rate_limit_rps": 20, "max_concurrency": 4}
    auth = {"identities": [  # no test_hints, by design
        {**i, "login_url": base + "/auth/session", "username_field": "email",
         "password_field": "passcode"} for i in GT["identities"][:2]]}
    eid = f"eng_{mode}_{links}"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, f"HoldLab {mode}", "safe_active", "draft", json.dumps(scope), json.dumps(auth),
         json.dumps({"max_duration_s": 900, "max_usd": 5}), time.time()))
    started = time.time()
    app.orchestrator().start(eid, mode="deterministic")
    duration = time.time() - started
    findings = app.pipeline.list(eid)
    rank = ["suspected", "observed", "validated", "reported", "retested_persists"]
    rows = []
    for seed in GT["seeded_findings"]:
        want = _norm(seed["endpoint"])
        hits = [f for f in findings
                if f["cwe"] in (seed["cwe"], *seed.get("cwe_also", ()))
                and _norm(f["endpoint"] or "") == want
                # the finding records the endpoint without the query string while the seed
                # names the parameter, so a CWE match on the same path is the seed hit
                and seed["endpoint"].split("?")[0] in (f["endpoint"] or "")]
        best = max(hits, key=lambda f: rank.index(f["state"]) if f["state"] in rank else -1,
                   default=None)
        status = "missed" if best is None else (
            "validated" if best["state"] in ("validated", "reported", "retested_persists")
            else "observed" if best["state"] == "observed" else best["state"])
        rows.append({"seed": seed["id"], "status": status,
                     "finding": best and best["id"], "endpoint": best and best["endpoint"],
                     "state": best and best["state"]})
    matched = {r["finding"] for r in rows if r["finding"]}
    confirmed = [f for f in findings if f["state"] in ("validated", "reported", "retested_persists")]
    verdicts = []
    for f in findings:
        for v in app.db.query("SELECT attempt, method, verdict, detail FROM verifications "
                              "WHERE finding_id=? ORDER BY attempt", (f["id"],)):
            verdicts.append({"finding": f["id"], "title": f["title"], "state": f["state"],
                             "method": v["method"], "verdict": v["verdict"], "detail": v["detail"]})
    n_ex = app.db.query("SELECT COUNT(*) AS n FROM exchanges WHERE engagement_id=?", (eid,))[0]["n"]
    return {"mode": mode, "links": links, "duration_s": round(duration, 1), "exchanges": n_ex,
            "seeds": rows,
            "confirmed_unmatched": [{"id": f["id"], "title": f["title"], "cwe": f["cwe"],
                                     "endpoint": f["endpoint"]}
                                    for f in confirmed if f["id"] not in matched],
            "all_findings": [{"id": f["id"], "state": f["state"], "cwe": f["cwe"],
                              "title": f["title"], "endpoint": f["endpoint"]} for f in findings],
            "verifications": verdicts}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default="both", choices=["vuln", "hardened", "both"])
    p.add_argument("--links", default="bare", choices=["bare", "query"])
    p.add_argument("--data-dir", default=str(ROOT / "benchmark_runs/holdlab"))
    p.add_argument("--out", default=None)
    a = p.parse_args()
    data_dir = Path(a.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for m in (["vuln", "hardened"] if a.mode == "both" else [a.mode]):
        lab = start_lab(m, a.links)
        try:
            results.append(run_one(m, data_dir, a.links))
        finally:
            lab.terminate()
            lab.wait(timeout=10)
    out = Path(a.out or data_dir / f"results_{a.links}.json")
    out.write_text(json.dumps(results, indent=2))
    for r in results:
        print(f"\n=== {r['mode']} (links={r['links']}) {r['duration_s']}s, {r['exchanges']} exchanges ===")
        for s in r["seeds"]:
            print(f"  {s['seed']}: {s['status']:9} {s['state']} {s['endpoint']}")
        print(f"  confirmed but unmatched ({'FALSE POSITIVES' if r['mode'] == 'hardened' else 'extra'}): "
              f"{len(r['confirmed_unmatched'])}")
        for u in r["confirmed_unmatched"]:
            print(f"    - {u['title']} [{u['cwe']}] {u['endpoint']}")
        for v in r["verifications"]:
            if v["state"] not in ("validated", "reported", "retested_persists"):
                print(f"  verdict {v['finding']} ({v['state']}) {v['method']}: {v['verdict']} | {str(v['detail'])[:160]}")
    print(f"\nresults: {out}")


if __name__ == "__main__":
    main()
