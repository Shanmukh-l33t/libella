"""PairLab benchmark: run a real assessment, score against ground truth.

Usage: python benchmarks/run_pairlab.py [--mode vuln|hardened|both] [--data-dir DIR]
Requires the PairLab twins running (labs/pairlab/app.py) on 8801/8802.
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.api import App

ROOT = Path(__file__).parent.parent
GT = json.loads((ROOT / "labs/pairlab/ground_truth.json").read_text())

HINTS = {
    "ssrf": {"url": "http://127.0.0.1:{port}/fetch", "param": "url",
             "internal_url": "http://127.0.0.1:{port}/internal/meta", "marker": "LABFAKEKEY0000"},
    "sqli_union": {"url": "http://127.0.0.1:{port}/api/products", "param": "category",
                   "payload": "' UNION SELECT id,username,password,role FROM users--",
                   "marker": "alice"},
    "idor": {"url_template": "http://127.0.0.1:{port}/api/orders/{id}",
             "foreign_ids": [102], "foreign_marker": '"user_id":2', "identity": "alice"},
}


def run_one(mode: str, data_dir: Path) -> dict:
    port = 8801 if mode == "vuln" else 8802
    base = f"http://127.0.0.1:{port}"
    app = App(data_dir / mode)
    hints = json.loads(json.dumps(HINTS).replace("{port}", str(port)))
    scope = {"targets": [{"kind": "url", "value": base}],
             "categories": ["recon", "web", "api", "infra"],
             "rate_limit_rps": 20, "max_concurrency": 4}
    auth = {"identities": [
        {**i, "login_url": base + "/login", "username_field": "username",
         "password_field": "password"} for i in GT["identities"][:2]
    ], "test_hints": hints}
    eid = app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (f"eng_{mode}", f"PairLab {mode}", "safe_active", "draft", json.dumps(scope),
         json.dumps(auth), json.dumps({"max_duration_s": 900, "max_usd": 5}), time.time()),
    ).lastrowid and f"eng_{mode}"
    started = time.time()
    orch = app.orchestrator()
    orch.start(eid, mode="deterministic")
    duration = time.time() - started
    findings = app.pipeline.list(eid)
    confirmed = [f for f in findings if f["state"] in ("validated", "reported", "retested_persists")]
    # score
    detected, missed = [], []
    for seed in GT["seeded_findings"]:
        path = seed["endpoint"].split("?")[0]
        hit = next((f for f in confirmed
                    if f["cwe"] == seed["cwe"] and (path in (f["endpoint"] or "") or (f["endpoint"] or "") in seed["endpoint"])), None)
        if hit:
            detected.append({"seed": seed["id"], "finding": hit["id"], "title": hit["title"],
                             "state": hit["state"]})
        else:
            missed.append({"seed": seed["id"], "title": seed["title"], "cwe": seed["cwe"]})
    matched_ids = {d["finding"] for d in detected}
    unmatched = [f for f in confirmed if f["id"] not in matched_ids]
    result = {
        "mode": mode, "duration_s": round(duration, 1),
        "findings_total": len(findings), "confirmed": len(confirmed),
        "seeds_total": len(GT["seeded_findings"]),
        "detected": len(detected), "missed": missed,
        "unmatched_confirmed": [{"id": f["id"], "title": f["title"], "cwe": f["cwe"],
                                 "endpoint": f["endpoint"]} for f in unmatched],
        "false_positives": len(unmatched) if mode == "hardened" else 0,
        "detail": detected,
        "states": {f["id"]: f["state"] for f in findings},
        "chain": app.evidence.verify_chain(eid),
    }
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default="both", choices=["vuln", "hardened", "both"])
    p.add_argument("--data-dir", default=str(ROOT / "benchmark_runs"))
    p.add_argument("--out", default=str(ROOT / "benchmark_runs/results.json"))
    args = p.parse_args()
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    modes = ["vuln", "hardened"] if args.mode == "both" else [args.mode]
    results = [run_one(m, data_dir) for m in modes]
    Path(args.out).write_text(json.dumps(results, indent=2))
    for r in results:
        print(f"\n=== {r['mode']} === {r['duration_s']}s")
        print(f"confirmed {r['confirmed']}/{r['seeds_total']} seeds | missed: {[m['seed'] for m in r['missed']]}")
        print(f"unmatched confirmed (FP if hardened): {len(r['unmatched_confirmed'])}")
        for u in r["unmatched_confirmed"]:
            print(f"  - {u['title']} [{u['cwe']}] {u['endpoint']}")
        print(f"evidence chain: {r['chain']}")
    print(f"\nresults: {args.out}")


if __name__ == "__main__":
    main()
