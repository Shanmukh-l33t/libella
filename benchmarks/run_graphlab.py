"""GraphLab benchmark: assess both twins, verify every finding, score vs ground truth.

Usage: python benchmarks/run_graphlab.py [--mode vuln|hardened|both] [--data-dir DIR]
Starts the lab twins in-process on ephemeral localhost ports (no external egress).
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "labs/graphlab"))

import graphlab_labctl as labctl  # noqa: E402
from libella.api import App  # noqa: E402
from libella.graphql_audit import assess_graphql  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.verifier import Verifier  # noqa: E402

GT = json.loads((ROOT / "labs/graphlab/ground_truth.json").read_text())


def run_one(mode: str, data_dir: Path) -> dict:
    base, srv = labctl.start_lab(mode)
    try:
        app = App(data_dir / mode)
        eid = f"eng_graphlab_{mode}_{int(time.time() * 1e6)}"
        app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (eid, f"GraphLab {mode}", "safe_active", "draft",
             json.dumps({"targets": [{"kind": "url", "value": base}]}), "{}", "{}", time.time()))
        scope = Scope({"targets": [{"kind": "url", "value": base}],
                       "categories": ["api", "web"],  # verifier replays under "web"
                       "rate_limit_rps": 20, "max_concurrency": 4})
        started = time.time()
        res = assess_graphql(base + "/graphql", app.db, app.evidence, app.pipeline, app.probe,
                             scope, eid, GT["identities"])
        verifier = Verifier(app.db, app.evidence, app.probe, app.pipeline)
        verdicts = {f["id"]: verifier.verify(eid, scope, f["id"])["verdict"]
                    for f in app.pipeline.list(eid)}
        duration = time.time() - started
        findings = app.pipeline.list(eid)
        confirmed = [f for f in findings if f["state"] in ("validated", "reported")]
        detected, missed = [], []
        for seed in GT["seeded_findings"]:
            hit = next((f for f in confirmed
                        if f["cwe"] == seed["cwe"]
                        and seed["title_contains"] in (f["title"] or "")), None)
            if hit:
                detected.append({"seed": seed["id"], "finding": hit["id"], "cwe": hit["cwe"],
                                 "title": hit["title"], "state": hit["state"],
                                 "verdict": verdicts.get(hit["id"])})
            else:
                missed.append({"seed": seed["id"], "title": seed["title"], "cwe": seed["cwe"]})
        matched = {d["finding"] for d in detected}
        unmatched = [f for f in confirmed if f["id"] not in matched]
        return {
            "mode": mode, "duration_s": round(duration, 1), "status": res["status"],
            "findings_total": len(findings), "confirmed": len(confirmed),
            "seeds_total": len(GT["seeded_findings"]), "detected": len(detected),
            "detail": detected, "missed": missed,
            "unmatched_confirmed": [{"id": f["id"], "title": f["title"], "cwe": f["cwe"],
                                     "endpoint": f["endpoint"]} for f in unmatched],
            "false_positives": len(unmatched),
            "observations": len(res["observations"]),
            "verdicts": verdicts,
            "chain": app.evidence.verify_chain(eid),
        }
    finally:
        srv.shutdown()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default="both", choices=["vuln", "hardened", "both"])
    p.add_argument("--data-dir", default=str(ROOT / "benchmark_runs"))
    p.add_argument("--out", default=str(ROOT / "benchmark_runs/graphlab_results.json"))
    args = p.parse_args()
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    modes = ["vuln", "hardened"] if args.mode == "both" else [args.mode]
    results = [run_one(m, data_dir) for m in modes]
    Path(args.out).write_text(json.dumps(results, indent=2))
    seeds = [s["id"] for s in GT["seeded_findings"]]
    print("\nseed  " + "  ".join(r["mode"] for r in results))
    for seed in seeds:
        row = ["HIT " if any(d["seed"] == seed for d in r["detail"]) else "--  " for r in results]
        print(f"{seed}   " + "   ".join(row))
    for r in results:
        print(f"\n=== {r['mode']} === {r['duration_s']}s status={r['status']}")
        print(f"confirmed {r['confirmed']}/{r['seeds_total']} seeds | "
              f"missed: {[m['seed'] for m in r['missed']]}")
        print(f"unmatched confirmed (false positives): {r['false_positives']} | "
              f"introspection observations: {r['observations']}")
        for u in r["unmatched_confirmed"]:
            print(f"  - {u['title']} [{u['cwe']}] {u['endpoint']}")
        print(f"evidence chain: {r['chain']}")
    print(f"\nresults: {args.out}")


if __name__ == "__main__":
    main()
