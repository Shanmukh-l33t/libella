"""CodeAudit benchmark: assess both fixture repos, score against ground truth.

Usage: python benchmarks/run_codeaudit.py [--out results.json]
Exit code 1 if a seeded issue is missed or the clean repo produces a finding.
"""
import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.codeaudit import assess_repo
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline

ROOT = Path(__file__).parent.parent
LABS = ROOT / "labs"


def run_one(name, db, evidence, pipeline):
    gt = json.loads((LABS / name / "ground_truth.json").read_text())
    eid = f"eng_code_{name}"
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
        "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, name, "safe_active", "draft", "{}", "{}", "{}", time.time()),
    )
    run = assess_repo(LABS / name, db, evidence, pipeline, eid, roots=[str(LABS)])
    rows = db.query("SELECT * FROM findings WHERE engagement_id=?", (eid,))

    matched, missed, rows_out = [], [], []
    for seed in gt["findings"]:
        hit = next((f for f in rows if f["cwe"] == seed["cwe"]
                    and f["endpoint"].split("#")[0].endswith(seed["file"])), None)
        rows_out.append({"seed": seed["id"], "cwe": seed["cwe"], "file": seed["file"],
                         "detected": bool(hit), "finding_id": hit["id"] if hit else None,
                         "state": hit["state"] if hit else None,
                         "line": (hit["endpoint"].split("#L")[-1] if hit else None)})
        (matched if hit else missed).append(seed["id"])
    unmatched = [f for f in rows if f["id"] not in {m["finding_id"] for m in rows_out}]

    expected = {(d["package"], d["version"]): set(d["cves"])
                for d in gt["dependency_observations"]}
    obs = db.query("SELECT * FROM observations WHERE engagement_id=? "
                   "AND kind='potentially_affected'", (eid,))
    dep_out = []
    for o in obs:
        hit = json.loads(o["summary"])
        dep_out.append({"cve": hit["cve"], "package": hit["package"],
                        "version": hit["version"], "source": hit["source"],
                        "expected": hit["cve"] in expected.get((hit["package"],
                                                                hit["version"]), set()),
                        "observation_id": o["id"]})
    dep_missed = sorted(f"{k[0]}=={k[1]} {c}" for k, cves in expected.items()
                        for c in cves if c not in {d["cve"] for d in dep_out})
    return {
        "repo": name, "duration_s": round(run["duration_ms"] / 1000, 2),
        "seeds_total": len(gt["findings"]), "detected": len(matched),
        "missed": missed, "unmatched_findings": [
            {"id": f["id"], "cwe": f["cwe"], "endpoint": f["endpoint"]} for f in unmatched],
        "false_positives": len(unmatched) if not gt["findings"] else 0,
        "dependency_observations": dep_out, "dependency_missed": dep_missed,
        "degradations": run["degradations"], "matrix": rows_out,
        "evidence_chain": evidence.verify_chain(eid),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    stamp = time.strftime("%Y%m%dT%H%M%S")
    out = Path(args.out) if args.out else ROOT / "benchmark_runs" / f"codeaudit_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        db = DB(Path(tmp) / "db.sqlite")
        evidence = EvidenceStore(db, Path(tmp) / "evidence")
        pipeline = FindingPipeline(db, evidence)
        results = [run_one(name, db, evidence, pipeline) for name in ("vulnrepo", "cleanrepo")]

    vuln, clean = results
    score = {
        "seeds_detected": vuln["detected"], "seeds_total": vuln["seeds_total"],
        "cleanrepo_findings": clean["false_positives"],
        "dependency_observations": len(vuln["dependency_observations"]),
        "evidence_chain_ok": all(r["evidence_chain"]["ok"] for r in results),
    }
    ok = (vuln["detected"] == vuln["seeds_total"] and not vuln["unmatched_findings"]
          and clean["false_positives"] == 0 and not vuln["dependency_missed"]
          and not clean["dependency_missed"] and score["evidence_chain_ok"])
    payload = {"generated_at": stamp, "score": score, "ok": ok, "results": results}
    out.write_text(json.dumps(payload, indent=2))

    print(f"{'repo':<10} {'seed':<14} {'cwe':<9} {'status':<9} finding")
    print("-" * 78)
    for r in (vuln, clean):
        for row in r["matrix"]:
            fid = f"{row['finding_id']} {row['file']}:{row['line']}" if row["detected"] \
                else f"MISSED {row['file']}"
            print(f"{r['repo']:<10} {row['seed']:<14} {row['cwe']:<9} "
                  f"{'DETECTED' if row['detected'] else 'MISSED':<9} {fid}")
        for f in r["unmatched_findings"]:
            print(f"{r['repo']:<10} {'-':<14} {f['cwe']:<9} {'EXTRA':<9} {f['endpoint']}")
        for d in r["dependency_observations"]:
            flag = "expected" if d["expected"] else "UNEXPECTED"
            print(f"{r['repo']:<10} {'dep':<14} {'OBS':<9} {'potential':<9} "
                  f"{d['package']}=={d['version']} {d['cve']} ({flag}, not a finding)")
    print("-" * 78)
    print(f"score: {vuln['detected']}/{vuln['seeds_total']} seeded issues detected, "
          f"{len(vuln['unmatched_findings'])} extra findings, "
          f"{clean['false_positives']} false positives on cleanrepo, "
          f"{score['dependency_observations']} dependency observations")
    print(f"duration: vulnrepo {vuln['duration_s']}s, cleanrepo {clean['duration_s']}s")
    print(f"results: {out}")
    if not ok:
        print("FAIL: benchmark gate not met")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
