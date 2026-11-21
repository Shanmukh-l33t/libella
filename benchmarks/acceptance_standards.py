"""Acceptance: does the standards ledger describe a REAL run, or a nice table?

Runs a complete deterministic assessment against a controlled PairLab instance
with ASVS 5.0.0 Level 2 selected, then reads the ledger and checks that:

* the requirement inventory is the published one (253 requirements at Level 2);
* every requirement marked executed has evidence pointers from this engagement;
* a requirement covered only partially by a check never reports a pass;
* an executed requirement and an unexecuted one are both visible, in the same
  ledger, with their reasons;
* one captured exchange accounts for requirements in both standards;
* the exported report reopens and carries the same coverage accounting.

Usage: PYTHONPATH=src python benchmarks/acceptance_standards.py <out-dir> [--port 8801]
Requires the PairLab vulnerable twin listening on the port.
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from libella import coverage  # noqa: E402
from libella.api import App  # noqa: E402
from libella.report import render_report  # noqa: E402

GT = json.loads((ROOT / "labs/pairlab/ground_truth.json").read_text())
EXECUTED = ("completed_no_issue", "partial_evidence", "finding_unverified", "finding_verified")


def _engagement(app: App, port: int) -> str:
    base = f"http://127.0.0.1:{port}"
    hints = {
        "ssrf": {"url": base + "/fetch", "param": "url",
                 "internal_url": base + "/internal/meta", "marker": "LABFAKEKEY0000"},
        "sqli_union": {"url": base + "/api/products", "param": "category",
                       "payload": "' UNION SELECT id,username,password,role FROM users--",
                       "marker": "alice"},
        "idor": {"url_template": base + "/api/orders/{id}", "foreign_ids": [102],
                 "foreign_marker": '"user_id":2', "identity": "alice"},
    }
    auth = {"identities": [{**i, "login_url": base + "/login", "username_field": "username",
                            "password_field": "password"} for i in GT["identities"][:2]],
            "test_hints": hints}
    scope = {"targets": [{"kind": "url", "value": base}],
             "categories": ["recon", "web", "api", "infra"],
             "rate_limit_rps": 20, "max_concurrency": 4}
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at, standards_json) VALUES(?,?,?,?,?,?,?,?,?)",
        ("eng_std", "Standards acceptance", "safe_active", "draft", json.dumps(scope),
         json.dumps(auth), json.dumps({"max_duration_s": 900, "max_usd": 5}), time.time(),
         json.dumps({"asvs": {"level": 2}})))
    return "eng_std"


def _flat(ws: dict) -> dict:
    return {t["id"]: t for c in ws["categories"] for t in c["tests"]}


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/acceptance_standards")
    port = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[2] == "--port" else 8801
    out.mkdir(parents=True, exist_ok=True)
    app = App(out / "data")
    eid = _engagement(app, port)
    print(f"running the deterministic assessment against :{port} with ASVS L2 ...", flush=True)
    t0 = time.time()
    app.orchestrator().start(eid, mode="deterministic")
    print(f"assessment finished in {time.time() - t0:.1f}s", flush=True)

    asvs = coverage.workspace(app.db, eid, "asvs")
    wstg = coverage.workspace(app.db, eid, "wstg")
    reqs = _flat(asvs)
    summary = asvs["summary"]
    executed = {rid: t for rid, t in reqs.items() if t["automatic"]["status"] in EXECUTED}
    failures = []

    if summary["total"] != 253:
        failures.append(f"ASVS L2 inventory is {summary['total']}, expected 253")
    if summary["level"] != 2 or summary["excluded_by_level"] != 92:
        failures.append(f"level accounting wrong: {summary['level']} "
                        f"excluded={summary['excluded_by_level']}")
    if not executed:
        failures.append("no requirement was executed: the ledger is not connected to the run")
    for rid, t in executed.items():
        ev = t["evidence"]
        if not (ev["tool_calls"] or ev["exchanges"] or ev["findings"] or ev["intents"]):
            failures.append(f"{rid} claims execution with no evidence pointers")
        if (t["automatic"]["status"] == "completed_no_issue"
                and t["automatic"].get("strength") != "direct"):
            failures.append(f"{rid} claims a pass from a {t['automatic'].get('strength')} check")
    unexecuted = [rid for rid, t in reqs.items()
                  if t["automatic"]["status"] in ("requires_manual", "inconclusive", "not_supported")]
    if not unexecuted:
        failures.append("every requirement looks executed: that is not credible")
    if not any(t["automatic"]["status"] == "requires_manual" for t in reqs.values()):
        failures.append("no requirement requires manual verification")

    # one exchange, two standards
    shared = [rid for rid, t in executed.items() if t["evidence"]["exchanges"]]
    wstg_flat = _flat(wstg)
    if not shared:
        failures.append("no requirement cites a captured exchange")
    else:
        rid = shared[0]
        ex = set(reqs[rid]["evidence"]["exchanges"])
        wstg_hits = [w for w, t in wstg_flat.items() if ex & set(t["evidence"]["exchanges"])]
        if not wstg_hits:
            failures.append(f"{rid} cites {ex} but no WSTG test cites the same exchange")

    doc = render_report(app.db, app.evidence, eid)
    (out / "report.json").write_text(json.dumps(doc, indent=1, default=str))
    reopened = json.loads((out / "report.json").read_text())
    if not reopened.get("coverage"):
        failures.append("report has no coverage section")
    elif reopened["coverage"].get("summary", {}).get("total") != wstg["summary"]["total"]:
        failures.append("report coverage total disagrees with the ledger")
    (out / "standards_asvs.json").write_text(json.dumps(asvs, indent=1, default=str))
    (out / "standards_wstg.json").write_text(json.dumps(wstg, indent=1, default=str))

    print("\n== ASVS 5.0.0 Level 2 accounting ==")
    for key in ("total", "catalog", "excluded_by_level", "applicable", "supported", "attempted",
                "completed", "partial", "with_findings", "skipped", "manual_required", "not_tested"):
        print(f"  {key:20s} {summary[key]}")
    print("\n== executed requirements ==")
    for rid, t in sorted(executed.items()):
        st = t["automatic"]
        print(f"  {rid:10s} L{t['level']} {st['status']:18s} {st.get('strength', '-'):7s} "
              f"{st['units']} :: {st['reason'][:70]}")
    print(f"\n== WSTG 4.2 for the same run: {wstg['summary']['completed']} of "
          f"{wstg['summary']['total']} completed ==")
    print(f"findings: {len(app.pipeline.list(eid))}, verified: "
          f"{sum(1 for f in app.pipeline.list(eid) if f['state'] in ('validated', 'reported', 'retested_persists'))}")
    if failures:
        print("\nFAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nPASS: {len(executed)} of {summary['total']} L2 requirements executed, "
          f"{len(unexecuted)} honestly unexecuted; artifacts in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
