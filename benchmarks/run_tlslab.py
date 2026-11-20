"""TLS lab benchmark: full orchestrator engagement against HTTPS twins.

Requires: tlslab on 8443 (vuln/expired), 8444 (hardened/valid), 8445 (vuln/mismatch).
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.api import App
from libella.scope import Scope
from libella.tls_audit import audit_tls

ROOT = Path(__file__).parent.parent


def engagement(port: int, tag: str, app: App) -> dict:
    base = f"https://127.0.0.1:{port}"
    scope = {"targets": [{"kind": "url", "value": base}],
             "categories": ["recon", "infra"], "rate_limit_rps": 20}
    eid = f"eng_tls_{tag}"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, f"TLS lab {tag}", "safe_active", "draft", json.dumps(scope), "{}",
         json.dumps({"max_duration_s": 600}), time.time()))
    t0 = time.time()
    app.orchestrator().start(eid, mode="deterministic")
    findings = app.pipeline.list(eid)
    tls_findings = [f for f in findings if (f["cwe"] or "").startswith(("CWE-298", "CWE-297", "CWE-326"))]
    return {"tag": tag, "duration_s": round(time.time() - t0, 1),
            "tls_findings": [{"title": f["title"], "state": f["state"], "cwe": f["cwe"]}
                             for f in tls_findings],
            "validated": sum(1 for f in tls_findings if f["state"] == "validated"),
            "chain": app.evidence.verify_chain(eid)}


def main():
    app = App(ROOT / "benchmark_runs" / "tlslab")
    results = [engagement(8446, "vuln_expired", app), engagement(8444, "hardened", app)]
    # mismatch instance: direct module call (cert variant)
    scope = Scope({"targets": [{"kind": "url", "value": "https://127.0.0.1:8445"}],
                   "categories": ["infra"]})
    eid = "eng_tls_mismatch"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, "TLS mismatch", "safe_active", "draft", json.dumps(scope.spec), "{}", "{}", time.time()))
    res = audit_tls("127.0.0.1", 8445, app.db, app.evidence, app.pipeline, scope, eid)
    for r in res:
        app.verifier.verify(eid, scope, r["id"])
    mm_after = [app.db.one("SELECT title, state FROM findings WHERE id=?", (r["id"],)) for r in res]
    results.append({"tag": "vuln_mismatch",
                    "tls_findings": [dict(m) for m in mm_after],
                    "validated": sum(1 for m in mm_after if m["state"] == "validated"),
                    "chain": app.evidence.verify_chain(eid)})
    (ROOT / "benchmark_runs" / "tlslab_results.json").write_text(json.dumps(results, indent=2))
    for r in results:
        print(f"== {r['tag']} == validated TLS findings: {r['validated']}")
        for f in r["tls_findings"]:
            print(f"   [{f['state']}] {f['title']}")
    print("chain ok:", all(r["chain"]["ok"] for r in results))


if __name__ == "__main__":
    main()
