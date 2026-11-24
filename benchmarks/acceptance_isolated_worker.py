"""Isolated-worker acceptance: prove the native engine works where nuclei cannot exist.

bench_modes.py disables nuclei through the process's own resolver. That shows the engine
does not *call* nuclei; it does not show the engine works on a host where nuclei is not
installed. This test does the stronger thing: it runs the assessment inside a second
Python process whose PATH, HOME and tool directory contain no nuclei binary and whose
resolve step is additionally pinned to fail, then asserts from the persisted records that

  * the engine still reached the target and recorded exchanges,
  * it still produced findings,
  * every nuclei attempt (there should be none that ran) is recorded as unavailable,
  * the evidence chain verifies.

    python benchmarks/acceptance_isolated_worker.py [--twin vuln]
"""
import argparse
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).parent.parent
GT = json.loads((ROOT / "labs/pairlab/ground_truth.json").read_text())
CONFIRMED = ("validated", "reported", "retested_persists")

CHILD = textwrap.dedent('''
    import json, sys, time
    sys.path.insert(0, sys.argv[1])
    from libella.api import App
    from libella.tools import runner as runner_mod

    # The stronger boundary: no nuclei is resolvable even if a binary were on PATH.
    real = runner_mod.resolve_binary
    runner_mod.resolve_binary = lambda n: None if n == "nuclei" else real(n)
    assert runner_mod.resolve_binary("nuclei") is None, "nuclei resolved: not isolated"
    import shutil as _sh
    assert _sh.which("nuclei") is None, "a nuclei binary is on PATH: not isolated"

    base, data_dir, eid = sys.argv[2], sys.argv[3], sys.argv[4]
    app = App(data_dir)
    scope = {"targets": [{"kind": "url", "value": base}],
             "categories": ["recon", "web", "api", "infra"],
             "rate_limit_rps": 20, "max_concurrency": 4}
    auth = {"identities": [{"username": i["username"], "password": i["password"],
                            "role": i["role"], "uid": i["uid"],
                            "login_url": base + "/login", "username_field": "username",
                            "password_field": "password"} for i in json.loads(sys.argv[5])[:2]]}
    app.db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
                   "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (eid, "isolated worker", "safe_active", "draft", json.dumps(scope),
                    json.dumps(auth), json.dumps({"max_duration_s": 900, "max_usd": 0}),
                    time.time()))
    app.orchestrator().start(eid, mode="deterministic")
    print(json.dumps({"ok": True}))
''')


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--twin", default="vuln")
    p.add_argument("--data-dir", default=str(ROOT / "benchmark_runs/isolated_worker"))
    a = p.parse_args()
    base = "http://127.0.0.1:8801" if a.twin == "vuln" else "http://127.0.0.1:8802"
    data_dir = Path(a.data_dir) / a.twin
    shutil.rmtree(data_dir, ignore_errors=True)
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    eid = f"iso_{a.twin}"

    # A PATH with the python interpreter and coreutils, but no scanner directory and no
    # python venv bin (which is where pip pulls command-line scanners would land).
    bare = Path(a.data_dir) / "bin"
    # rebuilt each run: a stale symlink from a previous run must not fail the next one
    shutil.rmtree(bare, ignore_errors=True)
    bare.mkdir(parents=True, exist_ok=True)
    for name in ("sh", "env", "cat", "true"):
        src = shutil.which(name)
        if src:
            (bare / name).symlink_to(src)
    env = {"PATH": f"{bare}:/usr/bin:/bin", "HOME": str(Path(a.data_dir) / "home"),
           "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(Path(a.data_dir) / "tmp"),
           "LIBELLA_TOOL_PATH": str(Path(a.data_dir) / "no-tools")}
    for d in ("home", "tmp", "no-tools"):
        (Path(a.data_dir) / d).mkdir(parents=True, exist_ok=True)
    # Fails if nuclei is reachable at all in the child.
    assert shutil.which("nuclei", path=env["PATH"]) is None

    proc = subprocess.run(
        [sys.executable, "-c", CHILD, str(ROOT / "src"), base, str(data_dir), eid,
         json.dumps(GT["identities"])],
        capture_output=True, text=True, env=env, timeout=1800)
    checks, out = [], {}
    try:
        from libella.api import App
        app = App(data_dir)
        findings = app.pipeline.list(eid)
        confirmed = [f for f in findings if f["state"] in CONFIRMED]
        calls = app.db.query("SELECT tool, scope_decision FROM tool_calls WHERE engagement_id=?",
                             (eid,))
        row = app.db.one("SELECT COUNT(*) n FROM exchanges WHERE engagement_id=?", (eid,)) or {}
        exchanges = row["n"] if row else 0
        ran_nuclei = [c for c in calls if c["tool"] == "nuclei"
                      and not str(c["scope_decision"]).startswith("refused")]
        checks = [
            ("child process completed", proc.returncode == 0),
            ("no nuclei binary on the child PATH", shutil.which("nuclei", path=env["PATH"]) is None),
            ("the engine reached the target", exchanges > 0),
            ("nuclei never executed a scan", not ran_nuclei),
            ("findings were produced without nuclei", len(confirmed) > 0),
            ("evidence chain verifies", app.evidence.verify_chain(eid)["ok"]),
        ]
        out: dict = {"returncode": proc.returncode, "exchanges": exchanges,
               "confirmed_findings": len(confirmed),
               "nuclei_calls": len([c for c in calls if c["tool"] == "nuclei"]),
               "nuclei_that_ran": len(ran_nuclei),
               "checks": [{"check": n, "pass": bool(v)} for n, v in checks],
               "stderr_tail": proc.stderr.splitlines()[-3:] if proc.stderr else []}
        app.db.close()
    except Exception as exc:  # the child's own output is the evidence when this fires
        out = {"error": repr(exc), "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-3000:]}
        checks = [("harness could read the child's result", False)]

    passed = all(v for _, v in checks)
    out["passed"] = passed
    out["checks"] = [{"check": n, "pass": bool(v)} for n, v in checks]
    print(json.dumps(out, indent=2))
    report = Path(a.data_dir) / "isolated_worker_result.json"
    report.write_text(json.dumps(out, indent=2))
    print(f"\n{'PASS' if passed else 'FAIL'}: {sum(1 for _, v in checks if v)}/{len(checks)} checks"
          f" -> {report}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
