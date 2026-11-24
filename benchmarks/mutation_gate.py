"""Mutation gate: every verification guard must be load-bearing.

A guard whose removal leaves the suite green is decoration, and this project has already
shipped one (an empty-cookie precondition that passed with and without its own guard). So
the mutations live in a committed harness rather than in a session transcript: each entry
edits one production line, runs the focused gate, and requires a FAILURE.

    python benchmarks/mutation_gate.py [--only NAME] [-v]

Exit 0 only when every mutation is killed. Each mutation restores the file from an
in-memory copy, and the tree is verified unchanged at the end (a mutation left on disk
would be the same class of error as the bug).
"""
import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = "src/libella/proof.py"
VERIFIER = "src/libella/verifier.py"

# (name, file, exact text to replace, replacement, test targets)
MUTATIONS = [
    ("proof: an empty SSRF marker is allowed", PROOF,
     '''        if not _text(c.get("marker")):
            gaps.append("marker")''', "        pass",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("proof: an SSRF claim needs no benign control", PROOF,
     '''            gaps.append("benign_request.url")
    elif kind in (SQL_ERROR, BLIND_COMMAND)''',
     '''            pass
    elif kind in (SQL_ERROR, BLIND_COMMAND)''',
     ["tests/verify/test_verifier_accuracy.py"]),
    ("proof: an ownership claim needs neither owner field nor privilege", PROOF,
     '''        else:
            gaps += ["owner_field", "privilege"]''', "        else:\n            pass",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("proof: an ownership claim needs no credential", PROOF,
     '''        if not ({"cookie", "authorization"} & headers):
            gaps.append("credential")''', "        pass",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("proof: ownership and privilege are both optional", PROOF,
     '''        if _text(c.get("privilege")):
            pass
        elif _text(c.get("owner_field")):''', '''        if False:
            pass
        elif _text(c.get("owner_field")):''',
     ["tests/verify/test_verifier_accuracy.py"]),
    ("proof: a headers claim needs no document identity", PROOF,
     '''        if not _text(c.get("document")):
            gaps.append("document")''', "        pass",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("proof: an error signature needs no benign control", PROOF,
     '''        if not _text(_request(c.get("benign_request")).get("url")):
            gaps.append("benign_request.url")
        if not _text(c.get("signal")):
            gaps.append("signal")''', "        pass",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("verifier: the contract check is skipped", VERIFIER,
     '''        gaps = proof.missing(kind, spec.get("proof"), pr, f["title"] or "")''',
     "        gaps = []",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("verifier: an anonymous read of a public resource validates as IDOR", VERIFIER,
     '''        if b["status"] < 400:''', "        if False:",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("verifier: a marker that also arrives without the payload validates", VERIFIER,
     '''        if marker in (b.get("body") or ""):''', "        if False:",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("verifier: an injection signal is never compared to the control", VERIFIER,
     '''        if contract.get("signal") == "reflection":''', "        if True:",
     ["tests/verify/test_verifier_accuracy.py"]),
    ("verifier: the privilege branch is skipped", VERIFIER,
     '''        if contract.get("privilege"):''', "        if False:",
     ["tests/verify/test_verifier_accuracy.py", "tests/graphql"]),
    ("verifier: a timing claim ignores the control baseline", VERIFIER,
     '''        proven = slow >= max(base * TIMING_FACTOR, base + TIMING_FLOOR_MS)''',
     "        proven = True",
     ["tests/verify/test_timing_verification.py"]),
    ("verifier: a timing claim drops the absolute floor", VERIFIER,
     '''        proven = slow >= max(base * TIMING_FACTOR, base + TIMING_FLOOR_MS)''',
     "        proven = slow >= base * TIMING_FACTOR",
     ["tests/verify/test_timing_verification.py"]),
    ("checks: the SSRF check accepts an empty marker", "src/libella/checks.py",
     '''        if not (marker or "").strip():
            return []''', "        pass",
     ["tests/test_check_preconditions.py"]),
    ("checks: the IDOR check accepts an empty session", "src/libella/checks.py",
     '''        if not (cookie_header or "").strip() or not (foreign_marker or "").strip() \\
                or not (identity_name or "").strip():
            return []''', "        pass",
     ["tests/test_check_preconditions.py"]),
    ("checks: a record envelope is read as the record", "src/libella/checks.py",
     '''    if "id" in data:
        return data
    for value in data.values():
        if isinstance(value, dict):
            found = record_of(json.dumps(value))
            if found is not None:
                return found''', "    return data",
     ["tests/verify", "tests/test_check_preconditions.py"]),
    ("checks: SSRF needs no foreign-page evidence", "src/libella/checks.py",
     '''        hit = _foreign_page_marker(body)
        if not hit:
            return []''', "        hit = 'marker'  # any body",
     ["tests/verify/test_ssrf_discovery.py"]),
    ("checks: SSRF skips the own-origin baseline", "src/libella/checks.py",
     '''        if own.get("ok") and hit in (own["body"] or ""):
            return []''', "        pass",
     ["tests/verify/test_ssrf_discovery.py"]),
    ("checks: a published document is not read", "src/libella/checks.py",
     '''    if isinstance(doc, dict) and isinstance(doc.get("paths"), dict):
        return doc''', "    return None",
     ["tests/verify/test_published_inventory.py"]),
    ("checks: a url-formatted parameter is not a destination", "src/libella/checks.py",
     '''    if fmt in ("uri", "url"):
        return True''', "    if False:\n        return True",
     ["tests/verify/test_published_inventory.py"]),
    ("checks: boolean SQLi accepts an echoed parameter", "src/libella/checks.py",
     '''        if not _content_differs(true_r["body"], false_r["body"]):
            return []''', "        pass",
     ["tests/verify/test_sqli_boolean_real_shapes.py"]),
    ("checks: object enumeration accepts an anonymous read", "src/libella/checks.py",
     '''            if anon["status"] < 400:''', "            if False:",
     ["tests/verify"]),
]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_one(name, rel, old, new, targets) -> tuple[bool, str]:
    path = ROOT / rel
    original = path.read_text()
    if old not in original:
        return False, "mutation target not found (the code moved; fix the harness)"
    if original.count(old) > 1:
        return False, "mutation target is ambiguous (appears more than once)"
    path.write_text(original.replace(old, new, 1))
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *targets],
            cwd=ROOT, capture_output=True, text=True,
            env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
        )
        tail = (proc.stdout or "").strip().splitlines()[-1:] or ["(no output)"]
        return proc.returncode != 0, tail[0]
    finally:
        path.write_text(original)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="substring of one mutation name")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    before = {m[1]: _digest(ROOT / m[1]) for m in MUTATIONS}
    chosen = [m for m in MUTATIONS if not args.only or args.only in m[0]]
    if not chosen:
        print(f"no mutation matches {args.only!r}")
        return 2
    survived = []
    for name, rel, old, new, targets in chosen:
        killed, tail = run_one(name, rel, old, new, targets)
        print(f"{'KILLED  ' if killed else 'SURVIVED'} {name}: {tail}")
        if not killed:
            survived.append(name)
    for rel, digest in before.items():
        if _digest(ROOT / rel) != digest:
            print(f"TREE CHANGED: {rel} was not restored")
            return 2
    print(f"\n{len(chosen) - len(survived)}/{len(chosen)} mutations killed")
    if survived:
        print("survived (each is decoration: delete the guard or add the test that needs it):")
        for name in survived:
            print(f"  - {name}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
