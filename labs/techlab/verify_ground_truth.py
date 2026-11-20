"""Verify TechLab ground truth: every seed fires in vuln mode, none in hardened.

Usage: python labs/techlab/verify_ground_truth.py   (twins running on 8821/8822)
"""
import json
from pathlib import Path

import httpx

GT = json.loads(Path(__file__).with_name("ground_truth.json").read_text())
V = "http://127.0.0.1:8821"
H = "http://127.0.0.1:8822"
TIMEOUT = 5


def fetch(base, f):
    kwargs = {"timeout": TIMEOUT, "follow_redirects": f.get("follow", True),
              "headers": f.get("headers")}
    if f.get("body"):
        kwargs["content"] = f["body"]
    return httpx.request(f.get("method", "GET"), base + f["path"], **kwargs)


def fires(base, f):
    r = fetch(base, f)
    if f.get("where", "").startswith("header:"):
        return f["needle"] in r.headers.get(f["where"].split(":", 1)[1], "")
    return r.status_code == f["status"] and f["needle"] in r.text


def main():
    fails, rows = [], []
    for f in GT["seeded_findings"]:
        vuln, hard = fires(V, f), fires(H, f)
        rows.append((f["id"], f["tech"], int(vuln), int(hard)))
        if not vuln:
            fails.append(f"vuln mode: {f['id']} ({f['path']}) did NOT fire")
        if hard:
            fails.append(f"hardened mode: {f['id']} ({f['path']}) STILL fires")
    # negative controls
    for stack, path in (("wp", "/wp/"), ("php", "/php/")):
        r = httpx.get(V + path, timeout=TIMEOUT)
        if r.status_code != 200:
            fails.append(f"NC {path}: vuln landing page not 200")
        if stack == "php" and "X-Powered-By" in httpx.get(H + path, timeout=TIMEOUT).headers:
            fails.append("NC-05: hardened PHP still sends X-Powered-By")
    print(f"{'id':<14}{'tech':<12}vuln hard")
    for rid, tech, v, h in rows:
        print(f"{rid:<14}{tech:<12}{v:<5}{h}")
    if fails:
        print("FAILURES:")
        for f in fails:
            print(" -", f)
        raise SystemExit(1)
    print(f"ALL GROUND-TRUTH CHECKS PASS: {len(rows)} seeds fire only in vuln mode; "
          "negative controls hold.")


if __name__ == "__main__":
    main()
