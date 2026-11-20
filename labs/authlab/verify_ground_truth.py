"""Verify AuthLab ground truth: every seed fires in vuln mode, none in hardened.

Usage: python labs/authlab/verify_ground_truth.py   (twins running on 8831/8832)
"""
import os

import httpx

V = os.environ.get("AUTHLAB_VULN", "http://127.0.0.1:8831")
H = os.environ.get("AUTHLAB_HARDENED", "http://127.0.0.1:8832")
TIMEOUT = 5


def login(base, user, pw, follow=False):
    c = httpx.Client(base_url=base, timeout=TIMEOUT)
    r = c.post("/login", data={"username": user, "password": pw}, follow_redirects=follow)
    assert r.status_code == 302, f"{user} cannot log in at {base}: {r.status_code}"
    return c


def checks(base):
    out = {}
    alice = login(base, "alice", "SI_SECRET_PASSWORD_AUTHLAB_A1")
    admin = login(base, "admin", "SI_SECRET_PASSWORD_AUTHLAB_C3")
    bob = login(base, "bob", "SI_SECRET_PASSWORD_AUTHLAB_B2")
    # seeds
    r = alice.get("/items/2")
    out["AL-01"] = r.status_code == 200 and "Leather bound" in r.text
    out["AL-02"] = alice.get("/admin").status_code == 200
    # token-less transfer of alice's pen (item 3) to bob
    r = alice.post("/items/3/transfer", data={"to": "bob"})
    moved = alice.get("/items/3")
    out["AL-03"] = r.status_code == 302 and "Owner: <span id=\"owner\">bob" in moved.text
    r = alice.get("/profile?uid=2")
    out["AL-04"] = r.status_code == 200 and "bob@example.invalid" in r.text
    # negative controls
    out["NC-01"] = alice.get("/items/1").status_code == 200
    out["NC-02"] = admin.get("/admin").status_code == 200
    out["NC-03"] = httpx.post(base + "/login", timeout=TIMEOUT,
                              data={"username": "alice", "password": "wrong"}).status_code == 401
    out["NC-04"] = bob.get("/items/2").status_code == 200
    r = httpx.get(base + "/dashboard", timeout=TIMEOUT, follow_redirects=False)
    out["NC-05"] = r.status_code == 302 and r.headers["location"].endswith("/login")
    for c in (alice, admin, bob):
        c.close()
    return out


def main():
    vuln, hard = checks(V), checks(H)
    fails = []
    for k in vuln:
        if k.startswith("AL-"):
            if not vuln[k]:
                fails.append(f"vuln mode: {k} did NOT fire")
            if hard[k]:
                fails.append(f"hardened mode: {k} STILL fires (control broken)")
        elif not (vuln[k] and hard[k]):
            fails.append(f"{k} negative control broken (vuln={vuln[k]} hard={hard[k]})")
    print("seed vuln hard")
    for k in sorted(vuln):
        print(f"{k} {int(vuln[k])} {int(hard[k])}")
    if fails:
        print("FAILURES:")
        for f in fails:
            print(" -", f)
        raise SystemExit(1)
    print(f"ALL GROUND-TRUTH CHECKS PASS: {len(vuln) - 5} seeds fire only in vuln mode; "
          "negative controls hold in both.")


if __name__ == "__main__":
    main()
