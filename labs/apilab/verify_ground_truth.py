"""Verify ApiLab ground truth: every seed fires in vuln mode, none in hardened.

Usage: python labs/apilab/verify_ground_truth.py   (twins running on 8811/8812)
"""
import httpx

V = "http://127.0.0.1:8811"
H = "http://127.0.0.1:8812"
TIMEOUT = 5


def login(base, user, pw):
    c = httpx.Client(base_url=base, timeout=TIMEOUT)
    r = c.post("/api/login", json={"username": user, "password": pw})
    assert r.json().get("authenticated") is True, f"{user} cannot log in at {base}"
    return c


def checks(base):
    out = {}
    alice, admin = login(base, "alice", "SI_SECRET_PASSWORD_APILAB_A1"), \
        login(base, "admin", "SI_SECRET_PASSWORD_APILAB_C3")
    r = alice.get("/api/items")
    out["AP-04"] = r.status_code == 200 and any("owner_password_hash" in i for i in r.json())
    r = alice.get("/api/items/2")
    out["AP-01"] = r.status_code == 200 and r.json().get("owner_id") == 2
    out["AP-02"] = alice.get("/api/admin/stats").status_code == 200
    r = alice.post("/api/items", json={"name": "mas-probe", "role": "admin", "is_admin": True})
    cid = r.json().get("id") if r.status_code == 201 else None
    g = alice.get(f"/api/items/{cid}") if cid else None
    out["AP-03"] = bool(g) and g.status_code == 200 and g.json().get("is_admin") in (1, True)
    r = httpx.get(base + "/api/users/2/profile", timeout=TIMEOUT)
    out["AP-05"] = r.status_code == 200 and r.json().get("username") == "bob"
    # negative controls
    out["NC-01"] = alice.get("/api/items/1").status_code == 200
    out["NC-02"] = admin.get("/api/admin/stats").status_code == 200
    out["NC-03"] = alice.get("/api/items/999").status_code == 404
    r = httpx.post(base + "/api/login", json={"username": "alice", "password": "wrong"}, timeout=TIMEOUT)
    out["NC-05"] = r.json().get("authenticated") is False
    alice.close()
    admin.close()
    return out


vuln = checks(V)
hard = checks(H)
fails = []
for k in vuln:
    if k.startswith("AP-"):
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
print(f"ALL GROUND-TRUTH CHECKS PASS: {len(vuln) - 4} seeds fire only in vuln mode; "
      "negative controls hold in both.")
