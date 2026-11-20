"""Verify GraphLab ground truth: every seed fires in vuln mode, none in hardened.

Usage: python labs/graphlab/verify_ground_truth.py   (twins running on 8821/8822)
"""
import json

import httpx

V = "http://127.0.0.1:8821"
H = "http://127.0.0.1:8822"
TIMEOUT = 5
BODY = {"Content-Type": "application/json"}


def login(base, user, pw):
    c = httpx.Client(base_url=base, timeout=TIMEOUT)
    r = c.post("/login", json={"username": user, "password": pw})
    assert r.json().get("authenticated") is True, f"{user} cannot log in at {base}"
    return c


def ask(client, query):
    return client.post("/graphql", json={"query": query}, headers=BODY)


def data_of(r):
    try:
        return r.json().get("data") if isinstance(r.json(), dict) else None
    except ValueError:
        return None


def checks(base):
    out = {}
    alice = login(base, "alice", "SI_SECRET_PASSWORD_GRAPHLAB_A1")
    admin = login(base, "admin", "SI_SECRET_PASSWORD_GRAPHLAB_C3")

    d = data_of(ask(alice, "{__schema{types{name}}}")) or {}
    names = [t["name"] for t in (d.get("__schema") or {}).get("types", [])]
    out["GL-01"] = "AdminStats" in names

    r = ask(alice, "{users(filter:\"libella'\"){id username}}")
    out["GL-02"] = "sqlite3.OperationalError" in r.text

    u = (data_of(ask(alice, "{user(id:2){id username email role}}")) or {}).get("user") or {}
    out["GL-03"] = u.get("id") == 2 and u.get("username") == "bob" and "email" in u

    stats = (data_of(ask(alice, "{adminStats{totalUsers totalRoles}}")) or {}).get("adminStats") or {}
    out["GL-04"] = stats.get("totalUsers") == 3

    nested = "".join(" manager{id" for _ in range(6)) + "}" * 6
    d = data_of(ask(alice, "{user(id:1){id%s}}" % nested)) or {}
    levels, node = 0, d.get("user")
    while isinstance(node, dict) and levels < 10:
        levels += 1
        node = node.get("manager")
    out["GL-05"] = levels >= 4

    q = "{" + " ".join(f"u{i}:user(id:1){{id}}" for i in range(50)) + "}"
    out["GL-06"] = len(data_of(ask(alice, q)) or {}) == 50

    r = alice.post("/graphql", json=[{"query": "{user(id:1){id username}}"},
                                     {"query": "{user(id:2){id username}}"},
                                     {"query": "{users{id}}"}], headers=BODY)
    body = r.json()
    out["GL-07"] = isinstance(body, list) and len(body) == 3 and all("data" in e for e in body)

    # negative controls
    out["NC-01"] = (data_of(ask(alice, "{user(id:1){id username}}")) or {}).get("user", {}).get("id") == 1
    out["NC-02"] = bool((data_of(ask(admin, "{adminStats{totalUsers}}")) or {}).get("adminStats"))
    # admin is authorized for any user, so an unknown id must be null in both modes
    out["NC-03"] = (data_of(ask(admin, "{user(id:999){id}}")) or {}).get("user", "missing") is None
    out["NC-04"] = httpx.post(base + "/graphql", json={"query": "{users{id}}"},
                              headers=BODY, timeout=TIMEOUT).status_code == 401
    r = httpx.post(base + "/login", json={"username": "alice", "password": "wrong-lab-pw"},
                   timeout=TIMEOUT)
    out["NC-05"] = r.json().get("authenticated") is False
    alice.close()
    admin.close()
    return out


vuln = checks(V)
hard = checks(H)
fails = []
for k in vuln:
    if k.startswith("GL-"):
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
seeds = [k for k in vuln if k.startswith("GL-")]
print(f"ALL GROUND-TRUTH CHECKS PASS: {len(seeds)} seeds fire only in vuln mode; "
      "negative controls hold in both.")
print(json.dumps({"seeds": len(seeds), "negative_controls": len(vuln) - len(seeds)}))
