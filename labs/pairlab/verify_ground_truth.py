"""Verify PairLab ground truth: every seed fires in vuln mode, none in hardened."""
import requests

V = "http://127.0.0.1:8801"
H = "http://127.0.0.1:8802"
TIMEOUT = 5


def checks(base):
    s = requests.Session()
    out = {}
    r = s.get(base + "/search", params={"q": "<script>alert(1)</script>"}, timeout=TIMEOUT)
    out["PL-01"] = "<script>alert(1)</script>" in r.text
    r = s.get(base + "/api/products", params={"category": "' UNION SELECT id,username,password,role FROM users--"}, timeout=TIMEOUT)
    try:
        out["PL-02"] = any(row.get("name") == "alice" for row in r.json())
    except Exception:
        out["PL-02"] = False
    r = s.post(base + "/login", data={"username": "admin'-- ", "password": "x"}, timeout=TIMEOUT)
    out["PL-03"] = r.json().get("authenticated") is True
    s2 = requests.Session()
    s2.post(base + "/login", data={"username": "alice", "password": "lab-password-123"}, timeout=TIMEOUT)
    r = s2.get(base + "/api/orders/102", timeout=TIMEOUT)
    out["PL-04"] = r.status_code == 200 and r.json().get("user_id") == 2
    r = s.get(base + "/files", params={"name": "../private_config.txt"}, timeout=TIMEOUT)
    out["PL-05"] = "LAB_PRIVATE_MARKER" in r.text
    r = s.get(base + "/api/profile", headers={"Origin": "https://evil.invalid"}, timeout=TIMEOUT)
    out["PL-06"] = r.headers.get("Access-Control-Allow-Origin") == "*" and r.headers.get("Access-Control-Allow-Credentials") == "true"
    r = s.get(base + "/api/users", timeout=TIMEOUT)
    try:
        out["PL-07"] = r.status_code == 200 and any("password" in u for u in r.json())
    except Exception:
        out["PL-07"] = False
    r = s.get(base + "/fetch", params={"url": base + "/internal/meta"}, timeout=TIMEOUT)
    out["PL-08"] = "LABFAKEKEY0000" in r.text
    r = s.get(base + "/redirect", params={"to": "https://example.invalid/"}, allow_redirects=False, timeout=TIMEOUT)
    out["PL-09"] = r.status_code in (301, 302, 303, 307, 308) and "example.invalid" in r.headers.get("Location", "")
    r = s.get(base + "/debug", timeout=TIMEOUT)
    out["PL-10"] = r.status_code == 200 and "secret_key" in r.text
    r = s.get(base + "/uploads/", timeout=TIMEOUT)
    out["PL-11"] = r.status_code == 200 and "readme.txt" in r.text
    r = s.post(base + "/login", data={"username": "alice", "password": "lab-password-123"}, timeout=TIMEOUT)
    sc = r.headers.get("Set-Cookie", "")
    out["PL-12"] = "session=" in sc and "HttpOnly" not in sc
    r = s.get(base + "/", timeout=TIMEOUT)
    out["PL-13"] = not any(h in r.headers for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"))
    probe = "<?php /* libella-upload-probe-marker-9f2c */ ?>"
    r = s.post(base + "/upload", files={"file": ("libella_probe.php", probe, "application/octet-stream")}, timeout=TIMEOUT)
    ok14 = r.status_code == 200 and "UPLOAD_ACCEPTED" in r.text
    if ok14:
        rr = s.get(base + "/files", params={"name": "libella_probe.php"}, timeout=TIMEOUT)
        ok14 = "libella-upload-probe-marker-9f2c" in rr.text
    out["PL-14"] = ok14
    r = s.get(base + "/greet", params={"name": "{{7*7}}"}, timeout=TIMEOUT)
    r2 = s.get(base + "/greet", params={"name": "{{7*19}}"}, timeout=TIMEOUT)
    out["PL-15"] = "49" in r.text and "7*7" not in r.text and "133" in r2.text
    r = s.get(base + "/greet", params={"name": "<script>alert(1)</script>"}, timeout=TIMEOUT)
    out["PL-16"] = "<script>alert(1)</script>" in r.text
    # negative controls
    r = s.get(base + "/files", params={"name": "readme.txt"}, timeout=TIMEOUT)
    out["NC-04"] = r.status_code == 200 and "public file" in r.text
    r = s.get(base + "/redirect", params={"to": "/health"}, allow_redirects=False, timeout=TIMEOUT)
    out["NC-05"] = r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location", "").startswith("/")
    return out


vuln = checks(V)
hard = checks(H)
fails = []
for k in vuln:
    if k.startswith("PL-"):
        if not vuln[k]:
            fails.append(f"vuln mode: {k} did NOT fire")
        if hard[k]:
            fails.append(f"hardened mode: {k} STILL fires (control broken)")
    else:
        if not vuln[k] or not hard[k]:
            fails.append(f"{k} negative control broken (vuln={vuln[k]} hard={hard[k]})")
print("seed vuln hard")
for k in sorted(vuln):
    print(f"{k} {int(vuln[k])} {int(hard[k])}")
if fails:
    print("FAILURES:")
    for f in fails:
        print(" -", f)
    raise SystemExit(1)
print("ALL GROUND-TRUTH CHECKS PASS: 16 seeds fire only in vuln mode; negative controls hold in both.")