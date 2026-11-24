"""HoldLab: holdout vulnerable/hardened twin, deliberately shaped differently from PairLab.

LAB_MODE=vuln (default) seeds three weaknesses; LAB_MODE=hardened serves the same routes
with correct controls. LAB_LINKS=bare (default) links pages without example queries, so a
parameter name must be discovered; LAB_LINKS=query links /catalog/items?kind=... as most
catalog pages do. Ground truth in ground_truth.json. Lab-only: binds 127.0.0.1, fake data.
"""
import os
import sqlite3

import requests
from flask import Flask, jsonify, request, session

MODE = os.environ.get("LAB_MODE", "vuln")
VULN = MODE == "vuln"
PORT = int(os.environ.get("LAB_PORT", "8831"))
LINKS = os.environ.get("LAB_LINKS", "bare")

app = Flask(__name__)
app.secret_key = "holdlab-lab-only-secret"
# lab runs on plain http: a Secure cookie is never sent back, so no identity could log
# in and every authenticated route looked anonymous. Samesite stays strict in both modes.
app.config.update(SESSION_COOKIE_SECURE=False, SESSION_COOKIE_SAMESITE="Strict")

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.row_factory = sqlite3.Row
_DB.executescript(
    """
    CREATE TABLE accounts(id INTEGER PRIMARY KEY, email TEXT, passcode TEXT, role TEXT);
    CREATE TABLE items(id INTEGER PRIMARY KEY, title TEXT, kind TEXT, cents INTEGER);
    CREATE TABLE invoices(id INTEGER PRIMARY KEY, customer_id INTEGER, memo TEXT, cents INTEGER);
    INSERT INTO accounts VALUES(11,'maya@holdlab.invalid','maya-pass-9921','member'),
        (12,'noor@holdlab.invalid','noor-pass-4417','member'),
        (13,'root@holdlab.invalid','root-pass-0083','admin');
    INSERT INTO items VALUES(1,'Anvil','hardware',4500),(2,'Bolt','hardware',25),
        (3,'Canvas','craft',1200),(4,'Dye','craft',350);
    INSERT INTO invoices VALUES(5001,11,'Anvil x1',4500),(5002,12,'Canvas x2',2400),
        (5003,11,'Bolt x40',1000);
    """
)


@app.after_request
def headers(resp):  # identical in both modes: only the three seeds differ
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/")
def index():
    q = "?kind=hardware" if LINKS == "query" else ""
    return (
        "<html><body><h1>HoldLab</h1><ul>"
        f"<li><a href='/catalog/items{q}'>catalog</a></li>"
        "<li><a href='/tools/preview'>link preview</a></li>"
        "<li><a href='/v2/invoices'>my invoices</a></li>"
        "<li><a href='/status'>status</a></li>"
        "</ul></body></html>"
    )


@app.get("/status")
def status():
    return jsonify(state="ok")


@app.post("/auth/session")
def auth():
    row = _DB.execute("SELECT id, role FROM accounts WHERE email=? AND passcode=?",
                      (request.form.get("email", ""), request.form.get("passcode", ""))).fetchone()
    if row is None:
        return jsonify(error="bad credentials"), 401
    session["uid"], session["role"] = row["id"], row["role"]
    return jsonify(signed_in=True)


@app.get("/catalog/items")
def catalog():
    kind = request.args.get("kind")
    try:
        if kind is None:
            rows = _DB.execute("SELECT id,title,kind,cents FROM items").fetchall()
        elif VULN:  # CWE-89
            rows = _DB.execute(
                "SELECT id,title,kind,cents FROM items WHERE kind='%s'" % kind).fetchall()
        else:
            rows = _DB.execute(
                "SELECT id,title,kind,cents FROM items WHERE kind=?", (kind,)).fetchall()
    except sqlite3.Error as e:  # verbose error body, as many JSON APIs return
        return jsonify(error=f"{type(e).__module__}.{type(e).__name__}: {e}"), 500
    return jsonify(results=[dict(r) for r in rows], count=len(rows))


@app.get("/_internal/creds")
def creds():
    return jsonify(service="vault-stub", secret="HOLDLAB-CRED-5e91c7")


@app.get("/tools/preview")
def preview():
    target = request.args.get("target", "")
    if not target:
        return jsonify(error="target required"), 400
    if not VULN:  # fixed: only the public status page may be previewed
        if target != f"http://127.0.0.1:{PORT}/status":
            return jsonify(error="target not allowed"), 403
    try:
        r = requests.get(target, timeout=5)  # vuln: CWE-918
        return jsonify(status=r.status_code, snippet=r.text[:500])
    except requests.RequestException as e:
        return jsonify(error=str(e)), 502


@app.get("/v2/invoices")
def my_invoices():
    uid = session.get("uid")
    if uid is None:
        return jsonify(error="sign in"), 401
    rows = _DB.execute("SELECT * FROM invoices WHERE customer_id=?", (uid,)).fetchall()
    return jsonify(invoices=[dict(r) for r in rows])


@app.get("/v2/invoices/<int:n>")
def invoice(n):
    uid = session.get("uid")
    if uid is None:
        return jsonify(error="sign in"), 401  # both twins
    row = _DB.execute("SELECT * FROM invoices WHERE id=?", (n,)).fetchone()
    if row is None:
        return jsonify(error="no such invoice"), 404
    if not VULN and row["customer_id"] != uid and session.get("role") != "admin":
        return jsonify(error="forbidden"), 403
    # vuln: CWE-639, ownership never compared. Wrapped in a named envelope.
    return jsonify(invoice=dict(row), links={"self": f"/v2/invoices/{n}"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
