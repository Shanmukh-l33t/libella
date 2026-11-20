"""PairLab: deterministic vulnerable/hardened twin app for Libella benchmarks.

LAB_MODE=vuln (default) seeds known weaknesses; LAB_MODE=hardened implements
the same routes with correct controls. Ground truth in ground_truth.json.
Lab-only: binds 127.0.0.1, fake credentials, no real data.
"""
import html
import os
import sqlite3
import urllib.parse

import requests
from flask import Flask, g, jsonify, redirect, request, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash

MODE = os.environ.get("LAB_MODE", "vuln")
VULN = MODE == "vuln"
PORT = int(os.environ.get("LAB_PORT", "8801"))
SECRET = "pairlab-lab-only-secret-do-not-use-in-prod"

app = Flask(__name__)
app.secret_key = SECRET
if VULN:
    # CWE-614: session cookie without HttpOnly/Secure/SameSite
    app.config["SESSION_COOKIE_HTTPONLY"] = False
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_SAMESITE"] = None

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public_files")
os.makedirs(FILES_DIR, exist_ok=True)
with open(os.path.join(FILES_DIR, "readme.txt"), "w") as f:
    f.write("PairLab public file. Nothing sensitive here.\n")
with open(os.path.join(os.path.dirname(FILES_DIR), "private_config.txt"), "w") as f:
    f.write("LAB_PRIVATE_MARKER=traversal-proof-7f3a\n")


def db():
    return _DB


def seed(conn):
    c = conn.cursor()
    c.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL);
        CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total REAL, address TEXT);
        """
    )
    pw = generate_password_hash("lab-password-123")
    c.executemany("INSERT INTO users VALUES(?,?,?,?)", [
        (1, "alice", pw, "user"), (2, "bob", pw, "user"),
        (3, "admin", generate_password_hash("admin-lab-pass-456"), "admin"),
    ])
    c.executemany("INSERT INTO products VALUES(?,?,?,?)", [
        (1, "Widget", "tools", 9.99), (2, "Gadget", "tools", 19.99),
        (3, "Gizmo", "toys", 4.99), (4, "Doohickey", "toys", 2.49),
    ])
    c.executemany("INSERT INTO orders VALUES(?,?,?,?,?)", [
        (101, 1, "Widget", 9.99, "1 Lab Lane, Testville"),
        (102, 2, "Gadget", 19.99, "2 Lab Lane, Testville"),
        (103, 1, "Gizmo", 4.99, "1 Lab Lane, Testville"),
    ])
    conn.commit()


_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.row_factory = sqlite3.Row
seed(_DB)


@app.teardown_appcontext
def close_db(exc):
    pass  # module-level DB persists across requests (stable lab state)


@app.after_request
def headers(resp):
    if VULN:
        resp.headers["X-Powered-By"] = "Express/4.16.0"  # version-signal negative control
        resp.headers["Server"] = "nginx/1.18.0"
    else:
        resp.headers["Server"] = "libella-pairlab"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/")
def index():
    return (
        "<html><body><h1>PairLab (%s mode)</h1><ul>"
        "<li><a href='/search?q=hello'>search</a></li>"
        "<li><a href='/api/products?category=tools'>products API</a></li>"
        "<li><a href='/files?name=readme.txt'>files</a></li>"
        "<li><a href='/uploads/'>uploads</a></li>"
        "<li><a href='/health'>health</a></li>"
        "</ul></body></html>" % MODE
    )


@app.get("/health")
def health():
    return jsonify(status="ok", mode=MODE)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    if VULN:
        body = "<html><body>Results for: %s</body></html>" % q  # CWE-79
    else:
        body = "<html><body>Results for: %s</body></html>" % html.escape(q)
    return body


@app.get("/api/products")
def products():
    cat = request.args.get("category", "")
    if VULN:
        rows = db().execute(
            "SELECT id,name,category,price FROM products WHERE category='%s'" % cat
        ).fetchall()  # CWE-89
    else:
        rows = db().execute(
            "SELECT id,name,category,price FROM products WHERE category=?", (cat,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/login")
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    if VULN:
        row = db().execute(
            "SELECT id,username,role FROM users WHERE username='%s' AND password='%s'"
            % (u, p)
        ).fetchone()  # CWE-89 auth bypass
        if row is None:
            # legitimate credentials still work (hash compare), so authenticated
            # workflows can be tested alongside the bypass
            legit = db().execute(
                "SELECT id,username,password,role FROM users WHERE username=?", (u,)
            ).fetchone()
            if legit is not None and check_password_hash(legit["password"], p):
                row = legit
        ok = row is not None
        if ok:
            session["uid"], session["user"], session["role"] = row["id"], row["username"], row["role"]
    else:
        row = db().execute(
            "SELECT id,username,password,role FROM users WHERE username=?", (u,)
        ).fetchone()
        ok = row is not None and check_password_hash(row["password"], p)
        if ok:
            session["uid"], session["user"], session["role"] = row["id"], row["username"], row["role"]
    resp = make_response(jsonify(authenticated=ok))
    if not VULN:
        resp.set_cookie("lab_session_marker", "1", secure=True, httponly=True, samesite="Strict")
    return resp


@app.get("/api/orders/<int:oid>")
def order(oid):
    row = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    if not VULN:
        if session.get("uid") != row["user_id"] and session.get("role") != "admin":
            return jsonify(error="forbidden"), 403  # fixed BOLA
    return jsonify(dict(row))  # vuln: CWE-639 IDOR/BOLA


@app.get("/api/profile")
def profile():
    uid = session.get("uid")
    data = {"user": session.get("user"), "uid": uid, "email": "lab@example.invalid"}
    resp = jsonify(data)
    if VULN:
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Credentials"] = "true"  # CWE-942 misconfig
    else:
        origin = request.headers.get("Origin", "")
        if origin in ("http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.get("/api/users")
def users():
    if VULN:
        rows = db().execute("SELECT id,username,password,role FROM users").fetchall()
        return jsonify([dict(r) for r in rows])  # CWE-200 excessive data exposure
    if not session.get("uid"):
        return jsonify(error="unauthorized"), 401
    return jsonify(user=session.get("user"), uid=session.get("uid"))


@app.get("/files")
def files():
    name = request.args.get("name", "readme.txt")
    if VULN:
        path = os.path.join(FILES_DIR, name)  # CWE-22 traversal
    else:
        safe = os.path.basename(name)
        path = os.path.join(FILES_DIR, safe)
        if not os.path.isfile(path):
            return jsonify(error="not found"), 404
    try:
        with open(path) as f:
            return f.read(), 200, {"Content-Type": "text/plain"}
    except OSError:
        return jsonify(error="not found"), 404


@app.get("/uploads/")
def uploads():
    if VULN:
        entries = os.listdir(FILES_DIR)  # CWE-548 directory listing
        return "<html><body><ul>%s</ul></body></html>" % "".join(
            "<li>%s</li>" % e for e in entries
        )
    return jsonify(error="forbidden"), 403


@app.get("/internal/meta")
def meta():
    # simulated cloud metadata endpoint, lab-only fake credentials
    return jsonify({"lab-only": True, "access_key": "LABFAKEKEY0000", "token": "LABFAKETOKEN"})


@app.get("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="url required"), 400
    if not VULN:
        allowed = "http://127.0.0.1:%d/" % PORT
        if not url.startswith(allowed) or "/internal/" in url:
            return jsonify(error="url not allowed"), 403  # fixed SSRF
    try:
        r = requests.get(url, timeout=5)
        return r.text[:2000], r.status_code, {"Content-Type": "text/plain"}
    except requests.RequestException as e:
        return jsonify(error=str(e)), 502  # vuln: CWE-918 SSRF


@app.get("/redirect")
def redir():
    to = request.args.get("to", "/")
    if not VULN:
        parsed = urllib.parse.urlparse(to)
        if parsed.netloc or not to.startswith("/"):
            return jsonify(error="redirect not allowed"), 400  # fixed open redirect
    return redirect(to)  # vuln: CWE-601


@app.get("/debug")
def debug():
    if VULN:
        return jsonify(secret_key=SECRET, mode=MODE, db=":memory:", env=dict(os.environ))
    return jsonify(error="not found"), 404


@app.post("/upload")
def upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        return jsonify(error="file required"), 400
    name = f.filename
    if VULN:
        # CWE-434: no extension/content validation, original name kept
        dest = os.path.join(FILES_DIR, name)
        f.save(dest)
        return jsonify(uploaded=True, path="/files?name=" + name, marker="UPLOAD_ACCEPTED")
    safe_ext = {".txt", ".png", ".jpg", ".pdf"}
    ext = os.path.splitext(name)[1].lower()
    if ext not in safe_ext:
        return jsonify(error="extension not allowed"), 400
    safe = "upload_" + os.urandom(8).hex() + ext
    f.save(os.path.join(FILES_DIR, safe))
    return jsonify(uploaded=True, path="/files?name=" + safe)


@app.get("/greet")
def greet():
    from flask import render_template_string
    name = request.args.get("name", "world")
    if VULN:
        # CWE-1336: user input rendered as template source
        return render_template_string("Hello " + name)
    return render_template_string("Hello {{ name }}", name=name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)