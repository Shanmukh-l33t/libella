"""AuthLab: deterministic vulnerable/hardened session-auth web app for Libella.

LAB_MODE=vuln (default) seeds broken object/function level authorization on
server-rendered pages and a login -> view item -> transfer flow; LAB_MODE=hardened
enforces ownership, role and CSRF on the same routes and forms. Lab-only: binds
127.0.0.1 in tests via labctl, fake credentials, no external egress.
"""
import os
import secrets
import sqlite3

from flask import Flask, abort, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

MODE = os.environ.get("LAB_MODE", "vuln")
VULN = MODE == "vuln"
PORT = int(os.environ.get("LAB_PORT", "8831" if VULN else "8832"))
SECRET = "authlab-lab-only-secret-do-not-use-in-prod"

ALICE_PW = "SI_SECRET_PASSWORD_AUTHLAB_A1"
BOB_PW = "SI_SECRET_PASSWORD_AUTHLAB_B2"
ADMIN_PW = "SI_SECRET_PASSWORD_AUTHLAB_C3"

BASE = """<!doctype html><html><head><title>{{title}}</title></head><body>
<nav><a href="/dashboard">Dashboard</a> <a href="/profile">Profile</a>
{% if show_admin %}<a href="/admin">Admin</a>{% endif %} <a href="/logout">Sign out</a></nav>
{{body|safe}}
</body></html>"""

LOGIN = """<!doctype html><html><head><title>Sign in</title></head><body>
<h1>Sign in</h1>
{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="post" action="/login">
  <input type="hidden" name="csrf" value="{{csrf}}">
  <label>Username <input name="username"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Sign in</button>
</form>
</body></html>"""

DASH = """<!doctype html><html><head><title>Dashboard</title></head><body>
<nav><a href="/dashboard">Dashboard</a> <a href="/profile?uid={{uid}}">Profile</a>
{% if show_admin %}<a href="/admin">Admin</a>{% endif %}</nav>
<h1 id="dashboard">Dashboard</h1>
<p>Signed in as {{user}} ({{role}})</p>
<ul>
{% for i in items %}
  <li><a href="/items/{{i['id']}}">{{i['name']}}</a> owner {{i['owner']}}</li>
{% endfor %}
</ul>
{% for i in items %}
<form method="post" action="/items/{{i['id']}}/transfer">
  <input type="hidden" name="csrf" value="{{csrf}}">
  <input name="to" placeholder="recipient">
  <button type="submit">Transfer {{i['name']}}</button>
</form>
{% endfor %}
<script>fetch('/api/me').then(r => r.json()).then(d => {document.title = 'Dashboard ' + d.user;});</script>
</body></html>"""

ITEM = """<!doctype html><html><head><title>{{item['name']}}</title></head><body>
<nav><a href="/dashboard">Dashboard</a> <a href="/profile">Profile</a></nav>
<h1 id="item">{{item['name']}}</h1>
<p>Owner: <span id="owner">{{owner}}</span></p>
<p>{{item['description']}}</p>
<form method="post" action="/items/{{item['id']}}/transfer">
  <input type="hidden" name="csrf" value="{{csrf}}">
  <input name="to" placeholder="recipient">
  <button type="submit">Transfer</button>
</form>
</body></html>"""

PROFILE = """<!doctype html><html><head><title>Profile</title></head><body>
<nav><a href="/dashboard">Dashboard</a> <a href="/profile">Profile</a></nav>
<h1 id="profile">Profile</h1>
<p>Username: {{u['username']}}</p>
<p>Email: {{u['email']}}</p>
{% if role %}<p>Role: {{u['role']}}</p>{% endif %}
</body></html>"""

ADMIN = """<!doctype html><html><head><title>Admin</title></head><body>
<nav><a href="/dashboard">Dashboard</a> <a href="/profile">Profile</a>
<a href="/admin">Admin</a></nav>
<h1 id="admin">Admin panel</h1>
<p>Site statistics: 3 users, 3 items, mode {{mode}}</p>
</body></html>"""

app = Flask(__name__)
app.secret_key = SECRET

conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.row_factory = sqlite3.Row
conn.executescript(
    """
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT,
                       role TEXT, email TEXT);
    CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT, owner_id INTEGER, description TEXT);
    """
)
conn.executemany("INSERT INTO users VALUES(?,?,?,?,?)", [
    (1, "alice", generate_password_hash(ALICE_PW), "user", "alice@example.invalid"),
    (2, "bob", generate_password_hash(BOB_PW), "user", "bob@example.invalid"),
    (3, "admin", generate_password_hash(ADMIN_PW), "admin", "admin@example.invalid"),
])
conn.executemany("INSERT INTO items VALUES(?,?,?,?)", [
    (1, "Alice's notebook", 1, "Spiral bound"),
    (2, "Bob's notebook", 2, "Leather bound"),
    (3, "Alice's pen", 1, "Blue ink"),
])
conn.commit()


def _csrf() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(8)
    return session["csrf"]


def _csrf_ok() -> bool:
    return secrets.compare_digest(str(session.get("csrf", "")), request.form.get("csrf", ""))


def _items(where: str = "", args: tuple = ()) -> list:
    return conn.execute(
        "SELECT i.*, u.username AS owner FROM items i JOIN users u ON u.id = i.owner_id "
        f"{where} ORDER BY i.id", args).fetchall()


@app.get("/")
def index():
    return redirect("/dashboard" if session.get("uid") else "/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN, csrf=_csrf())
    row = conn.execute("SELECT * FROM users WHERE username=?",
                       (request.form.get("username", ""),)).fetchone()
    if row is None or not check_password_hash(row["password_hash"],
                                             request.form.get("password", "")):
        return render_template_string(LOGIN, csrf=_csrf(), error="invalid credentials"), 401
    session.clear()
    session["uid"], session["user"], session["role"] = row["id"], row["username"], row["role"]
    return redirect("/dashboard")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/dashboard")
def dashboard():
    if not session.get("uid"):
        return redirect("/login")
    items = _items() if VULN else _items("WHERE i.owner_id=?", (session["uid"],))
    return render_template_string(
        DASH, user=session["user"], role=session["role"], items=items, csrf=_csrf(),
        uid=session["uid"], show_admin=VULN or session["role"] == "admin")


@app.get("/items/<int:iid>")
def item(iid):
    if not session.get("uid"):
        return redirect("/login")
    row = conn.execute(
        "SELECT i.*, u.username AS owner FROM items i JOIN users u ON u.id = i.owner_id "
        "WHERE i.id=?", (iid,)).fetchone()
    if row is None:
        abort(404)
    if not VULN and row["owner_id"] != session["uid"] and session.get("role") != "admin":
        abort(403)  # fixed BOLA
    return render_template_string(ITEM, item=row, owner=row["owner"], csrf=_csrf())


@app.post("/items/<int:iid>/transfer")
def transfer(iid):
    if not session.get("uid"):
        return redirect("/login")
    if not VULN and not _csrf_ok():
        abort(400)  # fixed CSRF on the state-changing step
    row = conn.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
    if row is None:
        abort(404)
    if not VULN and row["owner_id"] != session["uid"] and session.get("role") != "admin":
        abort(403)  # fixed BOLA on the workflow action
    to = conn.execute("SELECT id FROM users WHERE username=?",
                      (request.form.get("to", ""),)).fetchone()
    if to is None:
        abort(400)
    conn.execute("UPDATE items SET owner_id=? WHERE id=?", (to["id"], iid))
    conn.commit()
    return redirect(f"/items/{iid}")


@app.get("/profile")
def profile():
    if not session.get("uid"):
        return redirect("/login")
    uid = request.args.get("uid", type=int) or session["uid"]
    if not VULN and uid != session["uid"] and session.get("role") != "admin":
        abort(403)
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if row is None:
        abort(404)
    return render_template_string(PROFILE, u=row, role=VULN)


@app.get("/admin")
def admin():
    if not session.get("uid"):
        return redirect("/login")
    if not VULN and session.get("role") != "admin":
        abort(403)  # fixed BFLA
    return render_template_string(ADMIN, mode=MODE)


@app.get("/api/me")
def me():
    if not session.get("uid"):
        return {"authenticated": False}, 401
    return {"authenticated": True, "user": session["user"], "role": session["role"]}


@app.get("/health")
def health():
    return {"status": "ok", "mode": MODE}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
