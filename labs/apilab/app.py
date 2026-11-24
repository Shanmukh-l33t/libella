"""ApiLab: deterministic vulnerable/hardened JSON API twin for Libella benchmarks.

LAB_MODE=vuln (default) seeds known API weaknesses; LAB_MODE=hardened implements
the same routes with correct controls. OpenAPI 3 description in openapi.json,
ground truth in ground_truth.json. Lab-only: binds 127.0.0.1, fake credentials.

State is a module-level seeded SQLite database, so ids and content are stable
across requests (replayable proof requests) but drift as the assessment creates
objects — no response depends on mutable counts.
"""
import os
import sqlite3

from flask import Flask, jsonify, make_response, request, session
from werkzeug.security import check_password_hash, generate_password_hash

MODE = os.environ.get("LAB_MODE", "vuln")
VULN = MODE == "vuln"
PORT = int(os.environ.get("LAB_PORT", "8811" if VULN else "8812"))
SECRET = "apilab-lab-only-secret-do-not-use-in-prod"

ALICE_PW = "SI_SECRET_PASSWORD_APILAB_A1"
BOB_PW = "SI_SECRET_PASSWORD_APILAB_B2"
ADMIN_PW = "SI_SECRET_PASSWORD_APILAB_C3"

app = Flask(__name__)
app.secret_key = SECRET

conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.row_factory = sqlite3.Row


def _seed(db):
    db.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT,
                           role TEXT, email TEXT);
        CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT, owner_id INTEGER,
                           description TEXT, role TEXT DEFAULT 'user', is_admin INTEGER DEFAULT 0);
        """
    )
    db.executemany("INSERT INTO users VALUES(?,?,?,?,?)", [
        (1, "alice", generate_password_hash(ALICE_PW), "user", "alice@example.invalid"),
        (2, "bob", generate_password_hash(BOB_PW), "user", "bob@example.invalid"),
        (3, "admin", generate_password_hash(ADMIN_PW), "admin", "admin@example.invalid"),
    ])
    db.executemany("INSERT INTO items VALUES(?,?,?,?,?,?)", [
        (1, "Alice's notebook", 1, "Spiral bound", "user", 0),
        (2, "Bob's notebook", 2, "Leather bound", "user", 0),
        (3, "Alice's pen", 1, "Blue ink", "user", 0),
    ])
    db.commit()


_seed(conn)


@app.teardown_appcontext
def close_db(exc):
    pass  # module-level DB persists across requests (stable lab state)


def _item(row, detail=True):
    out = {"id": row["id"], "name": row["name"], "owner_id": row["owner_id"]}
    if detail:
        out["description"] = row["description"]
        if VULN:  # secret columns serialized straight from the row
            out["role"], out["is_admin"] = row["role"], row["is_admin"]
    return out


@app.get("/health")
def health():
    return jsonify(status="ok", mode=MODE)


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or request.form
    row = conn.execute("SELECT * FROM users WHERE username=?", (data.get("username", ""),)).fetchone()
    ok = row is not None and check_password_hash(row["password_hash"], data.get("password", ""))
    if ok:
        session["uid"], session["user"], session["role"] = row["id"], row["username"], row["role"]
    body = {"authenticated": ok}
    if ok:
        body.update(id=row["id"], role=row["role"], user=row["username"])
    return make_response(jsonify(body))


@app.get("/api/items")
def list_items():
    rows = conn.execute(
        "SELECT i.*, u.password_hash AS owner_password_hash FROM items i "
        "JOIN users u ON u.id = i.owner_id ORDER BY i.id"
    ).fetchall()
    if VULN:  # CWE-200: credential column joined into a public listing
        return jsonify([{**_item(r, False), "owner_password_hash": r["owner_password_hash"]} for r in rows])
    return jsonify([_item(r, False) for r in rows])


@app.get("/api/items/<int:iid>")
def get_item(iid):
    row = conn.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    if not session.get("uid"):
        return jsonify(error="unauthorized"), 401
    if not VULN and session["uid"] != row["owner_id"] and session.get("role") != "admin":
        return jsonify(error="forbidden"), 403  # fixed BOLA
    return jsonify(_item(row))  # vuln: CWE-639 any authenticated user reads any object


@app.post("/api/items")
def create_item():
    uid = session.get("uid")
    if not uid:
        return jsonify(error="unauthorized"), 401
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get("name"), str) or not data["name"].strip():
        return jsonify(error="name required"), 400
    fields = {"name": data["name"], "owner_id": uid, "description": str(data.get("description", ""))}
    if VULN:  # CWE-915: caller-chosen privileged columns bound straight into the insert
        fields.update({k: v for k, v in data.items() if k in ("role", "is_admin")})
    # column names come from the two fixed dicts above, never from user input
    cur = conn.execute(
        f"INSERT INTO items({','.join(fields)}) VALUES({','.join('?' * len(fields))})",
        tuple(fields.values()),
    )
    conn.commit()
    return jsonify(_item(conn.execute("SELECT * FROM items WHERE id=?", (cur.lastrowid,)).fetchone())), 201


@app.get("/api/admin/stats")
def admin_stats():
    if not VULN:
        if not session.get("uid"):
            return jsonify(error="unauthorized"), 401
        if session.get("role") != "admin":
            return jsonify(error="forbidden"), 403  # fixed BFLA
    return jsonify(db="sqlite", scope="admin", total_users=3)  # vuln: CWE-285 no role check


@app.get("/api/users/<int:uid>/profile")
def profile(uid):
    row = conn.execute("SELECT id, username, email, role FROM users WHERE id=?", (uid,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    if not VULN:
        if not session.get("uid"):
            return jsonify(error="unauthorized"), 401  # fixed CWE-306
        if session["uid"] != uid and session.get("role") != "admin":
            return jsonify(error="forbidden"), 403
    return jsonify(dict(row))  # vuln: CWE-639 cross-user read


@app.get("/openapi.json")
def openapi_spec():
    """The lab's own published description, as real APIs serve it in both twins."""
    import pathlib
    spec = pathlib.Path(__file__).with_name("openapi.json")
    return app.response_class(spec.read_text(), mimetype="application/json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
