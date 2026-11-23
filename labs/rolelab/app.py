"""RoleLab: a four-role app for the authenticated role-matrix sweep.

Seeded weaknesses: `/reports-all` leaks the report dump to anonymous callers
(the role guard only runs for a logged-in session) and `/api/users/<id>` lets
any authenticated user read any user (BOLA). Every `/hard/*` route mirrors the
same function with the check done correctly: a negative control that must
yield zero findings.

State is module-level and seeded once, so ids are stable across requests and
proof replays see the same records. Lab-only: binds 127.0.0.1, fake creds.
"""
import os

from flask import Flask, jsonify, request, session

PORT = int(os.environ.get("LAB_PORT", "8813"))
SECRET = "rolelab-lab-only-secret-do-not-use-in-prod"

# username -> (id, password, role)
USERS = {
    "alice": (1, "SI_SECRET_PASSWORD_ROLELAB_A1", "user"),
    "bob": (2, "SI_SECRET_PASSWORD_ROLELAB_B2", "user"),
    "carol": (3, "SI_SECRET_PASSWORD_ROLELAB_M3", "manager"),
    "dave": (4, "SI_SECRET_PASSWORD_ROLELAB_D4", "admin"),
}
BY_ID = {uid: {"id": uid, "username": name, "email": f"{name}@rolelab.invalid", "role": role}
         for name, (uid, _pw, role) in USERS.items()}
ORDERS = {
    1: {"id": 1, "item": "Widget", "owner_id": 1},
    2: {"id": 2, "item": "Gadget", "owner_id": 2},
}
ADMIN_NOTES = {1: {"order_id": 1, "note": "manual review: chargeback on order 1"}}
REPORTS = [
    {"id": 1, "title": "Q3 revenue", "body": "internal: 4.2M", "owner": "carol"},
    {"id": 2, "title": "Churn analysis", "body": "internal: churn 3.1%", "owner": "carol"},
]

app = Flask(__name__)
app.secret_key = SECRET


def _me():
    return BY_ID.get(session.get("uid"))


def _hard() -> bool:
    """Same handler, stricter checks: the /hard/* mirror is the control."""
    return request.path.startswith("/hard/")


def _deny(status: int, why: str):
    return jsonify(error=why), status


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or request.form
    row = USERS.get(data.get("username", ""))
    if row is None or data.get("password") != row[1]:
        return jsonify(authenticated=False)
    session["uid"], session["username"], session["role"] = row[0], data["username"], row[2]
    return jsonify(authenticated=True, **BY_ID[row[0]])


@app.get("/api/me")
@app.get("/hard/api/me")
def me():
    who = _me()
    if who is None:
        return _deny(401, "unauthorized")
    return jsonify(who)


@app.get("/api/orders/<int:oid>")
@app.get("/hard/api/orders/<int:oid>")
def order(oid):
    who = _me()
    if who is None:
        return _deny(401, "unauthorized")
    row = ORDERS.get(oid)
    if row is None:
        return _deny(404, "not found")
    if row["owner_id"] != who["id"] and who["role"] != "admin":
        return _deny(403, "forbidden")  # owner-only, correct in both modes
    return jsonify(row)


@app.get("/api/orders/<int:oid>/admin-note")
@app.get("/hard/api/orders/<int:oid>/admin-note")
def admin_note(oid):
    who = _me()
    if who is None:
        return _deny(401, "unauthorized")
    if who["role"] != "admin":
        return _deny(403, "forbidden")  # admin-only, correct in both modes
    row = ADMIN_NOTES.get(oid)
    if row is None:
        return _deny(404, "not found")
    return jsonify(row)


@app.get("/api/reports")
@app.get("/hard/api/reports")
def reports():
    who = _me()
    if who is None:
        return _deny(401, "unauthorized")
    if who["role"] not in ("manager", "admin"):
        return _deny(403, "forbidden")  # manager+, correct in both modes
    return jsonify(REPORTS)


@app.get("/reports-all")
@app.get("/hard/reports-all")
def reports_all():
    who = _me()
    if _hard():
        if who is None:
            return _deny(401, "unauthorized")
        if who["role"] not in ("manager", "admin"):
            return _deny(403, "forbidden")
        return jsonify(REPORTS)
    # seeded weakness: the role guard only runs for a logged-in session, so an
    # anonymous request falls straight through to the full report dump
    if who is not None and who["role"] not in ("manager", "admin"):
        return _deny(403, "forbidden")
    return jsonify(REPORTS)


@app.get("/api/users/<int:uid>")
@app.get("/hard/api/users/<int:uid>")
def user(uid):
    who = _me()
    if who is None:
        return _deny(401, "unauthorized")
    if _hard() and who["id"] != uid and who["role"] != "admin":
        return _deny(403, "forbidden")  # fixed BOLA
    row = BY_ID.get(uid)
    if row is None:
        return _deny(404, "not found")
    return jsonify(row)  # vuln: any authenticated user reads any user


@app.post("/api/reports/create")
@app.post("/hard/api/reports/create")
def create_report():
    who = _me()
    if who is None:
        return _deny(401, "unauthorized")
    if who["role"] not in ("manager", "admin"):
        return _deny(403, "forbidden")  # manager-only, correct in both modes
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get("title"), str) or not data["title"].strip():
        return _deny(400, "title required")
    row = {"id": len(REPORTS) + 1, "title": data["title"], "body": "", "owner": who["username"]}
    REPORTS.append(row)
    return jsonify(row), 201


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
