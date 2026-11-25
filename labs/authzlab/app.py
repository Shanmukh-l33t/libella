"""AuthzLab: ground truth for the expected-authorization oracle, one narrow fixture per case.

Every vulnerable route has a `/hard/...` twin with the check done correctly.
Cases: A/B notes (owner_only, BOLA), C tenant report, D account settings (anonymous),
E vault + profile (UNIVERSALLY accessible private data), F announcements (genuinely public),
role admin stats, billing (anonymous gets a 200 login page: a refusal, not access),
ledger (no policy at all). Lab-only: fake credentials, bind 127.0.0.1, port from LAB_PORT (0 = free).
"""
import os

from flask import Flask, jsonify, request, session

PORT = int(os.environ.get("LAB_PORT", "0"))
# username -> (id, password, role, tenant)
USERS = {
    "alice": (1, "SI_SECRET_PASSWORD_AUTHZ_A1", "user", "acme"),
    "bob": (2, "SI_SECRET_PASSWORD_AUTHZ_B2", "user", "acme"),
    "eve": (3, "SI_SECRET_PASSWORD_AUTHZ_E3", "user", "globex"),
    "dave": (4, "SI_SECRET_PASSWORD_AUTHZ_D4", "admin", "acme"),
}
BY_ID = {uid: {"id": uid, "username": n, "role": r, "tenant": t} for n, (uid, _p, r, t) in USERS.items()}
NOTES = {uid: {"id": uid, "owner": n, "note": f"private note of {n}"} for n, (uid, *_r) in USERS.items()}
VAULT = {uid: {"id": uid, "owner": n, "secret": f"vault secret of {n}"} for n, (uid, *_r) in USERS.items()}
LOGIN_PAGE = '<html><form action="/login" method="post"><input type="password" name="password"></form></html>'

app = Flask(__name__)
app.secret_key = "authzlab-lab-only-secret-do-not-use-in-prod"


def _me():
    return BY_ID.get(session.get("uid"))


def _hard() -> bool:
    return request.path.startswith("/hard/")


def _no(status, why):
    return jsonify(error=why), status


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or request.form
    row = USERS.get(data.get("username", ""))
    if row is None or data.get("password") != row[1]:
        return jsonify(authenticated=False)
    session["uid"] = row[0]
    return jsonify(authenticated=True, **BY_ID[row[0]])


def both(rule):
    def deco(fn):
        return app.get(rule)(app.get("/hard" + rule)(fn))
    return deco


@both("/api/notes/<int:nid>")  # B: owner_only; vulnerable = any authenticated user reads any note
def note(nid):
    who = _me()
    if who is None:
        return _no(401, "unauthorized")
    if nid not in NOTES:
        return _no(404, "not found")
    if _hard() and nid != who["id"]:
        return _no(403, "forbidden")
    return jsonify(NOTES[nid])


@both("/api/vault/<int:nid>")  # E: owner_only; vulnerable = EVERYONE incl. anonymous gets the same record
def vault(nid):
    who = _me()
    if _hard() and who is None:
        return _no(401, "unauthorized")
    if nid not in VAULT:
        return _no(404, "not found")
    if _hard() and nid != who["id"]:
        return _no(403, "forbidden")
    return jsonify(VAULT[nid])


@both("/api/profile")  # E (no id): owner_only; vulnerable = always serves alice's profile
def profile():
    who = _me()
    if who is None:
        return _no(401, "unauthorized")
    return jsonify(BY_ID[1] if not _hard() else who)


@both("/api/tenant/acme/report")  # C: tenant:acme; vulnerable = other tenants read it
def tenant_report():
    who = _me()
    if who is None:
        return _no(401, "unauthorized")
    if _hard() and who["tenant"] != "acme":
        return _no(403, "forbidden")
    return jsonify(report="acme quarterly numbers", tenant="acme")


@both("/api/account/settings")  # D: authenticated; vulnerable = anonymous reads it
def settings():
    who = _me()
    if who is None and _hard():
        return _no(401, "unauthorized")
    return jsonify(setting="notifications", value="weekly digest")


@both("/api/public/announcements")  # F: genuinely public, identical for everyone, on both twins
def announcements():
    return jsonify(title="Maintenance window", body="Saturday 02:00 UTC")


@both("/api/admin/stats")  # admin_only; vulnerable = any authenticated role
def admin_stats():
    who = _me()
    if who is None:
        return _no(401, "unauthorized")
    if _hard() and who["role"] != "admin":
        return _no(403, "forbidden")
    return jsonify(metric="active sessions", value=42)


@both("/api/account/billing")  # authenticated; anonymous gets 200 + a login page = NOT access (correct on both twins)
def billing():
    if _me() is None:
        return LOGIN_PAGE, 200, {"Content-Type": "text/html"}
    return jsonify(plan="team", invoice="INV-0042")


@both("/api/misc/ledger")  # H: nobody wrote a policy; everyone gets the same record
def ledger():
    return jsonify(entry="ledger line 7", amount=1200)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
