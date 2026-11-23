"""OAuthLab: an authorization server + session app with seeded flaws.

Vulnerable routes seed what the audit must find: redirect_uri matched by string
prefix or by path only, no `state`, no PKCE, implicit flow, scope granted
verbatim, session fixation, logout that only clears the client cookie, and a
password change with no re-authentication. `/hard/*` implements the same flows
correctly and is the negative control.

`/steal` is the attacker page: the lab binds 0.0.0.0 so the same process is
reachable at http://127.0.0.2:<port>, the loopback alias a redirect can really
land on. Lab only: loopback, fake users, no egress.
"""
import base64
import hashlib
import secrets
import threading
from urllib.parse import urlencode, urlparse

from flask import Flask, make_response, redirect, request
from werkzeug.serving import make_server

app = Flask(__name__)
CLIENT_ID = "labclient"
REDIRECT_PATH = "/callback"
HARD_REDIRECT_PATH = "/hard/callback"
USERS = {"alice": "SI_SECRET_PASSWORD_OAUTHLAB_A1"}
HARD_SCOPES = {"profile", "email"}
CODES: dict[str, dict] = {}
SESSIONS: dict[str, dict] = {}


def _base() -> str:
    return app.config.get("BASE") or request.host_url.rstrip("/")


def _vuln_redirect_ok(requested: str) -> bool:
    registered = _base() + REDIRECT_PATH
    # seed 1: string prefix match (so `<registered>@attacker` passes).
    # seed 2: only the path is compared (so any host serving /callback passes).
    return requested.startswith(registered) or urlparse(requested).path.startswith(REDIRECT_PATH)


@app.get("/authorize")
def authorize():
    if request.args.get("client_id") != CLIENT_ID:
        return "invalid client", 400
    ru = request.args.get("redirect_uri", "")
    if not _vuln_redirect_ok(ru):
        return "invalid redirect_uri", 400
    state = request.args.get("state")  # seed: optional, echoed, never validated
    scope = request.args.get("scope", "profile")  # seed: granted verbatim
    code = secrets.token_urlsafe(12)
    CODES[code] = {"scope": scope, "sub": "alice", "redirect": ru}
    if request.args.get("response_type") == "token":  # seed: implicit flow offered
        frag = urlencode({"access_token": secrets.token_urlsafe(16), "token_type": "Bearer",
                          "scope": scope})
        return redirect(f"{ru}#{frag}", 302)
    if request.args.get("response_mode") == "form_post":
        return (f'<html><body><form method="post" action="{ru}">'
                f'<input name="code" value="{code}"></form></body></html>')
    query = {"code": code, **({"state": state} if state else {})}
    return redirect(f"{ru}?{urlencode(query)}", 302)


@app.post("/token")
def token():
    entry = CODES.get(request.form.get("code", ""))
    if entry is None:
        return {"error": "invalid_grant"}, 400
    # seed: no PKCE check, no client authentication, code not consumed
    return {"access_token": secrets.token_urlsafe(16), "token_type": "Bearer",
            "scope": entry["scope"], "sub": entry["sub"]}


@app.get("/callback")
@app.get("/hard/callback")
def callback():
    return f"<html><body>code={request.args.get('code', '')} state={request.args.get('state', '')}</body></html>"


def _s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


@app.get("/hard/authorize")
def hard_authorize():
    registered = _base() + HARD_REDIRECT_PATH
    if request.args.get("client_id") != CLIENT_ID:
        return "invalid client", 400
    if request.args.get("redirect_uri") != registered:  # exact match only
        return "invalid redirect_uri", 400
    if not request.args.get("state"):
        return "state required", 400
    if request.args.get("response_type", "code") != "code":
        return "unsupported_response_type", 400
    scope = request.args.get("scope", "profile")
    if not set(scope.split()) <= HARD_SCOPES:  # no escalation
        return "invalid_scope", 400
    challenge = request.args.get("code_challenge")
    if not challenge or request.args.get("code_challenge_method") != "S256":
        return "code_challenge required", 400
    code = secrets.token_urlsafe(12)
    CODES[code] = {"scope": scope, "sub": "alice", "redirect": registered,
                   "challenge": challenge}
    return redirect(f"{registered}?{urlencode({'code': code, 'state': request.args['state']})}", 302)


@app.post("/hard/token")
def hard_token():
    entry = CODES.get(request.form.get("code", ""))
    if entry is None or not entry.get("challenge"):
        return {"error": "invalid_grant"}, 400
    if _s256(request.form.get("code_verifier", "")) != entry["challenge"]:
        return {"error": "invalid_grant"}, 400
    CODES.pop(request.form["code"], None)  # single use
    return {"access_token": secrets.token_urlsafe(16), "token_type": "Bearer",
            "scope": entry["scope"], "sub": entry["sub"]}


@app.get("/steal")
def steal():
    """The attacker page a bypass delivers the code to."""
    return (f"<html><body>attacker collected code={request.args.get('code', '')} "
            f"state={request.args.get('state', '')} "
            f"referer={request.headers.get('Referer', '')}</body></html>")


LOGIN_FORM = ("<html><body><form method='post'>"
              "<input name='username'><input name='password' type='password'>"
              "<button>Sign in</button></form></body></html>")


def _login(prefix: str):
    if request.method == "GET":
        return LOGIN_FORM
    user = request.form.get("username", "")
    if USERS.get(user) != request.form.get("password", ""):
        return "invalid credentials", 401
    if prefix == "/hard/session":
        sid = secrets.token_urlsafe(16)  # a client-supplied id is never adopted
        resp = make_response(f"Signed in as {user}")
        resp.set_cookie("sid", sid, path="/", httponly=True, samesite="Lax")
    else:
        sid = request.cookies.get("sid") or secrets.token_urlsafe(16)  # seed: fixation
        resp = make_response(f"Signed in as {user}")
        resp.set_cookie("sid", sid, path="/")  # seed: no HttpOnly, no SameSite
    SESSIONS[sid] = {"user": user}
    return resp


def _me(prefix: str):
    sess = SESSIONS.get(request.cookies.get("sid", ""))
    if sess is None:
        return "not authenticated", 401
    return f"Signed in as {sess['user']}"


def _logout(prefix: str):
    sid = request.cookies.get("sid", "")
    if prefix == "/hard/session":
        SESSIONS.pop(sid, None)  # server-side invalidation
        resp = redirect("/hard/session/login", 302)
    else:
        resp = redirect(f"/session/login?sid={sid}", 302)  # seed: id leaks into a URL
    resp.delete_cookie("sid", path="/")  # seed: only the client copy is removed
    return resp


def _password(prefix: str):
    sess = SESSIONS.get(request.cookies.get("sid", ""))
    if sess is None:
        return "not authenticated", 401
    if prefix == "/hard/session" and request.form.get("current_password") != USERS[sess["user"]]:
        return "current password required", 403
    new = request.form.get("new_password", "")
    if not new:
        return "new_password required", 400
    USERS[sess["user"]] = new
    return f"password changed for {sess['user']}"


app.add_url_rule("/session/login", "session_login", lambda: _login("/session"), methods=["GET", "POST"])
app.add_url_rule("/hard/session/login", "hard_login", lambda: _login("/hard/session"), methods=["GET", "POST"])
app.add_url_rule("/session/me", "session_me", lambda: _me("/session"), methods=["GET"])
app.add_url_rule("/hard/session/me", "hard_me", lambda: _me("/hard/session"), methods=["GET"])
app.add_url_rule("/session/logout", "session_logout", lambda: _logout("/session"), methods=["GET", "POST"])
app.add_url_rule("/hard/session/logout", "hard_logout", lambda: _logout("/hard/session"), methods=["GET", "POST"])
app.add_url_rule("/session/password", "session_password", lambda: _password("/session"), methods=["POST"])
app.add_url_rule("/hard/session/password", "hard_password", lambda: _password("/hard/session"), methods=["POST"])


def start_lab() -> dict:
    """-> {base, attacker, server}. Binds all interfaces so 127.0.0.2 resolves."""
    srv = make_server("0.0.0.0", 0, app, threaded=True)
    app.config["BASE"] = f"http://127.0.0.1:{srv.server_port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return {"base": app.config["BASE"], "attacker": f"http://127.0.0.2:{srv.server_port}",
            "server": srv}
