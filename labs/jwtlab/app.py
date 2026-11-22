"""JWTLab: a token API with real weak, confused and hardened verification paths.

/api/profile   accepts HS256 signed with a default secret, ignores exp, trusts
               the user_id/role claims        -> weak secret, expiry, claims
/api/none      accepts alg 'none' with an empty signature
/api/rs256     RS256, but an HS256 token is verified with the public key PEM
/api/hard      negative control: pinned HS256 + strong secret, exp required,
               identity and role read from the server-side user table
Lab-only: binds 127.0.0.1, fake credentials, keys generated on first start.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

PORT = int(os.environ.get("LAB_PORT", "0"))
WEAK_SECRET = "jwt" + "secret"                       # a wordlist default, by design
STRONG_SECRET = "jwtlab-strong-" + "9f2c41ab6e8d7c05"  # never a default
# name -> (user_id, password, role)
USERS = {
    "alice": (1, "alice-lab-pass", "user"),
    "bob": (2, "bob-lab-pass", "user"),
    "admin": (3, "admin-lab-pass", "admin"),
}
EMAILS = {1: "alice@lab.invalid", 2: "bob@lab.invalid", 3: "admin@lab.invalid"}

KEYS = Path(__file__).resolve().parent / "keys"
KEYS.mkdir(exist_ok=True)
PRIVATE_PEM = KEYS / "rs256.pem"
PUBLIC_PEM = KEYS / "public.pem"
if not (PRIVATE_PEM.exists() and PUBLIC_PEM.exists()):
    _key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIVATE_PEM.write_bytes(_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    PUBLIC_PEM.write_bytes(_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

app = Flask(__name__)


def claims_for(user: str) -> dict:
    uid, _, role = USERS[user]
    now = int(time.time())
    return {"sub": user, "user_id": uid, "role": role, "aud": "jwtlab-api",
            "iss": "jwtlab", "iat": now, "exp": now + 3600}


def token_in() -> str:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.cookies.get("jwt", "")


def raw_claims(token: str) -> dict:
    """Claims without any verification (what an alg:none endpoint trusts)."""
    parts = token.split(".")
    return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))


def unverified_header(token: str) -> dict:
    parts = token.split(".")
    return json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))


def hmac_claims(token: str, key: bytes) -> dict | None:
    """Hand-rolled HS256 verification: what a confused verifier does with a PEM."""
    try:
        head, body, sig = token.split(".")
        expected = base64.urlsafe_b64encode(
            hmac.new(key, f"{head}.{body}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(expected, sig):
            return None
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, IndexError):
        return None


def profile(claims: dict, marker: str) -> dict:
    uid = claims.get("user_id", 0)
    return {"marker": marker, "user": claims.get("sub"), "user_id": uid,
            "email": EMAILS.get(uid, "unknown@lab.invalid"),
            "role": claims.get("role"), "detail": "protected: profile of user"}


@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    user = body.get("username")
    if user not in USERS or body.get("password") != USERS[user][1]:
        return jsonify({"error": "invalid credentials"}), 401
    token = jwt.encode(claims_for(user), WEAK_SECRET, algorithm="HS256")
    resp = jsonify({"access_token": token, "token_type": "Bearer"})
    resp.set_cookie("jwt", token, httponly=False)  # discovery via Set-Cookie
    return resp


@app.post("/login-rs")
def login_rs():
    body = request.get_json(silent=True) or {}
    user = body.get("username")
    if user not in USERS or body.get("password") != USERS[user][1]:
        return jsonify({"error": "invalid credentials"}), 401
    token = jwt.encode(claims_for(user), PRIVATE_PEM.read_bytes(), algorithm="RS256",
                       headers={"kid": "rs1", "jku": request.host_url.rstrip("/") + "/jwks.json"})
    return jsonify({"access_token": token, "token_type": "Bearer"})


@app.post("/login-hard")
def login_hard():
    """Tokens the hardened endpoint actually accepts: strong secret, real issuer."""
    body = request.get_json(silent=True) or {}
    user = body.get("username")
    if user not in USERS or body.get("password") != USERS[user][1]:
        return jsonify({"error": "invalid credentials"}), 401
    token = jwt.encode(claims_for(user), STRONG_SECRET, algorithm="HS256")
    return jsonify({"access_token": token, "token_type": "Bearer"})


@app.get("/jwks.json")
def jwks():
    return jsonify({"keys": [{"kty": "RSA", "kid": "rs1", "alg": "RS256", "use": "sig",
                              "x5u": request.host_url.rstrip("/") + "/public.pem"}]})


@app.get("/public.pem")
def public_pem():
    return PUBLIC_PEM.read_bytes(), 200, {"Content-Type": "application/x-pem-file"}


@app.get("/api/profile")
def api_profile():
    token = token_in()
    try:
        # the lab's vulnerability: default secret, no exp check, claims trusted
        claims = jwt.decode(token, WEAK_SECRET, algorithms=["HS256"],
                            options={"verify_exp": False, "verify_aud": False})
    except jwt.PyJWTError:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(profile(claims, "protected:profile"))


@app.get("/api/none")
def api_none():
    token = token_in()
    try:
        header = unverified_header(token)
        if str(header.get("alg", "")).lower() != "none":
            return jsonify({"error": "unauthorized"}), 401
        claims = raw_claims(token)
    except (ValueError, IndexError, KeyError):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(profile(claims, "protected:none"))


@app.get("/api/rs256")
def api_rs256():
    token = token_in()
    try:
        alg = str(unverified_header(token).get("alg", "")).upper()
        if alg.startswith("RS"):
            claims = jwt.decode(token, PUBLIC_PEM.read_bytes(), algorithms=["RS256"],
                                options={"verify_exp": False})
        elif alg.startswith("HS"):
            # the classic confusion bug: the verification key is used as an HMAC secret
            claims = hmac_claims(token, PUBLIC_PEM.read_bytes())
            if claims is None:
                return jsonify({"error": "unauthorized"}), 401
        else:
            return jsonify({"error": "unauthorized"}), 401
    except (jwt.PyJWTError, ValueError):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(profile(claims, "protected:rs256"))


@app.get("/api/hard")
def api_hard():
    token = token_in()
    try:
        claims = jwt.decode(token, STRONG_SECRET, algorithms=["HS256"], audience="jwtlab-api",
                            options={"require": ["exp", "iat", "sub"], "verify_exp": True})
    except jwt.PyJWTError:
        return jsonify({"error": "unauthorized"}), 401
    user = claims.get("sub")
    if user not in USERS:  # identity and role come from the server, not the token
        return jsonify({"error": "unauthorized"}), 401
    uid, _, role = USERS[user]
    return jsonify({"marker": "protected:hard", "user": user, "user_id": uid,
                    "email": EMAILS[uid], "role": role})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
