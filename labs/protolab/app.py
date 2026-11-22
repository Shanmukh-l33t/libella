"""ProtoLab: one seeded web-protocol weakness per class, plus a /hard/* twin.

/pay      validation reads the FIRST copy of a duplicated parameter, the action
          settles the LAST one                          -> HPP
/export   GET refused (403), the protected action is only reachable by PUT
/portal   served by a hand-written proxy shim that builds its Location from
          the client's X-Forwarded-Host                  -> host header injection
/echo     reflects X-Forwarded-Host into a template comment, nothing more
/reset    builds the password-reset link from the client's Host header
/cache    in-process cache keyed on the path only; the response carries the
          caller's X-Cache-Canary, so one caller's value is served to the next
/hard/*   the same routes with the correct control: no candidates

Lab-only: binds 127.0.0.1 (LAB_PORT, 0 = ephemeral), module-level state, fake data.
"""
import os

from flask import Flask, Response, request
from werkzeug.serving import make_server

PORT = int(os.environ.get("LAB_PORT", "0"))
app = Flask(__name__)

CACHE: dict[str, tuple] = {}   # path -> (status, headers, body); path only, by design


def _remember(path: str, resp: Response):
    CACHE[path] = (resp.status_code,
                   {k: v for k, v in resp.headers.items()
                    if k.lower() not in ("content-length", "x-cache")},
                   resp.get_data())


def _cached(path: str):
    hit = CACHE.get(path)
    if hit is None:
        return None
    status, headers, body = hit
    r = Response(body, status=status)
    for k, v in headers.items():
        r.headers[k] = v
    r.headers["X-Cache"] = "HIT"
    return r


@app.get("/pay")
def pay():
    copies = request.args.getlist("amount")
    if not copies:
        return Response("amount required", status=400, mimetype="text/plain")
    if copies[0] != "100":                     # validated on the first copy
        return Response(f"amount {copies[0]} not allowed", status=400, mimetype="text/plain")
    return Response(f"charged amount={copies[-1]} status=settled", mimetype="text/plain")


@app.get("/hard/pay")
def hard_pay():
    copies = request.args.getlist("amount")
    if len(copies) != 1 or copies[0] != "100":
        return Response("invalid amount", status=400, mimetype="text/plain")
    return Response("charged amount=100 status=settled", mimetype="text/plain")


@app.get("/export")
def export_get():
    return Response("export requires an authorized PUT", status=403, mimetype="text/plain")


@app.route("/export", methods=["PUT", "POST", "PATCH", "DELETE"])
def export_write():
    if request.method != "PUT":
        return Response("unsupported", status=405, mimetype="text/plain")
    return Response("protected export: owner=alice balance=1234.56", mimetype="text/plain")


@app.route("/hard/export", methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
def hard_export():
    return Response("authentication required", status=403, mimetype="text/plain")


@app.get("/echo")
def echo():
    xfh = request.headers.get("X-Forwarded-Host", "none")
    return Response(f"<html><!-- debug host: {xfh} --><h1>welcome</h1></html>",
                    mimetype="text/html")


@app.get("/hard/echo")
def hard_echo():
    return Response("<html><!-- debug host: fixed --><h1>welcome</h1></html>",
                    mimetype="text/html")


@app.get("/reset")
def reset():
    host = request.headers.get("Host", "localhost")
    return Response(f'<html><a href="http://{host}/reset/confirm?token=demo">'
                    "reset password</a></html>", mimetype="text/html")


@app.get("/hard/reset")
def hard_reset():
    return Response('<html><a href="https://lab.invalid/reset/confirm?token=demo">'
                    "reset password</a></html>", mimetype="text/html")


@app.get("/cache")
def cache():
    hit = _cached(request.path)
    if hit is not None:
        return hit
    canary = request.headers.get("X-Cache-Canary", "")
    r = Response(f"<html><body>dashboard canary={canary}</body></html>", mimetype="text/html")
    r.headers["X-Cache"] = "MISS"
    r.headers["Cache-Control"] = "public, max-age=60"
    r.headers["X-Canary"] = canary
    _remember(request.path, r)
    return r


@app.get("/hard/cache")
def hard_cache():
    hit = _cached(request.path + ":" + request.headers.get("X-Cache-Canary", ""))
    if hit is not None:
        return hit
    canary = request.headers.get("X-Cache-Canary", "")
    r = Response(f"<html><body>dashboard canary={canary}</body></html>", mimetype="text/html")
    r.headers["Cache-Control"] = "private, no-store"
    r.headers["Vary"] = "X-Cache-Canary"
    r.headers["X-Canary"] = canary
    _remember(request.path + ":" + request.headers.get("X-Cache-Canary", ""), r)
    return r


class ProxyShim:
    """Hand-written stand-in for a reverse proxy: it owns the absolute redirects.

    It trusts X-Forwarded-Host unconditionally -- that is the seeded weakness.
    The /hard/ twins answer with a fixed relative Location.
    """

    def __init__(self, wsgi_app):
        self.app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path in ("/portal", "/hard/portal"):
            if path == "/hard/portal":
                location = "/hard/login"
            else:
                location = f"http://{environ.get('HTTP_X_FORWARDED_HOST', '')}/login"
            start_response("302 Found", [("Location", location), ("Content-Length", "0")])
            return [b""]
        return self.app(environ, start_response)


application = ProxyShim(app.wsgi_app)

if __name__ == "__main__":
    make_server("127.0.0.1", PORT, application).serve_forever()