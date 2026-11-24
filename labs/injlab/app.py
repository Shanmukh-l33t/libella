"""InjectionLab: one deliberately vulnerable endpoint per injection class, plus hardened mirrors.

/xml        DOCTYPE entities resolved, SYSTEM ids (file:// and http://) fetched  -> XXE
/ping       shell command built from the host parameter                          -> command injection
/download   open() on a joined base path, never normalised                       -> LFI / traversal
/setcookie  the parameter is written into a response header verbatim             -> CRLF header injection
/hard/*     the same four routes, validating input; each must yield nothing
Lab-only: binds 127.0.0.1, reads only files this user may read, fetches only the SYSTEM
ids named in the document it is handed. Never deploy this.
"""
import os
import re
import socket
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from flask import Flask, Response, request
from werkzeug.datastructures import Headers

PORT = int(os.environ.get("LAB_PORT", "0"))
BASE = Path(tempfile.mkdtemp(prefix="injlab-files-", dir="/tmp"))  # shallow: a few ../ reach /
(BASE / "index.php").write_text("<?php echo 'injlab'; ?>\n")
(BASE / "public.txt").write_text("public file\n")

app = Flask(__name__)

_SYSTEM = re.compile(r"""<!ENTITY\s+(%?)\s*([\w.:-]+)\s+SYSTEM\s+["']([^"']+)["']\s*>""")
_INTERNAL = re.compile(r"""<!ENTITY\s+([\w.:-]+)\s+["']([^"']*)["']\s*>""")


def _param(name: str) -> str:
    """The one declared parameter: query string, form field or JSON field, decoded once."""
    if request.is_json:
        return str((request.get_json(silent=True) or {}).get(name, ""))
    return request.values.get(name, "")


def _fetch(uri: str) -> str:
    """Resolve a SYSTEM id the way a parser with entity resolution enabled does."""
    if uri.startswith("file://"):
        try:
            return Path(uri[len("file://"):]).read_text(errors="replace")
        except OSError:
            return ""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(uri, timeout=2) as r:  # lab: models the vulnerable parser
            return r.read(4096).decode(errors="replace")
    except Exception:
        return ""


def _expand(doc: str) -> str:
    """Tiny entity expander: parameter entities first, then general entities."""
    for m in _SYSTEM.finditer(doc):
        if m.group(1) == "%":
            doc = doc.replace(f"%{m.group(2)};", _fetch(m.group(3)))
    for m in _SYSTEM.finditer(doc):
        if not m.group(1):
            doc = doc.replace(f"&{m.group(2)};", _fetch(m.group(3)))
    for m in _INTERNAL.finditer(doc):
        doc = doc.replace(f"&{m.group(1)};", m.group(2))
    return doc


class _RawHeaders(Headers):
    """Emit extra header lines verbatim, CRLF and all: exactly what the endpoint must not do."""

    def __init__(self, headers, extra):
        super().__init__(headers)
        self._extra = extra or []

    def to_wsgi_list(self):
        return super().to_wsgi_list() + self._extra


class _RawResponse(Response):
    extra_headers: list = []

    def get_wsgi_headers(self, environ):
        return _RawHeaders(list(super().get_wsgi_headers(environ)), self.extra_headers)


@app.route("/xml", methods=["GET", "POST"])
def xml():
    return Response(_expand(_param("xml")), mimetype="text/plain")


@app.route("/hard/xml", methods=["GET", "POST"])
def hard_xml():
    doc = _param("xml")
    if re.search(r"<!DOCTYPE|<!ENTITY", doc, re.I):
        return Response("external entities refused", status=400, mimetype="text/plain")
    return Response(re.sub(r"<[^>]+>", "", doc), mimetype="text/plain")


@app.route("/ping", methods=["GET", "POST"])
def ping():
    host = _param("host")
    proc = subprocess.run(f"ping -c 1 -W 1 -- {host}", shell=True, capture_output=True,
                          text=True, timeout=30)
    return Response(proc.stdout or proc.stderr or "no output", mimetype="text/plain")


@app.route("/hard/ping", methods=["GET", "POST"])
def hard_ping():
    host = _param("host")
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host):
        return Response("host rejected", status=400, mimetype="text/plain")
    try:
        return Response(socket.gethostbyname(host), mimetype="text/plain")
    except OSError:
        return Response("unresolved", mimetype="text/plain")


@app.route("/download", methods=["GET", "POST"])
def download():
    try:
        return Response(Path(os.path.join(BASE, _param("file"))).read_bytes(),
                        mimetype="text/plain")
    except OSError:
        return Response("not found", status=404, mimetype="text/plain")


@app.route("/hard/download", methods=["GET", "POST"])
def hard_download():
    path = (BASE / os.path.basename(_param("file"))).resolve()
    if not str(path).startswith(str(BASE.resolve()) + os.sep):
        return Response("path rejected", status=403, mimetype="text/plain")
    try:
        return Response(path.read_bytes(), mimetype="text/plain")
    except OSError:
        return Response("not found", status=404, mimetype="text/plain")


@app.route("/setcookie", methods=["GET", "POST"])
def set_cookie():
    r = _RawResponse("cookie set")
    r.extra_headers = [("X-Debug", _param("name"))]
    return r


@app.route("/hard/setcookie", methods=["GET", "POST"])
def hard_set_cookie():
    r = _RawResponse("cookie set")
    r.extra_headers = [("X-Debug", re.sub(r"[\r\n]", "", _param("name")))]
    return r


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
