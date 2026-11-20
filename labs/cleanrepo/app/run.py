"""Fixture service: same endpoints as vulnrepo, written safely."""
import ast
import json
import os
import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

SAFE_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    try:
        return str(ast.literal_eval(expr))
    except (ValueError, SyntaxError):
        return "error", 400


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not SAFE_HOST.fullmatch(host):
        return "error", 400
    out = subprocess.run(["ping", "-c", "1", host], shell=False,
                         capture_output=True, timeout=5)
    return out.stdout.decode(errors="replace")


@app.route("/load", methods=["POST"])
def load():
    return str(json.loads(request.data or b"{}"))


if __name__ == "__main__":
    app.run(host=os.environ.get("APP_HOST", "127.0.0.1"),
            port=int(os.environ.get("APP_PORT", "5000")), debug=False)
