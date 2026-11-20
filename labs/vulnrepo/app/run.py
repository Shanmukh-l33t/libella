"""Fixture service: deliberately vulnerable handlers (one per seeded class)."""
import pickle
import subprocess

from flask import Flask, request

from .creds import AWS_ACCESS_KEY_ID
from .signing import SIGNING_KEY_PEM

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out.decode(errors="replace")


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


@app.route("/key")
def key():
    return {"id": AWS_ACCESS_KEY_ID, "pem_len": len(SIGNING_KEY_PEM)}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
