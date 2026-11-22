"""ImpactLab: vulnerable endpoints plus hardened twins for the impact-proof layer.

/product?id=       string-concatenated SQL over in-memory sqlite  -> data access (CWE-89)
/orders/<id>       no identity check on the object                -> cross-identity data (CWE-639)
/ping?host=        shell=True over a query value                  -> command execution (CWE-78)
/ping?cmd=         runs whatever it is handed. Deliberately dangerous: the impact layer
                   must never reach it with anything but its read-only allowlist.
/hard/product      parameterised query                            -> no marker extraction
/hard/orders/<id>  owner header must match the order owner        -> 403 for another identity
/hard/ping         host must parse as an IP address              -> no command execution

Lab-only: binds 127.0.0.1, keeps everything in memory, never deploy this.
"""
import ipaddress
import os
import sqlite3
import subprocess
import threading

from flask import Flask, request

PORT = int(os.environ.get("LAB_PORT", "0"))
IMPACT_MARKER = "IMPACT-MARKER-7f3a9c"
ORDERS = {
    "1": {"order_id": "1", "owner": "attacker", "email": "attacker@example.com"},
    "2": {"order_id": "2", "owner": "victim", "email": "victim@example.com"},
}

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE products(id INTEGER PRIMARY KEY, payload TEXT)")
_db.execute("CREATE TABLE secrets(id INTEGER PRIMARY KEY, token TEXT)")
_db.execute("INSERT INTO products VALUES(1, 'Impact Widget $9.99')")
_db.execute("INSERT INTO secrets VALUES(1, ?)", (IMPACT_MARKER,))
_db.commit()
_lock = threading.Lock()

app = Flask(__name__)


@app.get("/product")
def product():
    # lab: the injection point, concatenated verbatim
    rows = _query(f"SELECT payload FROM products WHERE id = '{request.args.get('id', '1')}'")
    return "\n".join(rows) or "no product"


@app.get("/orders/<order_id>")
def order(order_id):
    # lab: no check that the caller owns this object
    found = ORDERS.get(order_id)
    if found is None:
        return "not found", 404
    return f"email={found['email']} order_id={found['order_id']}"


@app.get("/ping")
def ping():
    if "cmd" in request.args:
        command = request.args["cmd"]
    else:
        command = f"echo pinging {request.args.get('host', '127.0.0.1')}"
    try:
        done = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=3)
    except subprocess.TimeoutExpired:
        return "timeout", 504
    return (done.stdout or "") + (done.stderr or "")


def _query(sql: str) -> list[str]:
    with _lock:
        try:
            return [str(row[0]) for row in _db.execute(sql).fetchall()]
        except sqlite3.Error as exc:
            return [f"sql error: {exc}"]


@app.get("/hard/product")
def hard_product():
    with _lock:
        rows = [str(row[0]) for row in _db.execute(
            "SELECT payload FROM products WHERE id = ?", (request.args.get("id", "1"),))]
    return "\n".join(rows) or "no product"


@app.get("/hard/orders/<order_id>")
def hard_order(order_id):
    found = ORDERS.get(order_id)
    if found is None:
        return "not found", 404
    if request.headers.get("X-User") != found["owner"]:
        return "forbidden", 403
    return f"email={found['email']} order_id={found['order_id']}"


@app.get("/hard/ping")
def hard_ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "invalid host", 400
    return f"pinging {host}"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)
