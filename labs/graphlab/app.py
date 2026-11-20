"""GraphLab: deterministic vulnerable/hardened GraphQL twin for Libella benchmarks.

LAB_MODE=vuln (default) seeds known GraphQL weaknesses; LAB_MODE=hardened
implements the same document surface with correct controls. Ground truth in
ground_truth.json. Lab-only: binds 127.0.0.1, fake credentials, no egress.

State is a module-level seeded SQLite database, so ids and content are stable
across requests (replayable proof requests). Every response is compact,
key-sorted JSON, so verbatim quotes captured as evidence stay byte-stable.

Schema (hand-rolled resolver; no GraphQL dependency):
  Query.user(id: Int): User
  Query.users(filter: String): [User]
  Query.adminStats: AdminStats
  Mutation.updateRole(userId: Int, role: String): User
  User: id, username, email, role, manager: User
"""
import json
import os
import re
import sqlite3

from flask import Flask, Response, request

MODE = os.environ.get("LAB_MODE", "vuln")
VULN = MODE == "vuln"
PORT = int(os.environ.get("LAB_PORT", "8821" if VULN else "8822"))
MAX_DEPTH = 5      # hardened: brace nesting cap
MAX_ALIASES = 10   # hardened: explicit alias cap

ALICE_PW = "SI_SECRET_PASSWORD_GRAPHLAB_A1"
BOB_PW = "SI_SECRET_PASSWORD_GRAPHLAB_B2"
ADMIN_PW = "SI_SECRET_PASSWORD_GRAPHLAB_C3"
CREDS = {"alice": ALICE_PW, "bob": BOB_PW, "admin": ADMIN_PW}
SCHEMA_TYPES = ("AdminStats", "Boolean", "Int", "Mutation", "Query", "String", "User")

app = Flask(__name__)
conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.row_factory = sqlite3.Row


def _seed(db):
    db.executescript(
        "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT,"
        " role TEXT, manager_id INTEGER);"
    )
    db.executemany("INSERT INTO users VALUES(?,?,?,?,?)", [
        (1, "alice", "alice@example.invalid", "user", 2),
        (2, "bob", "bob@example.invalid", "user", 3),
        (3, "admin", "admin@example.invalid", "admin", 3),  # admin manages himself
    ])
    db.commit()


_seed(conn)


class GQLError(Exception):
    """Query rejected; shaped into the GraphQL errors array."""


# ---------------------------------------------------------------- tiny GraphQL
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUM = re.compile(r"-?\d+(?:\.\d+)?")


def _tokens(src):
    """Tokenize the subset of GraphQL the lab accepts: names, literals, punct."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in " \t\r\n,":
            i += 1
        elif c == "#":
            while i < n and src[i] != "\n":
                i += 1
        elif c in "{}()[]:":
            out.append(c)
            i += 1
        elif c == '"':
            j, buf = i + 1, []
            while j < n and src[j] != '"':
                if src[j] == "\\":
                    if j + 1 >= n:
                        raise GQLError("unterminated string literal")
                    buf.append(src[j + 1])
                    j += 2
                else:
                    buf.append(src[j])
                    j += 1
            if j >= n:
                raise GQLError("unterminated string literal")
            out.append(("str", "".join(buf)))
            i = j + 1
        else:
            m = _NUM.match(src, i) or _NAME.match(src, i)
            if not m:
                raise GQLError(f"unexpected character {c!r}")
            tok = m.group(0)
            out.append(("num", tok) if _NUM.fullmatch(tok) else ("name", tok))
            i = m.end()
    return out


class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0
        self.depth = 0
        self.aliases = 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    @staticmethod
    def _is(tok, kind):
        return tok == kind or (isinstance(tok, tuple) and tok[0] == kind)

    def take(self, kind=None):
        tok = self.peek()
        if tok is None or (kind is not None and not self._is(tok, kind)):
            raise GQLError(f"unexpected token {tok!r}")
        self.i += 1
        return tok

    def _skip(self, open_tok, close_tok):
        self.take(open_tok)
        level = 1
        while level:
            tok = self.take()
            if tok == open_tok:
                level += 1
            elif tok == close_tok:
                level -= 1

    def document(self):
        tok = self.peek()
        if isinstance(tok, tuple) and tok[1] in ("query", "mutation", "subscription"):
            op = self.take("name")[1]
            if isinstance(self.peek(), tuple) and self.peek()[0] == "name":
                self.i += 1  # operation name
            if self.peek() == "(":
                self._skip("(", ")")  # variable definitions unsupported (no substitution)
            if op == "subscription":
                raise GQLError("subscriptions are not supported")
            return op, self.selection_set(1)
        return "query", self.selection_set(1)

    def selection_set(self, level):
        self.depth = max(self.depth, level)
        self.take("{")
        fields = []
        while self.peek() != "}":
            if self.peek() is None:
                raise GQLError("unterminated selection set")
            fields.append(self.field(level))
        self.take("}")
        return fields

    def field(self, level):
        name = self.take("name")[1]
        alias = None
        if self.peek() == ":":
            self.take(":")
            alias, name = name, self.take("name")[1]
            self.aliases += 1
        args = self.arguments() if self.peek() == "(" else {}
        sub = self.selection_set(level + 1) if self.peek() == "{" else []
        return {"alias": alias or name, "name": name, "args": args, "fields": sub}

    def arguments(self):
        self.take("(")
        args = {}
        while self.peek() != ")":
            if self.peek() is None:
                raise GQLError("unterminated argument list")
            key = self.take("name")[1]
            self.take(":")
            args[key] = self.value()
        self.take(")")
        return args

    def value(self):
        tok = self.take()
        if tok == "[":
            vals = []
            while self.peek() != "]":
                vals.append(self.value())
            self.take("]")
            return vals
        if tok == "{":
            obj = {}
            while self.peek() != "}":
                k = self.take("name")[1]
                self.take(":")
                obj[k] = self.value()
            self.take("}")
            return obj
        if not isinstance(tok, tuple):
            raise GQLError(f"unexpected token {tok!r} in argument value")
        if tok[0] == "num":
            return float(tok[1]) if "." in tok[1] else int(tok[1])
        if tok[0] == "str":
            return tok[1]
        return {"true": True, "false": False, "null": None}.get(tok[1], tok[1])


def parse(src):
    """-> (operation, fields, brace depth, explicit alias count)."""
    p = _Parser(_tokens(src))
    op, fields = p.document()
    if p.peek() is not None:
        raise GQLError("trailing tokens after the operation")
    return op, fields, p.depth, p.aliases


# ------------------------------------------------------------------- resolvers
def _fetch(uid):
    if isinstance(uid, bool) or not isinstance(uid, (int, str)):
        return None
    return conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def _project_user(row, sub, ident):
    if row is None:
        return None
    if not sub:  # permissive: a leaf user field returns the whole record
        return {"id": row["id"], "username": row["username"],
                "email": row["email"], "role": row["role"]}
    return {f["alias"]: _user_field(row, f["name"], f["fields"], ident) for f in sub}


def _user_field(row, name, sub, ident):
    if name == "__typename":
        return "User"
    if name == "manager":
        return _project_user(_fetch(row["manager_id"]), sub, ident)
    if name in ("id", "username", "email", "role"):
        return row[name]
    raise GQLError(f"unknown field '{name}' on User")


def _query_users(flt):
    if flt is None:
        return conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    if VULN:  # seeded injection: caller text concatenated into the SQL
        sql = "SELECT * FROM users WHERE username LIKE '%" + str(flt) + "%' ORDER BY id"
        return conn.execute(sql).fetchall()
    return conn.execute("SELECT * FROM users WHERE username LIKE ? ORDER BY id",
                        (f"%{flt}%",)).fetchall()


def _query_field(name, args, sub, ident):
    if name == "__schema":
        if not VULN:
            raise GQLError("introspection is disabled")
        return {"types": [{"name": n} for n in SCHEMA_TYPES]}
    if name == "user":
        uid = args.get("id")
        if not VULN and uid != ident["id"] and ident["role"] != "admin":
            raise GQLError(f"forbidden: user {uid} is not readable by {ident['username']}")
        return _project_user(_fetch(uid), sub, ident)
    if name == "users":
        rows = _query_users(args.get("filter"))
        if not VULN and ident["role"] != "admin":
            rows = [r for r in rows if r["id"] == ident["id"]]
        return [_project_user(r, sub, ident) for r in rows]
    if name == "adminStats":
        if not VULN and ident["role"] != "admin":
            raise GQLError(f"forbidden: adminStats requires admin, caller is {ident['username']}")
        return {"totalUsers": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                "totalRoles": conn.execute("SELECT COUNT(DISTINCT role) FROM users").fetchone()[0]}
    raise GQLError(f"unknown field '{name}' on Query")


def _mutation_field(name, args, sub, ident):
    if name != "updateRole":
        raise GQLError(f"unknown field '{name}' on Mutation")
    uid, role = args.get("userId"), args.get("role")
    if not VULN:
        if ident["role"] != "admin":
            raise GQLError(f"forbidden: updateRole requires admin, caller is {ident['username']}")
        if role not in ("user", "admin"):
            raise GQLError(f"invalid role {role!r}")
    conn.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    conn.commit()
    return _project_user(_fetch(uid), sub, ident)


def execute(fields, ident, op):
    if op == "mutation":
        return {f["alias"]: _mutation_field(f["name"], f["args"], f["fields"], ident)
                for f in fields}
    return {f["alias"]: _query_field(f["name"], f["args"], f["fields"], ident) for f in fields}


# -------------------------------------------------------------------- HTTP API
def _json(obj, status=200):
    return Response(json.dumps(obj, sort_keys=True, separators=(",", ":")),
                    status=status, mimetype="application/json")


def _identity():
    username = request.cookies.get("sid")
    if username not in CREDS:
        return None
    row = conn.execute("SELECT id, username, role FROM users WHERE username=?",
                       (username,)).fetchone()
    return dict(row) if row else None


def _run_one(payload, ident):
    query = payload.get("query") if isinstance(payload, dict) else None
    if not isinstance(query, str) or not query.strip():
        return {"errors": [{"message": "query must be a non-empty string"}]}
    try:
        op, fields, depth, aliases = parse(query)
        if not VULN:
            if depth > MAX_DEPTH:
                return {"errors": [{"message": f"query depth {depth} exceeds limit {MAX_DEPTH}"}]}
            if aliases > MAX_ALIASES:
                return {"errors": [{"message":
                                    f"{aliases} aliases exceed limit {MAX_ALIASES}"}]}
        return {"data": execute(fields, ident, op)}
    except GQLError as e:
        return {"errors": [{"message": str(e)}]}
    except sqlite3.Error as e:  # error-based SQL injection surface (vuln mode)
        return {"errors": [{"message": f"sqlite3.{type(e).__name__}: {e}"}]}


@app.get("/health")
def health():
    return _json({"mode": MODE, "status": "ok"})


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    if CREDS.get(username) != data.get("password"):  # lab-only fake credentials
        return _json({"authenticated": False}, 401)
    row = conn.execute("SELECT id, username, role FROM users WHERE username=?",
                       (username,)).fetchone()
    resp = _json({"authenticated": True, "id": row["id"], "role": row["role"],
                  "username": row["username"]})
    resp.set_cookie("sid", username, httponly=True, samesite="Lax")
    return resp


@app.post("/graphql")
def graphql():
    ident = _identity()
    if ident is None:
        return _json({"errors": [{"message": "authentication required"}]}, 401)
    payload = request.get_json(silent=True)
    if isinstance(payload, list):
        if not VULN:
            return _json({"errors": [{"message": "batched requests are disabled"}]}, 400)
        return _json([_run_one(p, ident) for p in payload])
    if not isinstance(payload, dict):
        return _json({"errors": [{"message": "expected a JSON object with a query"}]}, 400)
    return _json(_run_one(payload, ident))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, threaded=True)
