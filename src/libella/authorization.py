"""Expected-authorization model and oracle.

Identical responses for two identities prove nothing by themselves: the
requirement may be "only the owner". So the expectation is stated explicitly,
carries where it CAME FROM, and the oracle judges response CONTENT against it.

Access classes: public, authenticated, role:<name>, owner_only, tenant:<name>,
admin_only, denied, unknown.  Sources (strongest first): operator, analyst,
openapi_security, inferred.  An `inferred` rule is a hypothesis: the oracle may
say `violation` but marks it not confirmable, and the caller must not raise a
confirmed finding from it.

The model persists in its own table (created lazily; db.py is untouched).
"""
import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

PLACEHOLDER = re.compile(r"\{[^}]*\}|<[^>]*>|:[A-Za-z_]\w*")
SIMPLE = ("public", "authenticated", "owner_only", "admin_only", "denied", "unknown")
SOURCES = ("operator", "analyst", "openapi_security", "inferred")
PRIORITY = {s: i for i, s in enumerate(SOURCES)}  # lower wins on merge
VERDICTS = ("compliant", "violation", "inconclusive", "unknown_policy")
IDENTITY_KEYS = ("owner_id", "user_id", "uid", "owner", "username", "user", "email")
LOGIN_PAGE = re.compile(r"type=[\"']?password|<form[^>]*(login|signin|sign-in)|sign[ -]?in\b|log[ -]?in\b", re.I)
DENIED_TEXT = re.compile(r"access denied|forbidden|unauthori[sz]ed|not authori[sz]ed|permission denied", re.I)


def norm(path: str) -> str:
    return "/" + PLACEHOLDER.sub("*", path.strip("/"))


def valid_access(access: str) -> bool:
    return access in SIMPLE or bool(re.fullmatch(r"(role|tenant):[\w.-]+", access or ""))


@dataclass
class Rule:
    method: str
    path: str
    access: str
    source: str
    note: str = ""
    allow_roles: tuple = field(default_factory=tuple)  # extra roles that may pass an owner_only rule

    def __post_init__(self):
        self.method = (self.method or "GET").upper()
        if not valid_access(self.access):
            raise ValueError(f"unknown access class {self.access!r}")
        if self.source not in SOURCES:
            raise ValueError(f"unknown policy source {self.source!r}")
        self.allow_roles = tuple(r.lower() for r in self.allow_roles)

    @property
    def key(self) -> tuple:
        return (self.method, norm(self.path))


class PolicyModel:
    """Rules keyed by (method, normalised path); the strongest source wins."""

    def __init__(self, rules=()):
        self.rules: dict[tuple, Rule] = {}
        for r in rules:
            self.add(r)

    def add(self, rule: Rule) -> Rule:
        cur = self.rules.get(rule.key)
        if cur is None or PRIORITY[rule.source] <= PRIORITY[cur.source]:
            self.rules[rule.key] = rule
        return self.rules[rule.key]

    def get(self, method: str, path: str) -> Rule | None:
        return self.rules.get((method.upper(), norm(path)))

    def to_data(self) -> list[dict]:
        return [asdict(r) | {"allow_roles": list(r.allow_roles)} for r in self.rules.values()]

    # ---- persistence: own table, lazily created
    @staticmethod
    def _ensure(db):
        db.execute("CREATE TABLE IF NOT EXISTS authz_policy(engagement_id TEXT NOT NULL, method TEXT NOT NULL, "
                   "path TEXT NOT NULL, access TEXT NOT NULL, source TEXT NOT NULL, note TEXT, "
                   "allow_roles TEXT, created_at REAL, PRIMARY KEY(engagement_id, method, path))")

    def save(self, db, engagement_id: str):
        self._ensure(db)
        for r in self.rules.values():
            db.execute("INSERT OR REPLACE INTO authz_policy VALUES(?,?,?,?,?,?,?,?)",
                       (engagement_id, r.method, r.path, r.access, r.source, r.note,
                        json.dumps(list(r.allow_roles)), time.time()))

    @classmethod
    def load(cls, db, engagement_id: str) -> "PolicyModel":
        cls._ensure(db)
        return cls(Rule(x["method"], x["path"], x["access"], x["source"], x["note"] or "",
                        tuple(json.loads(x["allow_roles"] or "[]")))
                   for x in db.query("SELECT * FROM authz_policy WHERE engagement_id=?", (engagement_id,)))


def from_operator(policy, default_source: str = "operator") -> list[Rule]:
    """Rules from a list of {method?, path, access, source?, note?, allow_roles?} or a JSON file path."""
    if isinstance(policy, (str, Path)):
        policy = json.loads(Path(policy).read_text())
    return [Rule(p.get("method", "GET"), p["path"], p["access"], p.get("source", default_source),
                 p.get("note", ""), tuple(p.get("allow_roles") or ()))
            for p in (policy or []) if isinstance(p, dict) and p.get("path") and p.get("access")]


def from_openapi(spec: dict) -> list[Rule]:
    """`security: []` -> public; a non-empty requirement -> authenticated; absent -> no rule.

    shortcut: OpenAPI security cannot express ownership or roles, so this never yields
    owner_only/role rules; the operator must supply those.
    """
    out = []
    for route, ops in (spec.get("paths") or {}).items():
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                continue
            sec = op["security"] if "security" in op else spec.get("security")
            if sec is None:
                continue
            anonymous_ok = not sec or any(not req for req in sec)
            out.append(Rule(method, route, "public" if anonymous_ok else "authenticated", "openapi_security",
                            "OpenAPI security field"))
    return out


def infer(method: str, path: str) -> Rule | None:
    """Hypothesis only: an object-id GET is probably owner_only."""
    if method.upper() == "GET" and PLACEHOLDER.search(path):
        return Rule(method, path, "owner_only", "inferred", "object-id route: ownership assumed")
    return None


# ---- oracle ---------------------------------------------------------------

def body_kind(status, body: str) -> str:
    """data | login | error | empty: what a 2xx body actually is."""
    text = (body or "").strip()
    if not text:
        return "empty"
    try:
        obj = json.loads(text)
    except ValueError:
        return "login" if LOGIN_PAGE.search(text) else "error" if DENIED_TEXT.search(text) else "data"
    if isinstance(obj, dict) and ("error" in obj or "errors" in obj or obj.get("authenticated") is False):
        return "error"
    return "data" if obj not in ({}, [], None) else "empty"


def served_owner(body: str, me: dict, others: list[dict]) -> tuple[str, str | None]:
    """Whose record the body carries: ("self"|"other"|"unknown", other identity name).

    Compares the body's identity fields to the requester's. A bare `id` is never read as
    an owner (it is the object's id).
    """
    try:
        obj = json.loads(body or "")
    except ValueError:
        return "unknown", None
    rows = obj if isinstance(obj, list) else [obj]
    vals = {str(v).lower() for r in rows if isinstance(r, dict) for k, v in r.items()
            if k in IDENTITY_KEYS and isinstance(v, (str, int))}

    def marks(i):
        return {str(i.get(k)).lower() for k in ("username", "uid", "email") if i.get(k) is not None}
    if vals & marks(me):
        return "self", None
    for o in others:
        if vals & marks(o):
            return "other", o["username"]
    return "unknown", None


def access_of(obs: dict) -> str:
    """granted | denied | unusable, from content rather than the status line alone."""
    status = obs.get("status")
    if obs.get("mitigated") or status is None:
        return "unusable"  # a WAF/edge block or a failed request is not the application's answer
    if status in (401, 403):
        return "denied"
    if status == 404:
        return "unusable" if obs.get("relation") == "owner" else "denied"
    if 200 <= status < 300:
        kind = obs.get("body_kind") or body_kind(status, obs.get("body") or "")
        return "granted" if kind == "data" else "denied" if kind in ("login", "error") else "unusable"
    if 300 <= status < 400:
        return "denied" if re.search(r"login|signin|auth", str(obs.get("location", "")), re.I) else "unusable"
    return "unusable"


def _expected(rule: Rule, obs: dict) -> bool | None:
    """Should this requester be granted? None = cannot tell."""
    anon = obs.get("relation") == "anonymous"
    role = (obs.get("role") or "").lower()
    a = rule.access
    if a == "public":
        return True
    if a == "denied":
        return False
    if anon:
        return False
    if a == "authenticated":
        return True
    if a == "owner_only":
        return obs.get("relation") == "owner" or role in rule.allow_roles
    if a == "admin_only":
        return role == "admin"
    if a.startswith("role:"):
        return role == a.split(":", 1)[1].lower()
    if a.startswith("tenant:"):
        t = obs.get("tenant")
        return None if t is None else str(t).lower() == a.split(":", 1)[1].lower()
    return None


def evaluate(rule, observations: list[dict]) -> dict:
    """Judge observations against one expectation.

    Each observation: identity, relation (owner|other_user|other_tenant|anonymous), role,
    tenant, status, mitigated, body (or body_kind), served_owner, served_owner_of.
    Returns {verdict, confirmable, source, access, reasons, violations, controls}.
    `confirmable` is False for an inferred rule: review it, do not report it.
    """
    out = {"verdict": "inconclusive", "confirmable": False, "reasons": [], "violations": [],
           "controls": [], "violation_obs": [], "control_obs": [], "source": getattr(rule, "source", None), "access": getattr(rule, "access", None)}
    if rule is None or rule.access == "unknown":
        out["verdict"] = "unknown_policy"
        out["reasons"].append("no expected-authorization rule: cannot tell public from private")
        return out
    tested_denial = False
    for o in observations:
        acc, want = access_of(o), _expected(rule, o)
        if acc == "unusable":
            out["reasons"].append(f"{o['identity']}: unusable response (status {o.get('status')}"
                                  f"{', ' + str(o['mitigated']) if o.get('mitigated') else ''})")
            continue
        if want is None:
            out["reasons"].append(f"{o['identity']}: expectation undefined (no tenant known)")
            continue
        if want and acc == "granted":
            if o.get("served_owner") == "other" and rule.access == "owner_only":
                out["violations"].append(o["identity"])
                out["violation_obs"].append(o)
                out["reasons"].append(f"{o['identity']} was served {o.get('served_owner_of')}'s record")
            else:
                out["controls"].append(o["identity"])
                out["control_obs"].append(o)
        elif want and acc == "denied":
            out["reasons"].append(f"{o['identity']} is expected to pass but was refused (availability, not a violation)")
        elif not want and acc == "granted":
            if o.get("served_owner") == "self" and not o.get("relation") == "anonymous":
                tested_denial = True  # served its own record: the id was ignored, nothing leaked
            else:
                out["violations"].append(o["identity"])
                out["violation_obs"].append(o)
                out["reasons"].append(f"{o['identity']} ({o.get('relation')}) got data; {rule.access} expected a refusal")
        else:
            tested_denial = True
    if out["violations"]:
        out["verdict"] = "violation"
        out["confirmable"] = rule.source != "inferred" and bool(out["controls"])
        if rule.source == "inferred":
            out["reasons"].append("expectation is inferred: hypothesis only, needs review")
        elif not out["controls"]:
            out["reasons"].append("no permitted identity read the resource: no control comparison")
    elif rule.access == "public" and out["controls"] or tested_denial and out["controls"]:
        out["verdict"] = "compliant"
    else:
        out["reasons"].append("no permitted+refused pair observed")
    return out
