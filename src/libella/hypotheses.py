"""Structured security hypotheses: from application evidence to a planned, authorized test.

The intelligence model records what the application IS. This module decides what to
INVESTIGATE about it, and it is deliberately not an LLM confidence contest: a hypothesis is
materialized from a graph relationship, ranked by a documented deterministic score, checked
against its prerequisites, and only then proposed as a test. A candidate is not a
vulnerability, and a graph edge is not a finding.

Lifecycle, one row per hypothesis:

    candidate -> blocked (a prerequisite is missing, with the reason)
              -> proposed (prerequisites satisfied, a test is defined)
              -> running -> observed -> verified | refuted | inconclusive

Ranking factors, all deterministic and inspectable (see `rank`):

    evidence      provenance of the relationship that raised it (observed > spec > source
                  > inferred), because a served owner field is stronger than a bundle string
    relevance     how directly the class bears on broken access control or trust boundaries
    applicability +1 when every prerequisite is satisfied, -1 when one is missing
    novelty       -1 when an equivalent test already ran, so a finished question is not
                  re-proposed every planning round
    cost          a cheap test outranks an expensive one at equal value
    gain          tests that can CONFIRM (a contrast with a control) outrank tests that can
                  only observe

No factor is a model opinion. An agent may add a hypothesis and may argue it is
interesting, but the ordering a plan follows is computed here.
"""
import json
import time

from . import appintel
from .appintel import AppIntel
from .db import DB, new_id

# Classes this pipeline currently knows how to test, with the relevance weight that keeps
# ordering honest: a dangling reference in a bundle must never outrank a served owner field.
CLASS_WEIGHT = {"authorization": 5.0, "ssrf": 4.0, "injection": 3.5, "session": 3.0}
EVIDENCE_WEIGHT = {appintel.OBSERVED: 4.0, appintel.SPEC: 3.0, appintel.SOURCE: 1.5,
                   appintel.INFERRED: 1.0, appintel.HYPOTHESIZED: 0.0}

CANDIDATE, BLOCKED, PROPOSED, RUNNING, OBSERVED, VERIFIED, REFUTED, INCONCLUSIVE = (
    "candidate", "blocked", "proposed", "running", "observed", "verified", "refuted",
    "inconclusive")
TERMINAL = (VERIFIED, REFUTED, INCONCLUSIVE)

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_hypotheses(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
  class TEXT NOT NULL,                    -- authorization|ssrf|injection|session
  statement TEXT NOT NULL,                -- the security property under investigation
  property TEXT NOT NULL,                 -- expected secure behaviour, in one line
  endpoint TEXT, param TEXT, resource TEXT, owner_field TEXT,
  node_ids_json TEXT NOT NULL DEFAULT '[]',
  evidence_ids_json TEXT NOT NULL DEFAULT '[]',
  identity_required TEXT,                 -- what identity context the test needs
  prerequisites_json TEXT NOT NULL DEFAULT '{}',
  missing_json TEXT NOT NULL DEFAULT '[]',
  test_json TEXT NOT NULL DEFAULT '{}',   -- the proposed method, as data
  provenance TEXT NOT NULL,               -- strength of the relationship that raised it
  score REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'candidate',
  blocked_reason TEXT, intended_role TEXT, intent_id TEXT, finding_id TEXT,
  created_by TEXT, created_at REAL, updated_at REAL
);
CREATE INDEX IF NOT EXISTS idx_sechyp_eng ON security_hypotheses(engagement_id, status);
"""


def _now() -> float:
    return time.time()


class HypothesisStore:
    def __init__(self, db: DB, engagement_id: str):
        self.db = db
        self.eng = engagement_id
        with self.db._lock:
            self.db._conn.executescript(SCHEMA)
            self.db._conn.commit()

    # ------------------------------------------------------------------ writing
    def add(self, *, klass: str, statement: str, prop: str, provenance: str,
            endpoint: str | None = None, param: str | None = None,
            resource: str | None = None, owner_field: str | None = None,
            node_ids: list | None = None, evidence_ids: list | None = None,
            prerequisites: dict | None = None, missing: list | None = None,
            test: dict | None = None, identity_required: str | None = None,
            created_by: str = "planner") -> str:
        """Record one hypothesis. Idempotent per (class, endpoint, param, resource)."""
        if klass not in CLASS_WEIGHT:
            raise ValueError(f"unknown hypothesis class {klass!r}")
        if provenance not in EVIDENCE_WEIGHT:
            raise ValueError(f"unknown provenance {provenance!r}")
        existing = self.db.one(
            "SELECT id FROM security_hypotheses WHERE engagement_id=? AND class=? AND "
            "COALESCE(endpoint,'')=COALESCE(?,'') AND COALESCE(param,'')=COALESCE(?,'') AND "
            "COALESCE(resource,'')=COALESCE(?,'')",
            (self.eng, klass, endpoint, param, resource))
        now = _now()
        if existing:
            self.db.execute(
                "UPDATE security_hypotheses SET statement=?, property=?, prerequisites_json=?, "
                "missing_json=?, test_json=?, provenance=?, updated_at=? WHERE id=?",
                (statement, prop, json.dumps(prerequisites or {}), json.dumps(missing or []),
                 json.dumps(test or {}), provenance, now, existing["id"]))
            return existing["id"]
        hid = new_id("hy")
        self.db.execute(
            "INSERT INTO security_hypotheses(id, engagement_id, class, statement, property, "
            "endpoint, param, resource, owner_field, node_ids_json, evidence_ids_json, "
            "identity_required, prerequisites_json, missing_json, test_json, provenance, "
            "status, intended_role, created_by, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (hid, self.eng, klass, statement, prop, endpoint, param, resource, owner_field,
             json.dumps(node_ids or []), json.dumps(evidence_ids or []), identity_required,
             json.dumps(prerequisites or {}), json.dumps(missing or []),
             json.dumps(test or {}), provenance,
             BLOCKED if missing else PROPOSED, _role_for(klass), created_by, now, now))
        self.db.emit(self.eng, "hypothesis_created",
                     {"id": hid, "class": klass, "status": BLOCKED if missing else PROPOSED,
                      "missing": missing or []})
        return hid

    def set_status(self, hid: str, status: str, reason: str | None = None) -> None:
        allowed = (CANDIDATE, BLOCKED, PROPOSED, RUNNING, OBSERVED, VERIFIED, REFUTED,
                   INCONCLUSIVE)
        if status not in allowed:
            raise ValueError(f"unknown hypothesis status {status!r}")
        self.db.execute("UPDATE security_hypotheses SET status=?, blocked_reason=?, "
                        "updated_at=? WHERE id=? AND engagement_id=?",
                        (status, reason, _now(), hid, self.eng))

    def attach_intent(self, hid: str, intent_id: str) -> None:
        self.db.execute("UPDATE security_hypotheses SET intent_id=?, status=?, updated_at=? "
                        "WHERE id=? AND engagement_id=?",
                        (intent_id, RUNNING, _now(), hid, self.eng))

    def attach_finding(self, hid: str, finding_id: str) -> None:
        self.db.execute("UPDATE security_hypotheses SET finding_id=?, updated_at=? WHERE id=?",
                        (finding_id, _now(), hid))

    # ------------------------------------------------------------------ reading
    def all(self, status: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM security_hypotheses WHERE engagement_id=?", [self.eng]
        if status:
            sql += " AND status=?"
            args.append(status)
        return [self._shape(r) for r in self.db.query(sql + " ORDER BY score DESC, created_at",
                                                      tuple(args))]

    def get(self, hid: str) -> dict | None:
        row = self.db.one("SELECT * FROM security_hypotheses WHERE id=? AND engagement_id=?",
                          (hid, self.eng))
        return self._shape(row) if row else None

    # ------------------------------------------------------------------ ranking
    def rank(self) -> list[dict]:
        """Score every open hypothesis and return them worst-effort-first.

        The factors are exactly the ones documented in the module docstring, each with a
        stated weight, so a reader can recompute any number on this screen by hand.
        """
        tested = self._tested_signatures()
        out = []
        for h in self.all():
            if h["status"] in TERMINAL:
                continue
            evidence = EVIDENCE_WEIGHT.get(h["provenance"], 0.0)
            relevance = CLASS_WEIGHT.get(h["class"], 1.0)
            applicable = 0.0 if h["missing"] else 1.0
            novelty = -1.0 if _signature(h) in tested else 0.0
            cost = -1.0 if _expensive(h) else 0.0
            gain = 1.0 if _can_confirm(h) else 0.0
            score = round(evidence + relevance + applicable + novelty + cost + gain, 2)
            self.db.execute("UPDATE security_hypotheses SET score=? WHERE id=?", (score, h["id"]))
            out.append({**h, "score": score,
                        "factors": {"evidence": evidence, "relevance": relevance,
                                    "applicable": applicable, "novelty": novelty,
                                    "cost": cost, "gain": gain}})
        out.sort(key=lambda h: (-h["score"], h["created_at"]))
        return out

    def _tested_signatures(self) -> set:
        """Signatures of hypotheses already proposed, so a plan does not repeat itself."""
        sigs = set()
        for r in self.db.query(
                "SELECT class, endpoint, param, resource, status FROM security_hypotheses "
                "WHERE engagement_id=?", (self.eng,)):
            if r["status"] not in (CANDIDATE,):
                sigs.add(_signature(dict(r)))
        return sigs

    def plan(self, limit: int = 4) -> list[dict]:
        """The hypotheses worth testing now: ranked, applicable, and not already executed.

        A hypothesis sitting at `proposed` is precisely the work to do, so it is eligible.
        What must be excluded is one already RUNNING or already resolved, otherwise every
        planning round either repeats itself or silently plans nothing.
        """
        ranked = self.rank()
        busy = {r["id"] for r in self.db.query(
            "SELECT id FROM security_hypotheses WHERE engagement_id=? AND status='running'",
            (self.eng,))}
        picked = [h for h in ranked
                  if not h["missing"] and h["id"] not in busy
                  and h["status"] in (CANDIDATE, PROPOSED)][:limit]
        return picked

    def record_outcome(self, hid: str, verdict: str, detail: str = "",
                       finding_id: str | None = None) -> None:
        """After execution: the outcome the EVIDENCE supports, not what was hoped for."""
        status = {VERIFIED: VERIFIED, REFUTED: REFUTED}.get(verdict, INCONCLUSIVE)
        self.set_status(hid, status, detail or None)
        if finding_id:
            self.attach_finding(hid, finding_id)
        self.db.emit(self.eng, "hypothesis_outcome",
                     {"id": hid, "status": status, "detail": detail[:300],
                      "finding_id": finding_id})

    @staticmethod
    def _shape(row) -> dict:
        return {"id": row["id"], "class": row["class"], "statement": row["statement"],
                "property": row["property"], "endpoint": row["endpoint"],
                "param": row["param"], "resource": row["resource"],
                "owner_field": row["owner_field"], "status": row["status"],
                "provenance": row["provenance"], "score": row["score"],
                "missing": json.loads(row["missing_json"] or "[]"),
                "prerequisites": json.loads(row["prerequisites_json"] or "{}"),
                "test": json.loads(row["test_json"] or "{}"),
                "evidence_ids": json.loads(row["evidence_ids_json"] or "[]"),
                "node_ids": json.loads(row["node_ids_json"] or "[]"),
                "identity_required": row["identity_required"],
                "blocked_reason": row["blocked_reason"], "intent_id": row["intent_id"],
                "finding_id": row["finding_id"], "created_at": row["created_at"]}


def _signature(h: dict) -> tuple:
    return (h.get("class"), h.get("endpoint"), h.get("param"), h.get("resource"))


def _expensive(h: dict) -> bool:
    """A test that needs a second identity costs more than one request against one URL."""
    return bool(h.get("identity_required")) or h.get("class") == "session"


def _can_confirm(h: dict) -> bool:
    """Classes whose proposed test contrasts a control, so it can confirm as well as observe."""
    return h.get("class") in ("authorization", "ssrf", "injection")


def _role_for(klass: str) -> str:
    return {"authorization": "hypothesis_authz", "ssrf": "hypothesis_ssrf",
            "injection": "hypothesis_injection", "session": "hypothesis_session"}[klass]


# ---------------------------------------------------------------------- generation
def materialize(db: DB, engagement_id: str, auth: dict | None = None) -> list[str]:
    """Turn application-evidence relationships into structured hypotheses.

    Each mapping is a general RULE about a kind of evidence, not a fixture's endpoint name:

      resource + owner field, served by an endpoint   -> authorization hypothesis
      parameter whose value or name is a place        -> server-side fetch hypothesis
      parameter discovered on a query-bearing endpoint -> input-validation hypothesis
      authentication-shaped route with a session      -> session lifecycle hypothesis

    A rule whose prerequisites are unmet still records the hypothesis, as BLOCKED with the
    reason, because an investigation that silently drops a question looks like coverage.
    """
    intel = AppIntel(db, engagement_id)
    store = HypothesisStore(db, engagement_id)
    auth = auth or {}
    identities = auth.get("identities") or []
    ids: list[str] = []

    resources = intel.nodes(appintel.RESOURCE)
    owners = {}
    for res in resources:
        for e in intel.edges(res["id"]):
            if e["kind"] == "owned_by":
                owners[res["key"]] = e["other"]["label"]
    for res in resources:
        owner_field = owners.get(res["key"])
        if not owner_field:
            continue
        endpoint = _endpoint_for(intel, res["key"])
        missing = []
        if len(identities) < 2:
            missing.append("second_identity")
        if not endpoint:
            missing.append("no_object_endpoint")
        ids.append(store.add(
            klass="authorization",
            statement=(f"a record of '{res['key']}' may be read only by its owner "
                       f"('{owner_field}') or an administrator"),
            prop="object-level authorization is enforced on every read",
            provenance=appintel.OBSERVED if endpoint else appintel.INFERRED,
            endpoint=endpoint, resource=res["key"], owner_field=owner_field,
            node_ids=[res["id"]], evidence_ids=[res["data"].get("sample_id")] if res["data"] else [],
            prerequisites={"identities": len(identities), "owner_field": owner_field,
                           "object_endpoint": bool(endpoint)},
            missing=missing,
            identity_required="two authenticated identities" if len(identities) >= 2 else None,
            test={"method": "cross_identity_read", "resource": res["key"],
                  "expect": "the second identity must be refused"}))
    for param in intel.nodes(appintel.PARAM):
        if not param["data"].get("destination_shaped"):
            continue
        endpoint = _endpoint_for_param(intel, param["key"])
        missing = [] if endpoint else ["no_endpoint"]
        ids.append(store.add(
            klass="ssrf",
            statement=(f"parameter '{param['key']}' must not make the server fetch an "
                       f"address the caller chose"),
            prop="outbound destinations are allowlisted, not caller-controlled",
            provenance=param["provenance"], endpoint=endpoint, param=param["key"],
            node_ids=[param["id"]], missing=missing,
            prerequisites={"endpoint": bool(endpoint), "destination_param": True},
            test={"method": "controlled_fetch", "param": param["key"],
                  "expect": "a destination outside the allowlist must be refused"}))
        continue
    for param in intel.nodes(appintel.PARAM):
        if param["data"].get("destination_shaped"):
            continue
        endpoint = _endpoint_for_param(intel, param["key"])
        if not endpoint:
            continue
        ids.append(store.add(
            klass="injection",
            statement=(f"parameter '{param['key']}' must not alter the query the endpoint runs"),
            prop="user input is bound, not concatenated into the query",
            provenance=param["provenance"], endpoint=endpoint, param=param["key"],
            node_ids=[param["id"]],
            prerequisites={"endpoint": True, "query_param": True},
            test={"method": "boolean_differential", "param": param["key"],
                  "expect": "a boolean condition must not change the rows returned"}))
    for op in intel.nodes(appintel.SENSITIVE_OP):
        if not op["key"].startswith("auth:"):
            continue
        route = op["key"].split("auth:", 1)[1]
        missing = [] if identities else ["no_identity"]
        ids.append(store.add(
            klass="session",
            statement=f"the session issued by '{route}' must end at logout and expire",
            prop="session state changes predictably across its lifecycle",
            provenance=op["provenance"], endpoint=route, node_ids=[op["id"]],
            prerequisites={"identities": len(identities)}, missing=missing,
            identity_required="one authenticated identity" if identities else None,
            test={"method": "logout_replay", "route": route,
                  "expect": "the old credential must stop working"}))
    return ids


def _endpoint_for(intel: AppIntel, resource: str) -> str | None:
    """The observed endpoint that SERVES this resource, from the graph edge, not a guess."""
    for ep in intel.nodes(appintel.ENDPOINT):
        for e in intel.edges(ep["id"]):
            if e["kind"] == "serves" and e["other"]["id"] == resource:
                return ep["key"]
    return None


def _endpoint_for_param(intel: AppIntel, param: str) -> str | None:
    """The endpoint that ACCEPTS this parameter, from the graph edge."""
    for ep in intel.nodes(appintel.ENDPOINT):
        for e in intel.edges(ep["id"]):
            if e["kind"] == "accepts" and e["other"]["id"] == param:
                return ep["key"]
    return None
