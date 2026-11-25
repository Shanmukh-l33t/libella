"""Application intelligence: what the application IS, with provenance on every claim.

This is deliberately separate from `graph.py` (a read-time view of the investigation) and
from `assets` (what was probed). Here the unit is FUNCTIONALITY: a route, a parameter, a
resource, an owner field, a role, a workflow step, a trust boundary.

Every node and edge states HOW it is known, and the vocabulary is fixed so a reader cannot
mistake a guess for an observation:

    observed     a response, a rendered page or a captured request showed it
    spec         an authoritative document said it (OpenAPI, an operator declaration)
    source       authorised source or bundle analysis showed it
    inferred     derived from evidence by a rule the code can state
    hypothesized an agent proposed it and it is not yet supported

Nothing becomes `observed` because a model said so. `promote()` is the only way a claim
gains strength, and it requires an evidence id.

Retrieval is by RELEVANCE, not by dump: `context()` answers "what do I know about this
endpoint / resource / workflow" for the agent loop, so a prompt never contains the whole
traffic log.
"""
import json
import time

from .db import DB, new_id

OBSERVED, SPEC, SOURCE, INFERRED, HYPOTHESIZED = (
    "observed", "spec", "source", "inferred", "hypothesized")
# strongest first: a claim is only ever promoted along this order
STRENGTH = {HYPOTHESIZED: 1, INFERRED: 2, SOURCE: 3, SPEC: 4, OBSERVED: 5}

ROUTE, ENDPOINT, PARAM, FORM, RESOURCE, OWNER, ROLE, WORKFLOW, STEP = (
    "route", "endpoint", "param", "form", "resource", "owner", "role", "workflow", "step")
TRUST_BOUNDARY, SENSITIVE_OP, TECHNOLOGY = "trust_boundary", "sensitive_op", "technology"

KINDS = (ROUTE, ENDPOINT, PARAM, FORM, RESOURCE, OWNER, ROLE, WORKFLOW, STEP,
         TRUST_BOUNDARY, SENSITIVE_OP, TECHNOLOGY)


def _now() -> float:
    return time.time()


class AppIntel:
    """Durable, provenance-carrying model of one engagement's application."""

    def __init__(self, db: DB, engagement_id: str):
        self.db = db
        self.eng = engagement_id

    # ---------------------------------------------------------------- writing
    def add(self, kind: str, key: str, label: str = "", data: dict | None = None,
            provenance: str = OBSERVED, confidence: float = 1.0,
            evidence_id: str | None = None, source_ref: str | None = None) -> str:
        """Record one piece of application understanding. Idempotent by (kind, key).

        Re-seeing a node keeps the STRONGEST provenance it has ever had and refreshes
        `last_seen`; it never downgrades an observation because a later sighting was weaker.
        """
        if kind not in KINDS:
            raise ValueError(f"unknown application-intelligence kind {kind!r}")
        if provenance not in STRENGTH:
            raise ValueError(f"unknown provenance {provenance!r}")
        row = self.db.one(
            "SELECT * FROM app_nodes WHERE engagement_id=? AND kind=? AND key=?",
            (self.eng, kind, key))
        now = _now()
        if row:
            keep = provenance if STRENGTH[provenance] >= STRENGTH[row["provenance"]] \
                else row["provenance"]
            merged = {**json.loads(row["data_json"] or "{}"), **(data or {})}
            self.db.execute(
                "UPDATE app_nodes SET label=COALESCE(NULLIF(?,''), label), data_json=?, "
                "provenance=?, confidence=?, evidence_id=COALESCE(?, evidence_id), "
                "source_ref=COALESCE(?, source_ref), last_seen=? WHERE id=?",
                (label, json.dumps(merged), keep, max(confidence, row["confidence"]),
                 evidence_id, source_ref, now, row["id"]))
            return row["id"]
        nid = new_id("an")
        self.db.execute(
            "INSERT INTO app_nodes(id, engagement_id, kind, key, label, data_json, provenance, "
            "confidence, evidence_id, source_ref, first_seen, last_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (nid, self.eng, kind, key, label, json.dumps(data or {}), provenance,
             confidence, evidence_id, source_ref, now, now))
        self.db.emit(self.eng, "app_node", {"kind": kind, "key": key, "provenance": provenance})
        return nid

    def link(self, src: str, dst: str, kind: str, provenance: str = OBSERVED,
             confidence: float = 1.0, evidence_id: str | None = None) -> None:
        """Record a relationship, e.g. endpoint -serves-> resource -owned_by-> owner."""
        if provenance not in STRENGTH:
            raise ValueError(f"unknown provenance {provenance!r}")
        existing = self.db.one(
            "SELECT id, provenance, confidence FROM app_edges WHERE engagement_id=? AND "
            "src_id=? AND dst_id=? AND kind=?", (self.eng, src, dst, kind))
        if existing:
            keep = provenance if STRENGTH[provenance] >= STRENGTH[existing["provenance"]] \
                else existing["provenance"]
            self.db.execute(
                "UPDATE app_edges SET provenance=?, confidence=? WHERE id=?",
                (keep, max(confidence, existing["confidence"]), existing["id"]))
            return
        self.db.execute(
            "INSERT INTO app_edges(id, engagement_id, src_id, dst_id, kind, provenance, "
            "confidence, evidence_id, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (new_id("ae"), self.eng, src, dst, kind, provenance, confidence, evidence_id, _now()))

    def promote(self, kind: str, key: str, provenance: str, evidence_id: str) -> None:
        """Strengthen a claim, but only with evidence behind it.

        A promotion without an evidence id is refused: that is the whole point, because an
        agent saying "I am confident this route exists" is not evidence that it does.
        """
        if not evidence_id:
            raise ValueError("a provenance promotion requires an evidence id")
        row = self.db.one("SELECT id, provenance FROM app_nodes WHERE engagement_id=? AND "
                          "kind=? AND key=?", (self.eng, kind, key))
        if row is None:
            raise KeyError(f"{kind}:{key}")
        if STRENGTH[provenance] < STRENGTH[row["provenance"]]:
            raise ValueError(f"cannot demote {kind}:{key} with a promotion call")
        self.db.execute("UPDATE app_nodes SET provenance=?, evidence_id=?, last_seen=? "
                        "WHERE id=?", (provenance, evidence_id, _now(), row["id"]))

    # ---------------------------------------------------------------- reading
    def node(self, kind: str, key: str) -> dict | None:
        row = self.db.one("SELECT * FROM app_nodes WHERE engagement_id=? AND kind=? AND key=?",
                          (self.eng, kind, key))
        return self._shape(row) if row else None

    def nodes(self, kind: str | None = None, min_provenance: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM app_nodes WHERE engagement_id=?", [self.eng]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        rows = self.db.query(sql + " ORDER BY kind, key", tuple(args))
        out = [self._shape(r) for r in rows]
        if min_provenance:
            floor = STRENGTH[min_provenance]
            out = [n for n in out if STRENGTH[n["provenance"]] >= floor]
        return out

    def edges(self, node_id: str, direction: str = "out") -> list[dict]:
        col = "src_id" if direction == "out" else "dst_id"
        rows = self.db.query(
            f"SELECT e.*, n.kind AS other_kind, n.key AS other_key, n.label AS other_label "
            f"FROM app_edges e JOIN app_nodes n ON n.id = "
            f"CASE WHEN e.src_id=? THEN e.dst_id ELSE e.src_id END "
            f"WHERE e.engagement_id=? AND e.{col}=?", (node_id, self.eng, node_id))
        return [{"kind": r["kind"], "provenance": r["provenance"],
                 "other": {"id": r["other_key"], "kind": r["other_kind"],
                           "label": r["other_label"]}} for r in rows]

    def context(self, focus: str | None = None, limit: int = 40) -> dict:
        """Relevant application context for an agent, not a dump of everything.

        `focus` is an endpoint path, a resource key or a workflow name; the result is the
        neighbourhood of whatever matches, plus the counts that say what is NOT included so
        an agent knows when it is working from partial knowledge.
        """
        selected: list[dict] = []
        if focus:
            needle = focus.lower()
            for n in self.nodes():
                hay = f"{n['key']} {n['label']}".lower()
                if needle in hay:
                    selected.append(n)
                    selected.extend(
                        {"kind": e["other"]["kind"], "key": e["other"]["id"],
                         "label": e["other"]["label"], "via": e["kind"]}
                        for e in self.edges(n["id"]))
        if not selected:
            # no focus: the shape of the application, not its raw traffic
            for kind in (ROUTE, ENDPOINT, RESOURCE, OWNER, ROLE, WORKFLOW, SENSITIVE_OP):
                selected.extend(self.nodes(kind)[:limit // 7 or 1])
        uniq, seen = [], set()
        for n in selected:
            marker = (n["kind"], n["key"])
            if marker in seen:
                continue
            seen.add(marker)
            uniq.append(n)
        by_kind: dict[str, int] = {}
        for n in self.nodes():
            by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
        return {"focus": focus, "items": uniq[:limit], "totals": by_kind,
                "truncated": len(uniq) > limit}

    def summary(self) -> dict:
        """What the engine believes it understands, with provenance split."""
        nodes = self.nodes()
        by_kind: dict[str, dict[str, int]] = {}
        for n in nodes:
            slot = by_kind.setdefault(n["kind"], {})
            slot[n["provenance"]] = slot.get(n["provenance"], 0) + 1
        observed = [n for n in nodes if n["provenance"] in (OBSERVED, SPEC, SOURCE)]
        return {"total": len(nodes), "by_kind": by_kind,
                "supported": len(observed),
                "hypothesized": sum(1 for n in nodes if n["provenance"] == HYPOTHESIZED),
                "routes": len({n["key"] for n in nodes if n["kind"] in (ROUTE, ENDPOINT)}),
                "resources": len([n for n in nodes if n["kind"] == RESOURCE]),
                "workflows": len([n for n in nodes if n["kind"] == WORKFLOW])}

    def gaps(self) -> list[dict]:
        """What is still unknown, stated as questions with a reason, not as silence.

        An agent needs to know where its knowledge stops; otherwise it re-tests what it
        already knows or invents endpoints. Each entry names a gap kind and the evidence
        that would close it.
        """
        out = []
        nodes = self.nodes()
        if not any(n["kind"] == ROLE for n in nodes):
            out.append({"gap": "no_roles", "detail": "no account or role recorded, so "
                        "authorization questions cannot be framed",
                        "would_close_with": "log in as at least one identity and record the role"})
        endpoints = [n for n in nodes if n["kind"] == ENDPOINT]
        with_params = {e["key"] for e in self.edges_all() if e["kind"] == "accepts"}
        for ep in endpoints:
            if ep["key"] not in with_params and ep["provenance"] in (OBSERVED, SPEC):
                out.append({"gap": "unknown_parameters", "endpoint": ep["key"],
                            "detail": "endpoint observed but no input surface recorded",
                            "would_close_with": "a request with a parameter, or a schema"})
            if not any(e["kind"] == "serves" and e["src"] == ep["key"]
                       for e in self.edges_all()):
                out.append({"gap": "unknown_resource", "endpoint": ep["key"],
                            "detail": "no resource model for this endpoint",
                            "would_close_with": "a response showing the object and its owner"})
        if not any(n["kind"] == WORKFLOW for n in nodes):
            out.append({"gap": "no_workflows", "detail": "multi-step functionality is not "
                        "modelled, so state-dependent behaviour cannot be tested",
                        "would_close_with": "capture two requests whose second depends on the first"})
        return out

    def edges_all(self) -> list[dict]:
        rows = self.db.query(
            "SELECT e.kind, s.kind AS skind, s.key AS src, d.kind AS dkind, d.key AS dst "
            "FROM app_edges e JOIN app_nodes s ON s.id=e.src_id "
            "JOIN app_nodes d ON d.id=e.dst_id WHERE e.engagement_id=?", (self.eng,))
        return [dict(r) for r in rows]

    @staticmethod
    def _shape(row) -> dict:
        return {"id": row["id"], "kind": row["kind"], "key": row["key"],
                "label": row["label"], "provenance": row["provenance"],
                "confidence": row["confidence"], "data": json.loads(row["data_json"] or "{}"),
                "evidence_id": row["evidence_id"], "source_ref": row["source_ref"]}
