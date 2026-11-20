"""Finding pipeline: dedup, evidence-bound state machine, provenance.

States: suspected -> observed -> validated -> reported -> remediated ->
        retested_fixed | retested_persists
        ruled_out (at any point, with reason)

Promotion to validated requires an independent replay verification.
Provenance is DERIVED from evidence bindings, never declared by the model.
"""
import json
import time

from .db import DB, new_id
from .evidence import EvidenceStore

STATE_ORDER = ["suspected", "observed", "validated", "reported", "remediated",
               "retested_fixed", "retested_persists", "ruled_out"]

# Promotion follows the lifecycle; no jumping straight to a confirmed state.
# A retest verdict is reachable only from a state that already reproduced.
ALLOWED_TRANSITIONS = {
    "suspected": {"observed", "ruled_out"},
    "observed": {"validated", "suspected", "ruled_out"},
    "validated": {"reported", "observed", "retested_persists", "retested_fixed", "ruled_out"},
    "reported": {"remediated", "retested_persists", "retested_fixed", "ruled_out"},
    "remediated": {"retested_fixed", "retested_persists", "reported", "ruled_out"},
    "retested_fixed": {"reported", "retested_persists", "ruled_out"},
    "retested_persists": {"reported", "remediated", "retested_fixed", "ruled_out"},
    "ruled_out": {"suspected", "observed"},
}


class FindingPipeline:
    def __init__(self, db: DB, evidence: EvidenceStore):
        self.db = db
        self.evidence = evidence

    def submit_candidate(self, engagement_id: str, cand: dict, intent_id: str | None = None) -> dict:
        """Ingest a check-produced candidate. Dedup by root-cause key."""
        dedup = cand.get("dedup_key") or f"{cand['title']}:{cand.get('endpoint','')}"
        existing = self.db.one(
            "SELECT * FROM findings WHERE engagement_id=? AND dedup_key=?",
            (engagement_id, dedup),
        )
        ev_ids = cand.get("evidence_ids", [])
        # derive provenance: every evidence id must resolve to a real ledger row
        derived_source = "unbound"
        if ev_ids:
            all_real = all(
                self.db.one("SELECT id FROM evidence WHERE id=? AND engagement_id=?", (e, engagement_id))
                for e in ev_ids
            )
            derived_source = "captured_exchange" if all_real else "unbound"
        if existing:
            merged = sorted(set(json.loads(existing["evidence_ids_json"])) | set(ev_ids))
            self.db.execute(
                "UPDATE findings SET evidence_ids_json=?, updated_at=? WHERE id=?",
                (json.dumps(merged), time.time(), existing["id"]),
            )
            self.db.emit(engagement_id, "finding_dedup",
                         {"finding_id": existing["id"], "dedup_key": dedup})
            return {"id": existing["id"], "deduped": True, "state": existing["state"]}
        fid = new_id("f")
        now = time.time()
        state = "observed" if derived_source == "captured_exchange" else "suspected"
        self.db.execute(
            "INSERT INTO findings(id, engagement_id, title, cwe, owasp, severity, cvss, confidence, "
            "asset_id, endpoint, state, description, impact, remediation, dedup_key, "
            "evidence_ids_json, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, engagement_id, cand["title"], cand.get("cwe"), cand.get("owasp"),
             cand.get("severity", "info"), cand.get("cvss"), cand.get("confidence", "low"),
             cand.get("asset_id"), cand.get("endpoint"), state, cand.get("description"),
             cand.get("impact"), cand.get("remediation"), dedup, json.dumps(ev_ids), now, now),
        )
        # store the proof request + quote as evidence so verification can replay
        proof_ev = self.evidence.put_json(engagement_id, {
            "proof_request": cand.get("proof_request"),
            "quote": cand.get("quote"), "quote_in": cand.get("quote_in", "body"),
            # the status the proof was captured at: a retest may only say "fixed"
            # from a response in the same class, or a block page reads as remediation
            "proof_status": self._proof_status(ev_ids),
            "derived_source": derived_source,
        }, "proof_spec")
        self.db.execute(
            "UPDATE findings SET evidence_ids_json=? WHERE id=?",
            (json.dumps(ev_ids + [proof_ev["id"]]), fid),
        )
        self.db.emit(engagement_id, "finding_new", {
            "finding_id": fid, "title": cand["title"], "severity": cand.get("severity"),
            "state": state, "endpoint": cand.get("endpoint"),
        })
        return {"id": fid, "deduped": False, "state": state}

    def record_observation(self, engagement_id: str, intent_id: str | None, kind: str,
                           summary: str, evidence_id: str | None = None, quote: str | None = None,
                           asset_id: str | None = None):
        derived = "unbound"
        if evidence_id:
            row = self.db.one("SELECT id FROM evidence WHERE id=? AND engagement_id=?",
                              (evidence_id, engagement_id))
            derived = "captured_exchange" if row else "unbound"
        oid = new_id("obs")
        self.db.execute(
            "INSERT INTO observations(id, engagement_id, intent_id, asset_id, kind, summary, "
            "evidence_id, quote, source_derived, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (oid, engagement_id, intent_id, asset_id, kind, summary, evidence_id, quote,
             derived, time.time()),
        )
        return oid

    def _proof_status(self, evidence_ids: list[str]) -> int | None:
        """Response status the bound evidence was captured at, if it was an exchange."""
        for eid in evidence_ids:
            row = self.db.one("SELECT status FROM exchanges WHERE evidence_id=?", (eid,))
            if row:
                return row["status"]
        return None

    def transition(self, finding_id: str, new_state: str, reason: str = ""):
        if new_state not in STATE_ORDER:
            raise ValueError(f"invalid state {new_state}")
        f = self.db.one("SELECT * FROM findings WHERE id=?", (finding_id,))
        if f is None:
            raise KeyError(finding_id)
        if new_state == f["state"]:
            return
        if new_state not in ALLOWED_TRANSITIONS.get(f["state"], set()):
            raise ValueError(f"illegal transition {f['state']} -> {new_state}")
        if new_state in ("validated", "reported"):
            v = self.db.one(
                "SELECT * FROM verifications WHERE finding_id=? AND verdict='reproduced' "
                "ORDER BY created_at DESC LIMIT 1", (finding_id,))
            if v is None:
                raise ValueError(f"cannot promote to {new_state} without a reproduced verification")
        if new_state in ("retested_fixed", "retested_persists"):
            verdict = "fixed" if new_state == "retested_fixed" else "persists"
            if self.db.one("SELECT id FROM retests WHERE finding_id=? AND verdict=?",
                           (finding_id, verdict)) is None:
                raise ValueError(f"no {verdict} retest recorded for this finding")
        self.db.execute("UPDATE findings SET state=?, updated_at=? WHERE id=?",
                        (new_state, time.time(), finding_id))
        self.db.emit(f["engagement_id"], "finding_state",
                     {"finding_id": finding_id, "state": new_state, "reason": reason})

    def list(self, engagement_id: str) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM findings WHERE engagement_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, created_at", (engagement_id,))
        for r in rows:
            r["evidence_ids"] = json.loads(r.pop("evidence_ids_json"))
        return rows
