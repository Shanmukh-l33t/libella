"""Remediation tracking and historical comparison across engagements.

Pure persistence helpers over findings/remediation columns + retests: the report
layer renders what is stored here, it never authors evidence.
"""
import json
import time
from datetime import date

from .db import DB
from .findings import STATE_ORDER, FindingPipeline
from .report import SEV_ORDER

# Remediation lifecycle, in board order. Derived from finding state + assignments.
BOARD = [("open", "Open"), ("in_progress", "In progress"), ("remediated", "Remediated"),
         ("fixed", "Fixed"), ("regressed", "Regressed"), ("closed", "Closed")]
# Operator-owned workflow state. Independent of verification: a retest (finding
# state) decides fixed/regressed, and it always wins over what the owner claims.
REMEDIATION_STATES = ("open", "in_progress", "resolved")
# "a fix was shipped" is an operator fact, but only for a finding that was confirmed.
REMEDIABLE_FROM = {"validated", "reported", "remediated", "retested_fixed",
                   "retested_persists"}

_LIMITS = {"owner": 120, "remediation_notes": 4000, "fix_commit": 200}
_FIELDS = ("id", "engagement_id", "title", "severity", "state", "endpoint", "dedup_key",
           "owner", "due_at", "remediation_state", "remediation_notes", "fix_commit",
           "remediated_at", "updated_at")


def _slim(row: dict) -> dict:
    return {k: row.get(k) for k in _FIELDS}


def _text(col: str, value):
    if not isinstance(value, str):
        raise ValueError(f"{col} must be a string")
    if len(value) > _LIMITS[col]:
        raise ValueError(f"{col} exceeds {_LIMITS[col]} characters")
    return value.strip()


def _due(value):
    """Empty string clears the due date; anything else must be an ISO calendar date."""
    if value == "":
        return None
    try:
        return date.fromisoformat(value).isoformat()
    except (TypeError, ValueError):
        raise ValueError("due_at must be an ISO date (YYYY-MM-DD)")


def board_status(f: dict) -> str:
    state = f.get("state")
    if state == "retested_fixed":
        return "fixed"
    if state == "retested_persists":
        return "regressed"
    if state == "ruled_out":
        return "closed"
    if f.get("remediation_state") == "resolved" or state == "remediated":
        return "remediated"
    if f.get("remediation_state") == "in_progress" or f.get("owner") or \
            f.get("remediation_notes") or f.get("fix_commit"):
        return "in_progress"
    return "open"


def set_remediation(db: DB, finding_id: str, notes: str | None = None, owner: str | None = None,
                    fix_commit: str | None = None, due_at: str | None = None,
                    remediation_state: str | None = None, state: str | None = None) -> dict:
    """Update remediation fields; entering 'resolved' stamps remediated_at.

    `remediation_state` is the owner's workflow (open/in_progress/resolved) and is
    independent of verification. `state` is the finding lifecycle: it still goes
    through FindingPipeline.transition, so verification gates cannot be bypassed.
    Raises KeyError for an unknown finding, ValueError for unknown states or dates.
    """
    f = db.one("SELECT * FROM findings WHERE id=?", (finding_id,))
    if f is None:
        raise KeyError(finding_id)
    if state is not None and state not in STATE_ORDER:
        raise ValueError(f"invalid state {state}")
    if remediation_state is not None and remediation_state not in REMEDIATION_STATES:
        raise ValueError(f"invalid remediation state {remediation_state}")
    now = time.time()
    updates = {}
    for col, val in (("remediation_notes", notes), ("owner", owner), ("fix_commit", fix_commit)):
        if val is not None:
            updates[col] = _text(col, val)
    if due_at is not None:
        updates["due_at"] = _due(due_at)
    if remediation_state is not None:
        updates["remediation_state"] = remediation_state
        if remediation_state == "resolved":
            updates.setdefault("remediated_at", f["remediated_at"] or now)
    if state is not None and state != f["state"]:
        if state != "remediated":
            # every other state is a *verdict*: the finding lifecycle decides
            FindingPipeline(db, None).transition(finding_id, state, reason="remediation update")
        elif f["state"] not in REMEDIABLE_FROM:
            raise ValueError(f"cannot mark a {f['state']} finding remediated; validate it first")
        else:
            updates["state"] = state
            updates.setdefault("remediated_at", f["remediated_at"] or now)
    before = {k: f.get(k) for k in updates}
    sets = ", ".join(f"{col}=?" for col in updates)
    db.execute(f"UPDATE findings SET updated_at=?{', ' + sets if sets else ''} WHERE id=?",
               (now, *updates.values(), finding_id))
    after = db.one("SELECT * FROM findings WHERE id=?", (finding_id,))
    assert after is not None  # row exists: we just read and updated it
    changes = {k: {"from": before[k], "to": after.get(k)}
               for k in updates if before[k] != after.get(k)}
    db.emit(f["engagement_id"], "finding_remediation",
            {"finding_id": finding_id, "owner": after.get("owner"),
             "due_at": after.get("due_at"),
             "remediation_state": after.get("remediation_state"),
             "fix_commit": after.get("fix_commit"),
             "state": state or f["state"], "changes": changes})
    return _slim(after)


def finding_activity(db: DB, finding_id: str, limit: int = 50) -> list[dict]:
    """This finding's audit trail, newest first (new/dedup/state/remediation events)."""
    f = db.one("SELECT engagement_id FROM findings WHERE id=?", (finding_id,))
    if f is None:
        raise KeyError(finding_id)
    limit = max(1, min(int(limit), 200))
    # shortcut: only the newest 400 engagement events are scanned; index the payload
    # (or add a finding_id column) if event feeds grow past that window.
    rows = db.query("SELECT seq, kind, payload_json, created_at FROM events "
                    "WHERE engagement_id=? ORDER BY seq DESC LIMIT 400",
                    (f["engagement_id"],))
    out = []
    for r in rows:
        payload = json.loads(r.pop("payload_json"))
        if payload.get("finding_id") != finding_id:
            continue
        out.append({**r, "payload": payload})
        if len(out) >= limit:
            break
    return out


def remediation_board(db: DB, engagement_id: str) -> dict:
    """Findings of one engagement grouped by remediation status."""
    if db.one("SELECT id FROM engagements WHERE id=?", (engagement_id,)) is None:
        raise KeyError(engagement_id)
    rows = db.query(
        "SELECT * FROM findings WHERE engagement_id=? ORDER BY CASE severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 "
        "ELSE 4 END, created_at", (engagement_id,))
    groups = {key: [] for key, _ in BOARD}
    for r in rows:
        groups[board_status(r)].append(_slim(r))
    return {"engagement_id": engagement_id,
            "columns": [{"status": key, "label": label, "findings": groups[key]}
                        for key, label in BOARD],
            "counts": {key: len(groups[key]) for key, _ in BOARD},
            "total": len(rows)}


def _index(rows: list[dict]) -> dict:
    return {(r.get("dedup_key") or r["id"]): r for r in rows}


def _severity_rank(sev) -> int:
    return SEV_ORDER.get(sev, 4)


def compare_engagements(db: DB, eng_a: str, eng_b: str) -> dict:
    """Diff two engagements' findings by dedup_key for historical comparison."""
    for eid in (eng_a, eng_b):
        if db.one("SELECT id FROM engagements WHERE id=?", (eid,)) is None:
            raise KeyError(eid)
    cols = ("id, engagement_id, title, severity, state, endpoint, dedup_key, owner, fix_commit")
    a_rows = db.query(f"SELECT {cols} FROM findings WHERE engagement_id=?", (eng_a,))
    b_rows = db.query(f"SELECT {cols} FROM findings WHERE engagement_id=?", (eng_b,))
    a, b = _index(a_rows), _index(b_rows)

    new, fixed, persisting, changed, absent = [], [], [], [], []
    for key, fb in b.items():
        fa = a.get(key)
        if fa is None:
            new.append({**fb, "dedup_key": key})
            continue
        if fb["state"] == "retested_fixed":
            fixed.append({**fb, "dedup_key": key, "previous_state": fa["state"],
                          "reason": "retested_fixed"})
        elif _severity_rank(fb["severity"]) != _severity_rank(fa["severity"]):
            changed.append({**fb, "dedup_key": key, "previous_severity": fa["severity"],
                            "direction": ("worse" if _severity_rank(fb["severity"])
                                          < _severity_rank(fa["severity"]) else "better")})
        else:
            persisting.append({**fb, "dedup_key": key, "previous_state": fa["state"]})
    for key, fa in a.items():
        if key not in b:
            absent.append({**fa, "dedup_key": key, "reason": "absent_in_b"})

    retests = {}
    for r in db.query("SELECT finding_id, verdict, detail, created_at FROM retests "
                      "WHERE finding_id IN (SELECT id FROM findings WHERE engagement_id=?) "
                      "ORDER BY created_at", (eng_b,)):
        retests.setdefault(r["finding_id"], []).append(
            {"verdict": r["verdict"], "detail": r["detail"], "created_at": r["created_at"]})
    for bucket in (new, fixed, persisting, changed, absent):
        for f in bucket:
            f["retests"] = retests.get(f["id"], [])

    name = {r["id"]: r["name"] for r in db.query(
        "SELECT id, name FROM engagements WHERE id IN (?,?)", (eng_a, eng_b))}
    return {
        "a": {"id": eng_a, "name": name.get(eng_a), "findings": len(a_rows)},
        "b": {"id": eng_b, "name": name.get(eng_b), "findings": len(b_rows)},
        "not_observed": absent, "new": new, "fixed": fixed, "persisting": persisting, "severity_changed": changed,
        "counts": {"new": len(new), "fixed": len(fixed), "persisting": len(persisting),
                   "severity_changed": len(changed), "not_observed": len(absent)},
        "retest_verdicts": {f["id"]: [r["verdict"] for r in f["retests"]]
                            for f in new + persisting + changed if f["retests"]},
    }
