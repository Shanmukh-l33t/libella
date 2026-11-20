"""Remediation tracking and historical comparison across engagements.

Pure persistence helpers over findings/remediation columns + retests: the report
layer renders what is stored here, it never authors evidence.
"""
import time

from .db import DB
from .findings import STATE_ORDER, FindingPipeline
from .report import SEV_ORDER

# Remediation lifecycle, in board order. Derived from finding state + assignments.
BOARD = [("open", "Open"), ("in_progress", "In progress"), ("remediated", "Remediated"),
         ("fixed", "Fixed"), ("regressed", "Regressed"), ("closed", "Closed")]
# "a fix was shipped" is an operator fact, but only for a finding that was confirmed.
REMEDIABLE_FROM = {"validated", "reported", "remediated", "retested_fixed",
                   "retested_persists"}

_FIELDS = ("id", "engagement_id", "title", "severity", "state", "endpoint", "dedup_key",
           "owner", "remediation_notes", "fix_commit", "remediated_at", "updated_at")


def _slim(row: dict) -> dict:
    return {k: row.get(k) for k in _FIELDS}


def board_status(f: dict) -> str:
    state = f.get("state")
    if state == "retested_fixed":
        return "fixed"
    if state == "retested_persists":
        return "regressed"
    if state == "remediated":
        return "remediated"
    if state == "ruled_out":
        return "closed"
    if f.get("owner") or f.get("remediation_notes") or f.get("fix_commit"):
        return "in_progress"
    return "open"


def set_remediation(db: DB, finding_id: str, notes: str | None = None, owner: str | None = None,
                    fix_commit: str | None = None, state: str | None = None) -> dict:
    """Update remediation fields; entering 'remediated' stamps remediated_at.

    Raises KeyError for an unknown finding, ValueError for an unknown state or an
    illegal transition. State goes through FindingPipeline.transition, so the
    lifecycle (and the reproduced-verification requirement) is not bypassable
    from this surface: remediation tracks findings, it does not confirm them.
    """
    f = db.one("SELECT * FROM findings WHERE id=?", (finding_id,))
    if f is None:
        raise KeyError(finding_id)
    if state is not None and state not in STATE_ORDER:
        raise ValueError(f"invalid state {state}")
    now = time.time()
    sets, params = ["updated_at=?"], [now]
    for col, val in (("remediation_notes", notes), ("owner", owner), ("fix_commit", fix_commit)):
        if val is not None:
            sets.append(f"{col}=?")
            params.append(val)
    if state is not None and state != f["state"]:
        if state != "remediated":
            # every other state is a *verdict*: the finding lifecycle decides
            FindingPipeline(db, None).transition(finding_id, state, reason="remediation update")
        elif f["state"] not in REMEDIABLE_FROM:
            raise ValueError(f"cannot mark a {f['state']} finding remediated; validate it first")
        else:
            sets.append("state=?")
            params.append(state)
            sets.append("remediated_at=COALESCE(remediated_at, ?)")
            params.append(now)
    params.append(finding_id)
    db.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id=?", tuple(params))
    db.emit(f["engagement_id"], "finding_remediation",
            {"finding_id": finding_id, "owner": owner, "fix_commit": fix_commit,
             "state": state or f["state"]})
    return _slim(db.one("SELECT * FROM findings WHERE id=?", (finding_id,)))


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

    new, fixed, persisting, changed = [], [], [], []
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
            fixed.append({**fa, "dedup_key": key, "reason": "absent_in_b"})

    retests = {}
    for r in db.query("SELECT finding_id, verdict, detail, created_at FROM retests "
                      "WHERE finding_id IN (SELECT id FROM findings WHERE engagement_id=?) "
                      "ORDER BY created_at", (eng_b,)):
        retests.setdefault(r["finding_id"], []).append(
            {"verdict": r["verdict"], "detail": r["detail"], "created_at": r["created_at"]})
    for bucket in (new, fixed, persisting, changed):
        for f in bucket:
            f["retests"] = retests.get(f["id"], [])

    name = {r["id"]: r["name"] for r in db.query(
        "SELECT id, name FROM engagements WHERE id IN (?,?)", (eng_a, eng_b))}
    return {
        "a": {"id": eng_a, "name": name.get(eng_a), "findings": len(a_rows)},
        "b": {"id": eng_b, "name": name.get(eng_b), "findings": len(b_rows)},
        "new": new, "fixed": fixed, "persisting": persisting, "severity_changed": changed,
        "counts": {"new": len(new), "fixed": len(fixed), "persisting": len(persisting),
                   "severity_changed": len(changed)},
        "retest_verdicts": {f["id"]: [r["verdict"] for r in f["retests"]]
                            for f in new + persisting + changed if f["retests"]},
    }
