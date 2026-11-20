"""Persistent cross-assessment intelligence: memory facts + attack-surface drift.

Discoveries, technologies, endpoints, and findings are keyed by stable target
identity (origin) so subsequent assessments reuse prior context and detect change.
Prevents stale findings from silently re-confirming: recall is provenance-tagged.
"""
import json
import time
from urllib.parse import urlparse

from .db import DB, new_id


def target_key(url_or_host: str) -> str:
    if "://" in url_or_host:
        p = urlparse(url_or_host)
        port = p.port or (443 if p.scheme == "https" else 80)
        return f"{p.scheme}://{p.hostname}:{port}"
    return url_or_host.lower()


def record_facts(db: DB, engagement_id: str):
    """Persist this engagement's discoveries as cross-run memory (provenance-tagged)."""
    now = time.time()
    assets = db.query("SELECT * FROM assets WHERE engagement_id=?", (engagement_id,))
    for a in assets:
        key = target_key(a["key"])
        kind = f"asset:{a['kind']}"
        val = json.loads(a["value_json"])
        val["key"] = a["key"]
        _upsert(db, key, kind, val, engagement_id, now)
    findings = db.query("SELECT * FROM findings WHERE engagement_id=?", (engagement_id,))
    for f in findings:
        key = target_key(f["endpoint"] or "")
        if not key:
            continue
        _upsert(db, key, f"finding:{f['dedup_key']}",
                {"title": f["title"], "cwe": f["cwe"], "severity": f["severity"],
                 "state": f["state"], "endpoint": f["endpoint"]}, engagement_id, now)


def _upsert(db, key, kind, value, eng, now):
    existing = db.one("SELECT * FROM memory_facts WHERE target_key=? AND kind=?", (key, kind))
    if existing:
        db.execute("UPDATE memory_facts SET value_json=?, source_engagement_id=?, last_seen=? WHERE id=?",
                   (json.dumps(value, default=str), eng, now, existing["id"]))
    else:
        db.execute(
            "INSERT INTO memory_facts(id, target_key, kind, value_json, source_engagement_id, confidence, first_seen, last_seen) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (new_id("mem"), key, kind, json.dumps(value, default=str), eng, 0.7, now, now))


def recall(db: DB, target: str) -> list[dict]:
    key = target_key(target)
    rows = db.query("SELECT * FROM memory_facts WHERE target_key=? ORDER BY last_seen DESC", (key,))
    for r in rows:
        r["value"] = json.loads(r["value_json"])
    return rows


def detect_drift(db: DB, engagement_id: str) -> list[dict]:
    """Compare current assets against prior memory at endpoint granularity."""
    now = time.time()
    assets = db.query("SELECT * FROM assets WHERE engagement_id=?", (engagement_id,))
    current = {(target_key(a["key"]), a["kind"], a["key"]) for a in assets}
    prior = db.query("SELECT * FROM memory_facts WHERE kind LIKE 'asset:%' AND source_engagement_id != ?",
                     (engagement_id,))
    prior_set = set()
    for p in prior:
        v = json.loads(p["value_json"])
        prior_set.add((p["target_key"], p["kind"].split(":", 1)[1], v.get("key", p["target_key"])))
    changes = []
    for tk, kind, key in current - prior_set:
        changes.append(_change(db, engagement_id, key, "added", None, {"kind": kind, "key": key}, now))
    for tk, kind, key in prior_set - current:
        changes.append(_change(db, engagement_id, key, "removed", {"kind": kind, "key": key}, None, now))
    return changes


def _change(db, eng, key, kind, old, new, now):
    cid = new_id("chg")
    db.execute(
        "INSERT INTO asset_changes(id, engagement_id, asset_key, change_kind, old_json, new_json, detected_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (cid, eng, key, kind, json.dumps(old), json.dumps(new), now))
    db.emit(eng, "asset_drift", {"asset_key": key, "change_kind": kind})
    return {"id": cid, "asset_key": key, "change_kind": kind}
