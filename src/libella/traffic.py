"""HTTP traffic intelligence: search captured exchanges, correlate them,
and replay a captured request under full scope enforcement.

Search reads the exchanges table plus the evidence blob of each candidate (the
response body only lives there). Replay never invents a request: it re-issues
the request recorded in the original exchange's evidence, drops hop-by-hop
headers, and refuses anything the scope engine rejects before egress.
"""
import difflib
import json
from pathlib import Path
from urllib.parse import urlparse

from .db import DB
from .evidence import EvidenceStore
from .scope import Scope
from .tools.http_probe import HttpProbe

SCAN_CAP = 1000  # exchanges inspected for body_text: each hit costs one blob read
# shortcut: the filtered exchange set is paged in Python, not SQL; upgrade to
# SQL-side LIMIT/OFFSET when one engagement exceeds tens of thousands of exchanges.
BLOB_CAP = 256 * 1024  # bytes of a blob decoded for text matching
DIFF_CAP = 8192  # chars per body compared for similarity
MAX_PAGE = 200
# Recomputed or connection-specific; replaying a captured value breaks the request.
HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "content-length",
              "upgrade", "proxy-connection", "te", "trailer"}


def _store(db: DB, evidence: EvidenceStore | None) -> EvidenceStore:
    return evidence or EvidenceStore(db, Path(db.path).parent / "evidence")


def _like(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped[:200]}%"


def _endpoint(url: str | None) -> str:
    """Stable endpoint key: scheme://host[:port]/path, query and fragment dropped."""
    p = urlparse(url or "")
    if not p.netloc:
        return (url or "").split("?")[0]
    return p._replace(query="", fragment="").geturl()


def _under(key: str, base: str) -> bool:
    """True when key is base or a path below it (not a bare string prefix)."""
    return bool(base) and (key == base or (key.startswith(base)
                                           and key[len(base):].startswith("/")))


def _item(row: dict) -> dict:
    return {k: row.get(k) for k in ("id", "method", "url", "status", "tool", "duration_ms",
                                    "peer_ip", "evidence_id", "replay_of", "tags_json",
                                    "created_at", "match") if k in row}


def _match_blob(store: EvidenceStore, row: dict, needle: str) -> str | None:
    """Snippet around needle in the exchange's evidence blob, or None."""
    if not row.get("evidence_id"):
        return None
    try:
        text = store.read(row["evidence_id"])[:BLOB_CAP].decode(errors="replace")
    except (KeyError, OSError, ValueError):
        return None  # missing or tampered evidence is never a search hit
    i = text.lower().find(needle)
    if i < 0:
        return None
    return text[max(0, i - 60):i + len(needle) + 60]


def search_exchanges(db: DB, engagement_id: str, filters: dict | None = None,
                     page: int = 1, page_size: int = 50,
                     evidence: EvidenceStore | None = None) -> dict:
    """Filtered, paginated exchange search. body_text scans evidence blobs, bounded."""
    f = filters or {}
    where, params = ["engagement_id=?"], [engagement_id]
    if f.get("url_substring"):
        where.append("url LIKE ? ESCAPE '\\'")
        params.append(_like(f["url_substring"]))
    if f.get("method"):
        where.append("method=?")
        params.append(str(f["method"]).upper())
    if f.get("status") not in (None, ""):
        where.append("status=?")
        params.append(int(f["status"]))
    if f.get("tool"):
        where.append("tool=?")
        params.append(f["tool"])
    rows = db.query("SELECT * FROM exchanges WHERE " + " AND ".join(where)
                    + " ORDER BY created_at DESC, rowid DESC", tuple(params))
    scanned = len(rows)
    meta = {"scanned": scanned, "scan_truncated": False}
    needle = str(f.get("body_text") or "").strip().lower()
    if needle:
        store = _store(db, evidence)
        kept = []
        for r in rows[:SCAN_CAP]:
            if m := _match_blob(store, r, needle):
                r["match"] = m
                kept.append(r)
        rows = kept
        meta["scan_truncated"] = scanned > SCAN_CAP
    page, page_size = max(1, int(page)), min(max(1, int(page_size)), MAX_PAGE)
    total = len(rows)
    start = (page - 1) * page_size
    return {"items": [_item(r) for r in rows[start:start + page_size]], "page": page,
            "page_size": page_size, "total": total,
            "pages": (total + page_size - 1) // page_size, **meta}


def correlate(db: DB, engagement_id: str) -> dict:
    """Group exchanges by endpoint, link the findings and observations bound to them."""
    rows = db.query("SELECT * FROM exchanges WHERE engagement_id=? ORDER BY created_at",
                    (engagement_id,))
    groups: dict[str, dict] = {}
    for r in rows:
        key = _endpoint(r["url"])
        g = groups.setdefault(key, {"endpoint": key, "requests": 0, "methods": [], "statuses": {},
                                    "tools": [], "exchange_ids": [], "evidence_ids": [],
                                    "first_seen": r["created_at"], "last_seen": r["created_at"]})
        g["requests"] += 1
        g["methods"] = sorted({*g["methods"], r["method"] or ""})
        g["statuses"][str(r["status"])] = g["statuses"].get(str(r["status"]), 0) + 1
        g["tools"] = sorted({*g["tools"], r["tool"] or ""})
        g["exchange_ids"] = g["exchange_ids"][-49:] + [r["id"]]
        if r["evidence_id"]:
            g["evidence_ids"] = g["evidence_ids"][-49:] + [r["evidence_id"]]
        g["last_seen"] = r["created_at"]

    findings = db.query("SELECT id, title, severity, state, endpoint FROM findings "
                        "WHERE engagement_id=?", (engagement_id,))
    obs = db.query("SELECT id, kind, summary, evidence_id FROM observations "
                   "WHERE engagement_id=? AND evidence_id IS NOT NULL", (engagement_id,))
    obs_by_evidence: dict[str, list] = {}
    for o in obs:
        obs_by_evidence.setdefault(o["evidence_id"], []).append(
            {"id": o["id"], "kind": o["kind"], "summary": o["summary"]})
    out = []
    for key, g in groups.items():
        linked = [f for f in findings if _under(key, _endpoint(f["endpoint"]))]
        seen, observations = set(), []
        for ev in g["evidence_ids"]:
            for o in obs_by_evidence.get(ev, []):
                if o["id"] not in seen:
                    seen.add(o["id"])
                    observations.append(o)
        out.append({**g, "findings": linked, "observations": observations})
    out.sort(key=lambda g: -g["requests"])
    return {"groups": out, "endpoints": len(out), "exchanges": len(rows)}


def _audit(db: DB, engagement_id: str, exchange_id: str, payload: dict, kind: str) -> None:
    db.emit(engagement_id, kind, {"exchange_id": exchange_id, **payload})


def _diff(blob: dict | None, replay: dict) -> dict:
    original = (blob or {}).get("response") or {}
    old = original.get("body") or ""
    new = replay.get("body") or ""
    similar = 1.0 if old == new else round(difflib.SequenceMatcher(
        None, old[:DIFF_CAP], new[:DIFF_CAP]).ratio(), 3)
    return {"status_original": original.get("status"), "status_replay": replay.get("status"),
            "status_changed": original.get("status") != replay.get("status"),
            "length_original": len(old), "length_replay": len(new),
            "length_delta": len(new) - len(old), "body_identical": old == new,
            "similarity": similar,
            "truncated_compare": len(old) > DIFF_CAP or len(new) > DIFF_CAP}


def replay(db: DB, evidence: EvidenceStore, probe: HttpProbe, scope: Scope,
           engagement_id: str, exchange_id: str, overrides: dict | None = None) -> dict:
    """Re-issue the captured request (optionally overridden), under scope, and diff it.

    Refuses: unknown exchange, unreadable/tampered evidence, malformed overrides,
    out-of-scope url. Every refusal and every replay is audited.
    """
    row = db.one("SELECT * FROM exchanges WHERE id=? AND engagement_id=?",
                 (exchange_id, engagement_id))
    if row is None:
        return {"ok": False, "error": "exchange not found in engagement"}
    try:
        blob = evidence.read_json(row["evidence_id"]) if row["evidence_id"] else None
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as e:
        return {"ok": False, "error": f"captured request unavailable: {e}"}
    req = (blob or {}).get("request") or {}
    url = req.get("url") or row["url"]
    if not isinstance(url, str) or not url:
        return {"ok": False, "error": "captured request has no url"}
    method = str(req.get("method") or row["method"] or "GET").upper()
    # Headers come from the sealed column (the evidence blob keeps them redacted);
    # pre-sealing captures have only the blob, so fall back to it.
    try:
        recorded = json.loads(row.get("req_headers_json") or "null")
    except json.JSONDecodeError:
        recorded = None
    if not isinstance(recorded, dict):
        recorded = None
    headers = {k: v for k, v in (recorded or req.get("headers") or {}).items()
               if k.lower() not in HOP_BY_HOP}
    body = req.get("body") or None
    ov = overrides or {}
    if not isinstance(ov, dict):
        return {"ok": False, "error": "overrides must be an object"}
    hov = ov.get("headers") or {}
    if not isinstance(hov, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in hov.items()):
        return {"ok": False, "error": "override headers must be a string map"}
    headers = {**headers, **hov}
    if "body" in ov:
        body = ov["body"] if isinstance(ov["body"], (str, type(None))) else json.dumps(ov["body"])
    category = next((c for c in ("web", "api", "infra", "recon") if c in scope.categories), "web")
    decision = scope.check_url(url, category)
    if not decision.allowed:
        _audit(db, engagement_id, exchange_id,
               {"url": url, "reason": decision.reason}, "traffic_replay_refused")
        return {"ok": False, "error": f"out_of_scope: {decision.reason}", "url": url}
    # probe re-checks scope on the first hop and on every redirect hop (per-hop refusal audited)
    r = probe.request(engagement_id, scope, url, method=method, headers=headers or None,
                      body=body, category=category, tool="traffic_replay")
    if not r.get("ok"):
        _audit(db, engagement_id, exchange_id,
               {"url": url, "error": r.get("error")}, "traffic_replay_failed")
        return {"ok": False, "error": r.get("error"), "url": r.get("url", url)}
    db.execute("UPDATE exchanges SET replay_of=?, tags_json=? WHERE id=?",
               (exchange_id, json.dumps(["replay"]), r["exchange_id"]))
    diff = _diff(blob, r)
    _audit(db, engagement_id, exchange_id,
           {"url": url, "method": method, "replay_exchange_id": r["exchange_id"], "diff": diff},
           "traffic_replay")
    return {"ok": True, "exchange_id": r["exchange_id"], "evidence_id": r["evidence_id"],
            "status": r["status"], "replay_of": exchange_id, "diff": diff}
