"""Nuclei scope/progress as persisted, never as planned.

Reads only tool_calls (argv, status, duration) and `scan_progress` events (nuclei's own
-stats samples). Anything a record does not carry stays None / "unknown": no template
count is inferred, no completion is assumed from a clean exit, and the tool's configured
time limit is never quoted (it is not recorded; only the recorded `timeout` outcome is).
"""
from __future__ import annotations

import json

SLACK_S = 1.0  # event/audit timestamps are taken at slightly different moments


def _argv(raw) -> list[str]:
    try:
        v = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [str(x) for x in v] if isinstance(v, list) else []


def _opt(argv: list[str], flag: str) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


def _status(call: dict) -> str:
    if str(call.get("scope_decision") or "").startswith("refused"):
        return "refused"  # never ran
    err = call.get("error")
    if err in ("timeout", "cancelled"):
        return err
    if err:
        return "failed"
    return "ok" if call.get("exit_code") == 0 else "unknown"  # legacy: no exit code


def _completion(status: str, percent) -> str:
    if status == "refused":
        return "not_run"
    if status in ("timeout", "cancelled"):
        return "unfinished"
    # shortcut: -si 5 samples can lag the exit, so <100% on a clean exit stays unknown
    if status == "ok" and percent == 100:
        return "complete"
    return "unknown"


def nuclei_scans(db, engagement_id: str, safe=lambda s: s) -> dict:
    """{"attempts": [...], "match_findings": int}; empty dict when nuclei never ran."""
    calls = db.query("SELECT * FROM tool_calls WHERE engagement_id=? AND tool='nuclei' "
                     "ORDER BY created_at, id", (engagement_id,))
    if not calls:
        return {}
    samples = []
    for e in db.query("SELECT seq, created_at, payload_json FROM events WHERE engagement_id=? "
                      "AND kind='scan_progress' ORDER BY seq", (engagement_id,)):
        try:
            p = json.loads(e["payload_json"])
        except ValueError:
            continue
        if isinstance(p, dict) and p.get("tool") == "nuclei":
            samples.append((e["created_at"], p))
    by_intent: dict = {}
    for c in calls:
        by_intent.setdefault(c["intent_id"], []).append(c)

    def owned(c, at, p) -> bool:
        group = by_intent[c["intent_id"]]
        if p.get("intent_id") is None or p.get("intent_id") != c["intent_id"]:
            return False
        if len(group) == 1:
            return True
        end = c["created_at"] or 0
        start = end - (c["duration_ms"] or 0) / 1000
        mine = start - SLACK_S <= (at or 0) <= end + SLACK_S
        # a sample inside two overlapping attempts belongs to neither
        return mine and sum(1 for o in group if o is not c and
                            (o["created_at"] or 0) - (o["duration_ms"] or 0) / 1000 - SLACK_S
                            <= (at or 0) <= (o["created_at"] or 0) + SLACK_S) == 0

    attempts = []
    for c in calls:
        argv = _argv(c["argv_json"])
        mine = [p for at, p in samples if owned(c, at, p)]
        last = mine[-1] if mine else {}
        status = _status(c)
        group = by_intent[c["intent_id"]]
        attempts.append({
            "call_id": c["id"], "intent_id": c["intent_id"], "target": safe(c["target"]),
            "attempt": group.index(c) + 1, "attempts_for_intent": len(group),
            "status": status, "exit_code": c["exit_code"],
            "timed_out": status == "timeout",
            "duration_ms": c["duration_ms"],
            "filters": {"severity": safe((_opt(argv, "-severity") or [None])[0]),
                        "tags": safe((_opt(argv, "-tags") or [None])[0]),
                        "protocol_types": safe((_opt(argv, "-pt") or [None])[0]),
                        "rate_limit": (_opt(argv, "-rate-limit") or [None])[0],
                        "template_paths": len(_opt(argv, "-t"))},
            "progress": {"reported": bool(mine), "samples": len(mine),
                         "templates_selected": last.get("templates"),
                         "percent_last": last.get("percent"),
                         "requests": last.get("requests"),
                         "total_requests": last.get("total_requests"),
                         "matched": last.get("matched"), "errors": last.get("errors"),
                         "elapsed": safe(last.get("elapsed"))},
            "completion": _completion(status, last.get("percent")),
        })
    n = db.one("SELECT COUNT(*) n FROM findings WHERE engagement_id=? "
               "AND dedup_key LIKE 'nuclei:%'", (engagement_id,))["n"]
    return {"attempts": attempts, "match_findings": n}


def _v(x, unit="") -> str:
    return "not reported" if x is None else f"{x}{unit}"


def scan_md(scans: dict | None, heading: str = "##") -> list[str]:
    """Markdown lines for report["scans"]; [] for reports without a nuclei record."""
    rec = (scans or {}).get("nuclei") or {}
    attempts = rec.get("attempts") or []
    if not attempts:
        return []
    out = [f"\n{heading} Template scan (nuclei) scope and progress\n",
           "From the persisted tool call and the engine's own progress samples. A template "
           "match is a signal, not a measure of methodology coverage; an unreported figure "
           "is unknown, not zero.\n"]
    for a in attempts:
        f, p = a.get("filters") or {}, a.get("progress") or {}
        tag = f" (attempt {a['attempt']} of {a['attempts_for_intent']})" \
            if a.get("attempts_for_intent", 1) > 1 else ""
        out.append(f"- `{a.get('call_id')}`{tag}: target `{a.get('target')}`, run status "
                   f"**{a.get('status')}**, completion **{a.get('completion')}**"
                   + (", ended on its time limit" if a.get("timed_out") else ""))
        out.append(f"  - Selection: severity {_v(f.get('severity'))}, tags {_v(f.get('tags'))}, "
                   f"protocol {_v(f.get('protocol_types'))}, templates selected "
                   f"{_v(p.get('templates_selected'))}")
        out.append(f"  - Last progress sample ({p.get('samples', 0)} recorded): "
                   f"{_v(p.get('percent_last'), '%')} request progress, requests {_v(p.get('requests'))} of "
                   f"{_v(p.get('total_requests'))}, errors {_v(p.get('errors'))}, "
                   f"engine-reported matches {_v(p.get('matched'))}")
    out.append("\nExecuted and unfinished template counts: not reported by the scanner.")
    out.append(f"\nFindings recorded from nuclei matches: {rec.get('match_findings', 0)}\n")
    return out
