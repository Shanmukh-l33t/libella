"""Standards coverage ledger: what a standard requires, and what the run did.

One ledger for every standard in :mod:`libella.standards` (WSTG 4.2, ASVS 5.0.0,
...). Two independent records per requirement, both always visible:

* automatic — derived from persisted engagement state (intents, tool calls,
  captured exchanges, degradation events, findings) through the standard's
  evidence mapping. It says what the run actually did, never what a report
  would like to claim.
* manual — an operator's recorded review (`covered` needs this engagement's
  evidence, `manual`/`unsupported` need a reason).

`status` is the manual record when one exists, otherwise the automatic status.
Nothing here plans, queues or runs a tool.

A requirement is only ever accounted for by the units mapped to it in the
standard's mapping, and a check that covers part of a requirement can never
report `completed_no_issue`: it reports `partial_evidence`, because a passing
partial check is not a passing requirement.
"""
import json
import time

from . import controls, standards
from .db import DB

DEFAULT = "wstg"
STATUSES = ("covered", "manual", "unsupported")  # manual review ledger
AUTO_STATUSES = ("not_applicable", "not_supported", "requires_manual", "skipped_policy",
                 "skipped_dependency", "attempted", "inconclusive", "failed",
                 "completed_no_issue", "partial_evidence", "finding_unverified",
                 "finding_verified")
CONFIRMED_STATES = {"validated", "reported", "retested_persists"}  # == gate.CONFIRMED_STATES
COMPLETED = ("completed_no_issue", "partial_evidence", "finding_unverified", "finding_verified")
ATTEMPTED = ("attempted", "inconclusive", "failed") + COMPLETED
MANUAL_AS = {"covered": "completed_no_issue", "manual": "requires_manual",
             "unsupported": "not_supported"}
DEPENDENCY_CODES = {"missing_tool", "tool_unavailable", "image_not_local"}
NOTE_MAX = 2000

# Unit outcome -> the status the ledger shows. Ordered by what wins a merge.
_PREF = (("blocked_target", "inconclusive"), ("partial", "partial_evidence"),
         ("completed", "completed_no_issue"),
         ("inconclusive", "inconclusive"),
         ("failed", "failed"), ("skipped_policy", "skipped_policy"),
         ("skipped_dependency", "skipped_dependency"), ("attempted", "attempted"))
_VERB = {"blocked_target": "the target answered with a challenge or the scan stopped early: not assessed",
         "partial": "executed with a subset of its checks: the excluded subset was never tested",
         "completed": "executed, no finding recorded",
         "inconclusive": "ran partially (timeout/cancel), never completed",
         "failed": "failed",
         "skipped_policy": "refused by the engagement profile",
         "skipped_dependency": "not run: mapped tool or dependency is missing",
         "attempted": "scheduled or running, without a completion record"}


def _engagement(db: DB, engagement_id: str):
    row = db.one("SELECT id FROM engagements WHERE id=?", (engagement_id,))
    if not row:
        raise LookupError("engagement not found")
    return row


def _slot(slots: dict, name: str) -> dict:
    return slots.setdefault(name, {"calls": [], "exchanges": [], "intents": [],
                                   "denied": [], "missing": [], "blocked": [],
                                   "partial": []})


def _unit_slots(db: DB, engagement_id: str, spec: dict) -> dict:
    """Index persisted execution state by the unit names the engine did record."""
    slots: dict = {}
    for r in db.query("SELECT id, tool, scope_decision, error FROM tool_calls "
                      "WHERE engagement_id=?", (engagement_id,)):
        _slot(slots, r["tool"])["calls"].append(r)
    for r in db.query("SELECT id, tool FROM exchanges WHERE engagement_id=?",
                      (engagement_id,)):
        unit = spec["external_unit"].get(r["tool"])
        if unit:
            _slot(slots, unit)["exchanges"].append(r["id"])
    roles = {}
    for r in db.query("SELECT id, role, status FROM intents WHERE engagement_id=?",
                      (engagement_id,)):
        _slot(slots, r["role"])["intents"].append(r)
        roles[r["id"]] = r["role"]
    for e in db.query("SELECT seq, payload_json FROM events WHERE engagement_id=? "
                      "AND kind='degradation'", (engagement_id,)):
        payload = json.loads(e["payload_json"])
        code = payload.get("code")
        if code == "policy_restriction":
            # the orchestrator may name several refused methods in one unit string
            for unit in str(payload.get("unit") or "").split(","):
                if unit.strip():
                    _slot(slots, unit.strip())["denied"].append(e["seq"])
        elif code == "oast_unsupported":
            # The unit RAN and its in-band templates are valid results; only the
            # out-of-band subset was refused by policy. That is partial evidence, not an
            # unassessed target: calling it inconclusive would understate the work done.
            _slot(slots, payload.get("unit") or "nuclei_scan")["partial"].append(e["seq"])
        elif code in ("audit_blocked", "crawl_result_missing"):
            # the audit ran but could not test: its completion is not a result.
            # crawl_result_missing is the same class: the inventory it needed was absent,
            # so the sweep of zero endpoints must never read as assessed.
            unit = payload.get("unit") or roles.get(payload.get("intent_id")) or "web_checks"
            _slot(slots, unit)["blocked"].append(e["seq"])
        elif code in ("target_mitigated", "scan_partial"):
            # the unit ran but could not read the application: never count it as assessed.
            # The payload names the tools involved; map them to the units they prove.
            named = [u for u in (payload.get("units") or []) if isinstance(u, str)]
            units = {spec["external_unit"].get(u, u) for u in named}
            if not units:  # older record without unit names: the role is still honest
                units = {roles.get(payload.get("intent_id")) or "web_checks"}
            for unit in units:
                _slot(slots, unit)["blocked"].append(e["seq"])
        elif code in DEPENDENCY_CODES:
            detail = str(payload.get("detail") or "").lower()
            for unit, row in spec["units"].items():
                if any(tool in detail for tool in row.get("tools", ())):
                    _slot(slots, unit)["missing"].append(e["seq"])
    return slots


def _provenance(db: DB, engagement_id: str, spec: dict, findings) -> dict:
    """finding id -> the units whose captured evidence the finding cites.

    Recovered from the evidence a finding binds (exchange or tool artifact), so a
    requirement only counts findings its own checks produced. A finding whose
    evidence maps to no known unit (an agent's own request) keeps an empty set and
    is matched by CWE alone.
    """
    unit_of: dict = {}
    for r in db.query("SELECT evidence_id, tool FROM exchanges WHERE engagement_id=? "
                      "AND evidence_id IS NOT NULL", (engagement_id,)):
        unit = spec["external_unit"].get(r["tool"])
        if unit:
            unit_of.setdefault(r["evidence_id"], set()).add(unit)
    for r in db.query("SELECT artifact_id, tool FROM tool_calls WHERE engagement_id=? "
                      "AND artifact_id IS NOT NULL", (engagement_id,)):
        if r["tool"] in spec["units"]:
            unit_of.setdefault(r["artifact_id"], set()).add(r["tool"])
    out = {}
    for f in findings:
        try:
            ids = json.loads(f.get("evidence_ids_json") or "[]")
        except ValueError:
            ids = []
        out[f["id"]] = set().union(*(unit_of.get(e, set()) for e in ids)) if ids else set()
    return out


def _merge(slots: dict, names) -> dict:
    out = {"calls": [], "exchanges": [], "intents": [], "denied": [], "missing": [],
           "blocked": [], "partial": []}
    for name in names:
        for key, value in slots.get(name, {}).items():
            out[key] += value
    return out


def _unit_state(s: dict):
    """What one unit's recorded evidence supports. `missing`/timeout beat a bare exit 0."""
    missing = bool(s["missing"]) or any((c["error"] or "").startswith("missing_tool")
                                        for c in s["calls"])
    refused = any(str(c["scope_decision"] or "").startswith("refused") for c in s["calls"])
    if s["denied"] or (refused and not missing):
        # the engagement refused the work (scope category, port, profile): not a failure
        return "skipped_policy"
    if s["blocked"]:
        return "blocked_target"
    if s["partial"]:
        return "partial"
    if any((c["scope_decision"] or "") == "executed: ok" for c in s["calls"]) or s["exchanges"]:
        return "completed"
    if missing:
        return "skipped_dependency"
    if any(c["error"] in ("timeout", "cancelled") for c in s["calls"]):
        return "inconclusive"
    if any(c["error"] for c in s["calls"]):
        return "failed"
    if any(i["status"] == "done" for i in s["intents"]):
        return "completed"
    if any(i["status"] in ("blocked", "failed") for i in s["intents"]):
        return "failed"
    if any(i["status"] in ("open", "running") for i in s["intents"]):
        return "attempted"
    if any(i["status"] == "exhausted" for i in s["intents"]):
        return "inconclusive"
    return None


def _pointers(slots: dict, units, hits=(), spec=None) -> dict:
    merged = _merge(slots, units)
    if spec:
        roles = [p for u in units for p in spec.get("parents", {}).get(u, ()) if p not in units]
        merged["intents"] += _merge(slots, roles)["intents"]
    return {"tool_calls": [c["id"] for c in merged["calls"]],
            "exchanges": merged["exchanges"],
            "intents": [i["id"] for i in merged["intents"]],
            "events": merged["denied"] + merged["missing"],
            "findings": [f["id"] for f in hits]}


def _strength(spec: dict, rid: str, units) -> str:
    """How much of the requirement the mapped checks actually cover."""
    order = {"direct": 0, "partial": 1, "indirect": 2}
    strengths = [spec["units"][u]["strength"].get(rid) or "direct" for u in units
                 if u in spec["units"]]
    return min(strengths, key=lambda s: order.get(s, 1)) if strengths else "partial"


def _derive(spec: dict, rid: str, slots: dict, findings, profile: str, categories,
            produced_by=None, links=None) -> tuple:
    """Automatic status + evidence pointers for one requirement, from recorded execution."""
    every = spec["by_requirement"].get(rid, ())
    # per-method rows are precise; a role row (which runs all of them) only speaks
    # when no specific method is mapped, so a refused method is never masked.
    units = [u for u in every if not spec["units"][u]["union_of"]] or list(every)
    applies = [c for c in spec["applies_to"] if c in categories]
    if not applies:
        return {"status": "not_applicable", "units": [],
                "reason": f"engagement scope has no {' or '.join(spec['applies_to'])} category"}, \
               _pointers(slots, [])
    if not units:
        linked = _attributed(spec, rid, findings, produced_by or {}, links or {})
        if linked:  # no automated check, but an analyst tied a finding to it
            verified = [f for f in linked if f["state"] in CONFIRMED_STATES]
            f = (verified or linked)[0]
            return {"status": "finding_verified" if verified else "finding_unverified",
                    "units": [], "reason": f"analyst-linked finding {f['id']} ({f['cwe']}, "
                                           f"{f['state']})"}, _pointers(slots, [], linked)
        blocked = spec["not_supported"].get(rid)
        if blocked:
            return {"status": "not_supported", "units": [], "reason": blocked}, \
                   _pointers(slots, [])
        return {"status": "requires_manual", "units": [],
                "reason": standards.manual_reason(spec["id"], rid)}, _pointers(slots, [])
    states = {}
    for unit in units:
        row = spec["units"][unit]
        names = (unit, *row.get("tools", ()), *row.get("alias_evidence", ()))
        states[unit] = _unit_state(_merge(slots, names))
    hits = _attributed(spec, rid, findings, produced_by or {}, links or {})
    pointers = _pointers(slots, units, hits, spec)
    if hits:
        verified = [f for f in hits if f["state"] in CONFIRMED_STATES]
        f = (verified or hits)[0]
        return {"status": "finding_verified" if verified else "finding_unverified",
                "units": units, "strength": _strength(spec, rid, units),
                "reason": f"finding {f['id']} ({f['cwe']}, {f['state']})"}, pointers
    strength = _strength(spec, rid, units)
    for state, status in _PREF:
        named = [u for u, s in states.items() if s == state]
        if named:
            reason = f"{', '.join(named)}: {_VERB[state]}"
            if state == "skipped_policy":
                reason += f" ({profile!r})"
            if state == "completed" and strength != "direct":
                # a check that covers only part of the requirement cannot pass it
                status = "partial_evidence"
                reason += f"; covers the requirement only {strength}ly"
            return {"status": status, "units": named, "strength": strength,
                    "reason": reason}, pointers
    return {"status": "inconclusive", "units": units, "strength": strength,
            "reason": f"{', '.join(units)}: mapped check never ran in this engagement"}, pointers


def level_for(db: DB, engagement_id: str, framework: str) -> int | None:
    """The verification level selected for this engagement, if the standard has levels."""
    if not standards.levels(framework):
        return None
    row = db.one("SELECT standards_json FROM engagements WHERE id=?", (engagement_id,))
    try:
        chosen = json.loads((row or {}).get("standards_json") or "{}")
    except ValueError:
        chosen = {}
    value = ((chosen.get(framework) or {}).get("level"))
    return value if isinstance(value, int) and value in standards.levels(framework) else None


def _links(db: DB, engagement_id: str, framework: str) -> dict:
    """(requirement, finding) -> the analyst's latest attribution decision.

    requirement_links is append-only: every add/remove stays as audit history and
    the newest row per pair is the one in force.
    """
    current: dict = {}
    for r in db.query("SELECT * FROM requirement_links WHERE engagement_id=? AND framework=? "
                      "ORDER BY id", (engagement_id, framework)):
        current[(r["requirement_id"], r["finding_id"])] = r
    return current


def _attributed(spec, rid, findings, produced_by, links) -> list:
    """Automatic structured attribution, then analyst corrections on top."""
    hits = {f["id"]: f for f in standards.findings_for(spec["id"], rid, findings, produced_by)}
    by_id = {f["id"]: f for f in findings}
    for (req, fid), row in links.items():
        if req != rid or fid not in by_id:
            continue
        if row["action"] == "remove":
            hits.pop(fid, None)
        elif row["action"] == "add":
            hits[fid] = {**by_id[fid], "linked_by": "analyst"}
    return list(hits.values())


def link(db: DB, engagement_id: str, framework: str, requirement_id: str, finding_id: str,
         action: str, note: str, actor: str = "operator") -> dict:
    """Record an analyst attribution decision (add/remove) with a mandatory reason."""
    _engagement(db, engagement_id)
    spec = standards.spec(framework)
    if requirement_id not in spec["requirements"]:
        raise LookupError(f"unknown {framework} requirement {requirement_id}")
    if not db.one("SELECT id FROM findings WHERE id=? AND engagement_id=?",
                  (finding_id, engagement_id)):
        raise LookupError("finding not found in this engagement")
    if action not in ("add", "remove"):
        raise ValueError("action must be add or remove")
    note = (note or "").strip() if isinstance(note, str) else ""
    if not note:
        raise ValueError("an attribution change needs a note explaining why")
    if len(note) > NOTE_MAX:
        raise ValueError(f"note exceeds {NOTE_MAX} characters")
    db.execute("INSERT INTO requirement_links(engagement_id, framework, requirement_id, "
               "finding_id, action, note, actor, created_at) VALUES(?,?,?,?,?,?,?,?)",
               (engagement_id, framework, requirement_id, finding_id, action, note, actor,
                time.time()))
    return {"history": db.query(
        "SELECT requirement_id, finding_id, action, note, actor, created_at FROM "
        "requirement_links WHERE engagement_id=? AND framework=? AND requirement_id=? ORDER BY id",
        (engagement_id, framework, requirement_id))}


def workspace(db: DB, engagement_id: str, framework: str = DEFAULT, evidence=None) -> dict:
    """Catalog + automatic execution status + recorded review for one engagement."""
    _engagement(db, engagement_id)
    spec = standards.spec(framework)
    eng = db.one("SELECT scope_json, profile FROM engagements WHERE id=?", (engagement_id,))
    profile = eng["profile"]
    scope_categories = json.loads(eng["scope_json"]).get("categories") or []
    level = level_for(db, engagement_id, framework)
    in_scope = set(standards.requirements(framework, level))
    slots = _unit_slots(db, engagement_id, spec)
    if evidence is not None:
        controls.migrate(db, evidence, engagement_id)
    findings = db.query("SELECT id, cwe, state, title, evidence_ids_json, controls_json, "
                        "controls_source FROM findings WHERE engagement_id=?", (engagement_id,))
    produced_by = _provenance(db, engagement_id, spec, findings)
    links = _links(db, engagement_id, framework)
    recorded = {r["test_id"]: r for r in db.query(
        "SELECT * FROM coverage_entries WHERE engagement_id=? AND framework=?",
        (engagement_id, framework))}
    statuses = {s: 0 for s in AUTO_STATUSES}
    manual = {s: 0 for s in STATUSES}
    effective = {s: 0 for s in AUTO_STATUSES}
    categories = []
    total = 0
    for group in spec["groups"]:
        rows, counts = [], {s: 0 for s in AUTO_STATUSES}
        for rid in group["requirements"]:
            if rid not in in_scope:
                continue
            req = spec["requirements"][rid]
            auto, pointers = _derive(spec, rid, slots, findings, profile, scope_categories,
                                     produced_by, links)
            row = recorded.get(rid) or {}
            review = row["status"] if row.get("status") in STATUSES else None
            entry = {"status": review, "note": row.get("note"),
                     "evidence_id": row.get("evidence_id"),
                     "updated_at": row.get("updated_at")} if review else None
            if review:
                manual[review] += 1
            statuses[auto["status"]] += 1
            counts[auto["status"]] += 1
            effective[MANUAL_AS.get(review, auto["status"])] += 1
            total += 1
            rows.append({"id": rid, "title": req["title"], "level": req.get("level"),
                         "section": req.get("section"), "section_title": req.get("section_title"),
                         "status": review or auto["status"],
                         "automatic": auto, "manual": entry, "evidence": pointers})
        categories.append({"id": group["id"], "name": group["name"], "counts": counts,
                           "tests": rows})

    completed = sum(effective[s] for s in COMPLETED)
    applicable = total - effective["not_applicable"]
    summary = {
        "total": total, "catalog": len(spec["order"]), "level": level,
        "excluded_by_level": len(spec["order"]) - len(in_scope),
        "applicable": applicable,
        "supported": applicable - effective["requires_manual"] - effective["not_supported"],
        "attempted": sum(effective[s] for s in ATTEMPTED),
        "completed": completed,
        "partial": effective["partial_evidence"],
        "with_findings": effective["finding_verified"] + effective["finding_unverified"],
        "skipped": effective["skipped_policy"] + effective["skipped_dependency"],
        "manual_required": effective["requires_manual"],
        "not_tested": applicable - completed,
        "statuses": statuses, "manual": manual,
    }
    attributed = {fid for c in categories for t in c["tests"] for fid in t["evidence"]["findings"]}
    unattributed = [{"id": f["id"], "title": f["title"], "cwe": f["cwe"], "state": f["state"],
                     "reason": ("no producing check could be recovered from its evidence"
                                if not produced_by.get(f["id"])
                                else "its producing check maps to no requirement here")}
                    for f in findings if f["id"] not in attributed]
    return {"unattributed_findings": unattributed,
            "framework": {**spec["framework"], **{"requirements": len(spec["order"]),
                                                  "groups": len(spec["groups"]),
                                                  "applies_to": spec["applies_to"]}},
            "engagement_id": engagement_id, "summary": summary,
            "categories": categories,
            "mapping": {u: {"requirements": list(r["ids"]), "why": r["why"],
                            "strength": r["strength"]}
                        for u, r in spec["units"].items()}}


def record(db: DB, engagement_id: str, test_id: str, status, note=None,
           evidence_id=None, framework: str = DEFAULT) -> dict:
    """Record one review outcome. Returns the refreshed workspace.

    covered: needs evidence_id that exists in this engagement.
    manual / unsupported: need a note saying what was done or why it cannot be.
    unknown: clears the entry. Raises LookupError (unknown engagement/test) or
    ValueError (bad status, missing justification, foreign evidence).
    """
    _engagement(db, engagement_id)
    spec = standards.spec(framework)
    if test_id not in spec["requirements"]:
        raise LookupError(f"unknown {framework} requirement {test_id}")
    if status not in STATUSES and status != "unknown":
        raise ValueError(f"status must be one of {', '.join(STATUSES)}, unknown")
    if status == "unknown":
        db.execute("DELETE FROM coverage_entries WHERE engagement_id=? AND framework=? "
                   "AND test_id=?", (engagement_id, framework, test_id))
        return workspace(db, engagement_id, framework)

    note = (note or "").strip() if isinstance(note, str) else note
    if note is not None and not isinstance(note, str):
        raise ValueError("note must be a string")
    if len(note or "") > NOTE_MAX:
        raise ValueError(f"note exceeds {NOTE_MAX} characters")
    if status in ("manual", "unsupported") and not note:
        raise ValueError(f"{status} needs a note explaining the review")
    if evidence_id and status != "covered":
        raise ValueError("evidence_id only applies to covered tests")
    if status == "covered":
        if not evidence_id:
            raise ValueError("covered needs an evidence_id from this engagement")
        ev = db.one("SELECT engagement_id FROM evidence WHERE id=?", (evidence_id,))
        if ev is None:
            raise ValueError("evidence not found")
        if ev["engagement_id"] != engagement_id:
            raise ValueError("evidence belongs to another engagement")

    db.execute(
        "INSERT INTO coverage_entries(engagement_id, framework, test_id, status, note, "
        "evidence_id, updated_at) VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(engagement_id, test_id) DO UPDATE SET framework=excluded.framework, "
        "status=excluded.status, note=excluded.note, evidence_id=excluded.evidence_id, "
        "updated_at=excluded.updated_at",
        (engagement_id, framework, test_id, status, note,
         evidence_id if status == "covered" else None, time.time()))
    return workspace(db, engagement_id, framework)
