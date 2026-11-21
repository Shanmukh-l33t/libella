"""Versioned security standards as data: catalogs plus evidence mappings.

Two things live here and nothing else does:

* a :func:`catalog` — the requirements of one published standard, at one version,
  with their exact published identifiers. ASVS 5.0.0 is imported from the OWASP
  machine-readable export (see ``scripts/import_standards.py``); WSTG 4.2 is the
  curated test index. Provenance (source, upstream commit, licence, retrieval
  date) travels with the data so a report can name what it was measured against.
* a :func:`mapping` — which units Libella actually executes touch which
  requirements, and how much of the requirement each one really covers. This is
  reviewer judgement recorded as data, not a keyword match, which is why every
  row carries its reason.

One shape serves both standards so the coverage ledger has one implementation:
a requirement is only ever accounted for by the units mapped to it, and that
mapping never turns a passed check into a passed requirement.
"""
import json
import pathlib

DATA = pathlib.Path(__file__).resolve().parent / "standards_data"
_cache: dict = {}


def _read(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def _rows(rows) -> dict:
    """Expand `union` rows so every unit lists the requirement ids it proves."""
    out: list = []
    for r in rows:
        if "union" in r:
            ids, cwe, strength, match = [], {}, {}, {}
            for unit in r["union"]:
                src = next((o for o in out if o["unit"] == unit), None)
                if src is None:
                    raise ValueError(f"union member {unit} must precede {r['unit']}")
                for rid in src["ids"]:
                    if rid not in ids:
                        ids.append(rid)
                    cwe[rid] = tuple(dict.fromkeys(cwe.get(rid, ()) + tuple(src["cwe"].get(rid, ()))))
                    strength[rid] = src["strength"].get(rid) or "direct"
                    match[rid] = tuple(dict.fromkeys(match.get(rid, ()) + src["match"].get(rid, ())))
            row = {"unit": r["unit"], "ids": tuple(ids), "cwe": cwe, "strength": strength,
                   "match": match,
                   "union_of": tuple(r["union"])}
        else:
            spec = r.get("requirements") or {}
            if isinstance(spec, (list, tuple)):  # flat id list: every id is direct
                spec = {rid: {"strength": "direct"} for rid in spec}
            ids = tuple(spec)
            row = {"unit": r["unit"], "ids": ids,
                   "cwe": {rid: tuple(v.get("cwe") or ()) for rid, v in spec.items()},
                   "strength": {rid: v.get("strength") or "direct" for rid, v in spec.items()},
                   "match": {rid: tuple(v.get("match") or ()) for rid, v in spec.items()},
                   "union_of": tuple(r.get("union_of") or ())}
        row.update({"why": r.get("why") or r.get("note") or "",
                    "exchanges": tuple(r.get("exchanges") or ()),
                    "tools": tuple(r.get("tools") or ()),
                    "alias_evidence": tuple(r.get("alias_evidence") or ())})
        out.append(row)
    return {r["unit"]: r for r in out}


def _spec(fid: str, catalog: dict, mapping: dict) -> dict:
    reqs = catalog["requirements"]
    by_id = {r["id"]: r for r in reqs}
    unknown = [rid for r in mapping.get("rows", []) for rid in _row_ids(r) if rid not in by_id]
    if unknown:
        raise ValueError(f"{fid}: mapping names requirements absent from the catalog: {unknown}")
    units = _rows(mapping.get("rows", []))
    chapters = catalog.get("chapters") or [
        {"id": c, "name": next((r.get("chapter_title") or c for r in reqs if r["chapter"] == c), c)}
        for c in dict.fromkeys(r["chapter"] for r in reqs)]
    groups = []
    for ch in chapters:
        members = [r["id"] for r in reqs if r.get("chapter") == ch["id"]]
        if members:
            groups.append({"id": ch["id"], "name": ch["name"], "requirements": members})
    return {
        "id": fid,
        "framework": catalog["framework"],
        "levels": catalog["framework"].get("levels") or [],
        "applies_to": mapping.get("applies_to") or ["web"],
        "requirements": by_id,
        "order": [r["id"] for r in reqs],
        "groups": groups,
        "units": units,
        "by_requirement": {rid: tuple(u for u, row in units.items() if rid in row["ids"])
                           for rid in by_id},
        "parents": {u: tuple(role for role, row in units.items() if u in row["union_of"])
                    for u in units},
        "external_unit": {name: row["unit"] for row in units.values() for name in
                          row["exchanges"] + row["alias_evidence"]},
        "not_supported": mapping.get("not_supported") or {},
        "manual": mapping.get("manual") or {},
        "manual_overrides": mapping.get("manual_overrides") or {},
        "unmapped": mapping.get("unmapped") or {},
    }


def _row_ids(row: dict) -> tuple:
    if "union" in row:
        return ()
    spec = row.get("requirements") or {}
    return tuple(spec) if not isinstance(spec, (list, tuple)) else tuple(spec)


def _wstg() -> dict:
    """WSTG keeps its reviewed row table; adapt it to the shared spec shape."""
    from . import check_mapping as mapping

    rows = []
    for unit, row in mapping.CHECKS.items():
        rows.append({
            "unit": unit,
            "requirements": {rid: {"strength": "direct", "cwe": row["cwe_by_test"].get(rid, ())}
                             for rid in row["wstg"]},
            # check_mapping already expanded its unions, but keeps the membership:
            # a role row must not mask a refused individual method
            "union_of": list(row.get("union", ())),
            "exchanges": row.get("exchanges", ()), "tools": row.get("tools", ()),
            "alias_evidence": row.get("alias_evidence", ()),
            "why": row.get("why", ""),
        })
    return {
        "applies_to": ["web"],
        "rows": rows,
        "unmapped": dict(mapping.UNMAPPED),
        "manual": dict(mapping.MANUAL_REASONS),
        "manual_overrides": dict(mapping.MANUAL_OVERRIDES),
        "not_supported": dict(mapping.NOT_SUPPORTED),
    }


def spec(fid: str) -> dict:
    """The loaded catalog + mapping for one standard, cached per process."""
    if fid in _cache:
        return _cache[fid]
    cat = DATA / f"{fid}.json"
    hits = sorted(DATA.glob(f"{fid}-*.json"))
    if not cat.exists() and hits:
        cat = hits[-1]
    if not cat.exists():
        raise KeyError(f"unknown standard {fid!r}")
    catalog = _read(cat)
    if fid == "wstg":
        mapping = _wstg()
    else:
        mm = DATA / f"mapping-{cat.stem}.json"
        if not mm.exists():
            raise KeyError(f"no evidence mapping for {fid!r}")
        mapping = _read(mm)
    _cache[fid] = _spec(fid, catalog, mapping)
    return _cache[fid]


def available() -> list:
    """Every standard this build can account for, for a selector or an index."""
    found = {}
    for path in sorted(DATA.glob("*.json")):
        if path.stem.startswith("mapping-"):
            continue
        catalog = _read(path)
        fw = catalog["framework"]
        fid = fw["id"].lower()
        try:
            s = spec(fid)
        except (KeyError, ValueError):
            continue
        found[fid] = {"id": fid, "framework": fw, "levels": s["levels"],
                      "applies_to": s["applies_to"], "requirements": len(s["order"]),
                      "mapped_units": len(s["units"]),
                      "applicable_to_scope": s["applies_to"]}
    return list(found.values())


def levels(fid: str) -> list:
    return spec(fid)["levels"]


def requirement(fid: str, rid: str) -> dict:
    return spec(fid)["requirements"][rid]


def requirements(fid: str, level=None) -> list:
    """Requirement ids in published order, optionally capped at one verification level.

    ASVS levels are cumulative: a Level 2 assessment covers the Level 1 and 2
    requirements, which is why this filters by `<= level` rather than equality.
    """
    s = spec(fid)
    if level is None:
        return list(s["order"])
    return [rid for rid in s["order"]
            if (s["requirements"][rid].get("level") or 1) <= level]


def units_for(fid: str, rid: str) -> tuple:
    return spec(fid)["by_requirement"].get(rid, ())


def manual_reason(fid: str, rid: str) -> str:
    s = spec(fid)
    if rid in s["manual_overrides"]:
        return s["manual_overrides"][rid]
    chapter = rid.split(".")[0]
    return s["manual"].get(chapter) or s["manual"].get(chapter.rsplit("-", 1)[0]) or "no Libella check"


def not_supported(fid: str, rid: str):
    return spec(fid)["not_supported"].get(rid)


def unit_row(fid: str, unit: str):
    return spec(fid)["units"].get(unit)


def findings_for(fid: str, rid: str, findings, produced_by=None) -> list:
    """Findings that are evidence against this requirement.

    A finding counts only when (a) its CWE is one a mapped check emits for this
    requirement, (b) when its producing unit is known, that unit is one mapped to
    the requirement (a CWE-200 from a path probe is not GraphQL introspection
    evidence), and (c) when the mapping names a `match` for the requirement, the
    finding title names it (a missing-CSP finding is not a missing-HSTS one).
    `produced_by` maps finding id -> set of units recovered from its evidence.
    """
    s = spec(fid)
    mapped = s["by_requirement"].get(rid, ())
    units = [u for u in mapped if not s["units"][u]["union_of"]]
    cwes = {c for u in units for c in (s["units"][u]["cwe"].get(rid) or ())}
    matches = {m.lower() for u in units for m in (s["units"][u]["match"].get(rid) or ())}
    out = []
    for f in findings:
        if f["cwe"] not in cwes:
            continue
        origin = (produced_by or {}).get(f["id"])
        if origin and not origin & set(mapped):
            continue
        if matches and not any(m in (f.get("title") or "").lower() for m in matches):
            continue
        out.append(f)
    return out


def framework(fid: str) -> dict:
    return spec(fid)["framework"]
