"""Investigation knowledge graph: real persisted lineage, not decorative nodes.

Connects assets -> endpoints -> auth contexts; observations -> evidence;
hypotheses -> findings; findings -> verifications -> remediation -> retests;
intents -> agent_runs -> investigation_steps -> tool_calls. Supports filtering,
timeline, and coverage so an operator can answer: what was discovered, why it
matters, how, which tests ran, and what evidence supports the conclusion.
"""
import json

from .db import DB


def build_graph(db: DB, engagement_id: str, include=None) -> dict:
    nodes, edges = [], []
    seen = set()

    def node(nid, ntype, label, data=None, kind=None):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "type": ntype, "kind": kind or ntype,
                      "label": label, "data": data or {}})

    def edge(src, dst, kind, verified=False):
        if src in seen and dst in seen:
            edges.append({"source": src, "target": dst, "kind": kind, "verified": verified})

    assets = db.query("SELECT * FROM assets WHERE engagement_id=?", (engagement_id,))
    for a in assets:
        node(a["id"], "asset", a["key"], json.loads(a["value_json"]), kind=a["kind"])
        if a["parent_id"]:
            edge(a["parent_id"], a["id"], "contains")
    asset_by_key = {a["key"]: a["id"] for a in assets}

    auths = db.query("SELECT * FROM auth_contexts WHERE engagement_id=?", (engagement_id,))
    for ac in auths:
        node(ac["id"], "auth_context", ac.get("name") or ac.get("username") or ac["id"],
             {"status": ac["status"], "username": ac.get("username")})

    intents = db.query("SELECT * FROM intents WHERE engagement_id=?", (engagement_id,))
    for i in intents:
        node(i["id"], "intent", i["objective"][:80], {"status": i["status"], "role": i["role"]},
             kind=i["status"])
        for dep in json.loads(i["depends_on_json"]):
            edge(dep, i["id"], "depends_on")
        if i.get("parent_id"):
            edge(i["parent_id"], i["id"], "delegates")

    runs = db.query("SELECT * FROM agent_runs WHERE engagement_id=?", (engagement_id,))
    for r in runs:
        node(r["id"], "agent_run", f"{r['role']} ({r['status']})",
             {"role": r["role"], "model": r["model"], "iterations": r["iterations"],
              "cost_usd": r["cost_usd"], "exit_reason": r["exit_reason"]}, kind=r["status"])
        if r["intent_id"]:
            edge(r["intent_id"], r["id"], "executed_by")

    observations = db.query("SELECT * FROM observations WHERE engagement_id=?", (engagement_id,))
    for o in observations:
        node(o["id"], "observation", o["summary"][:80], {"kind": o["kind"], "source": o["source_derived"]})
        if o["intent_id"]:
            edge(o["intent_id"], o["id"], "produced")
        if o["evidence_id"]:
            node(o["evidence_id"], "evidence", o["evidence_id"], {"kind": "artifact"})
            edge(o["id"], o["evidence_id"], "supported_by", verified=o["source_derived"] == "captured_exchange")
        if o["asset_id"]:
            edge(o["asset_id"], o["id"], "observed_on")

    hyps = db.query("SELECT * FROM hypotheses WHERE engagement_id=?", (engagement_id,))
    for h in hyps:
        node(h["id"], "hypothesis", h["statement"][:80],
             {"status": h["status"], "confidence": h["confidence"]}, kind=h["status"])
        if h["asset_id"]:
            edge(h["asset_id"], h["id"], "about")
        if h["intent_id"]:
            edge(h["intent_id"], h["id"], "raised_by")

    findings = db.query("SELECT * FROM findings WHERE engagement_id=?", (engagement_id,))
    for f in findings:
        node(f["id"], "finding", f["title"][:80],
             {"severity": f["severity"], "state": f["state"], "cwe": f["cwe"],
              "confidence": f["confidence"], "endpoint": f["endpoint"]}, kind=f["severity"])
        ep = f["endpoint"]
        if ep and ep in asset_by_key:
            edge(asset_by_key[ep], f["id"], "affects",
                 verified=f["state"] in ("validated", "reported", "retested_persists"))
        for eid in json.loads(f["evidence_ids_json"]):
            node(eid, "evidence", eid, {"kind": "artifact"})
            edge(f["id"], eid, "supported_by")

    vers = db.query("SELECT * FROM verifications WHERE finding_id IN "
                    "(SELECT id FROM findings WHERE engagement_id=?)", (engagement_id,))
    for v in vers:
        vid = f"ver_{v['id']}"
        node(vid, "verification", f"{v['verdict']} (attempt {v['attempt']})",
             {"verdict": v["verdict"], "method": v["method"], "detail": v["detail"]}, kind=v["verdict"])
        edge(v["finding_id"], vid, "verified_by", verified=v["verdict"] == "reproduced")

    retests = db.query("SELECT * FROM retests WHERE finding_id IN "
                       "(SELECT id FROM findings WHERE engagement_id=?)", (engagement_id,))
    for rt in retests:
        rid = f"rt_{rt['id']}"
        node(rid, "retest", rt["verdict"], {"verdict": rt["verdict"], "detail": rt["detail"]},
             kind=rt["verdict"])
        edge(rt["finding_id"], rid, "retested", verified=rt["verdict"] == "fixed")

    # investigation timeline (ordered steps)
    steps = db.query("SELECT * FROM investigation_steps WHERE engagement_id=? ORDER BY created_at",
                     (engagement_id,))
    timeline = [{"seq": s["seq"], "kind": s["action_kind"], "summary": s["summary"],
                 "run_id": s["agent_run_id"], "at": s["created_at"]} for s in steps]

    # coverage: assets touched by observations/findings vs total
    touched = {o["asset_id"] for o in observations if o["asset_id"]}
    touched |= {asset_by_key.get(f["endpoint"]) for f in findings if f["endpoint"] in asset_by_key}
    coverage = {"assets_total": len(assets), "assets_investigated": len(touched & set(asset_by_key.values())),
                "findings": len(findings),
                "validated": sum(1 for f in findings if f["state"] in ("validated", "reported", "retested_persists")),
                "hypotheses_open": sum(1 for h in hyps if h["status"] == "open"),
                "agent_runs": len(runs)}

    if include:
        nodes = [n for n in nodes if n["type"] in include]
        ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["source"] in ids and e["target"] in ids]
    return {"nodes": nodes, "edges": edges, "timeline": timeline, "coverage": coverage}
