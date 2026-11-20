"""Composition root + FastAPI API + SSE. Localhost-only by default, token auth."""
import json
import os
import secrets
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .checks import WebChecks
from .crawl import Crawler
from .db import DB, new_id
from .evidence import EvidenceStore
from .findings import FindingPipeline
from .llm import LLM
from .orchestrator import Orchestrator
from .report import render_report
from .scope import Scope
from .tools import Registry
from .tools.adapters import ALL_ADAPTERS
from .tools.http_probe import HttpProbe
from .tools.runner import ToolRunner
from .verifier import Verifier


class App:
    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db = DB(self.data_dir / "libella.db")
        self.evidence = EvidenceStore(self.db, self.data_dir / "evidence")
        self.probe = HttpProbe(self.db, self.evidence)
        self.pipeline = FindingPipeline(self.db, self.evidence)
        self.verifier = Verifier(self.db, self.evidence, self.probe, self.pipeline)
        self.registry = Registry()
        for spec in ALL_ADAPTERS:
            self.registry.register(spec)
        self.runner = ToolRunner(self.db, self.evidence, self.data_dir / "runs")
        self._llm = None
        self._threads: dict[str, threading.Thread] = {}
        token_row = self.db.one("SELECT value_json FROM settings WHERE key='api_token'")
        if token_row:
            self.token = json.loads(token_row["value_json"])
        else:
            self.token = os.environ.get("LIBELLA_TOKEN") or secrets.token_urlsafe(24)
            self.db.execute("INSERT INTO settings(key, value_json) VALUES('api_token', ?)",
                            (json.dumps(self.token),))

    def llm(self) -> LLM | None:
        row = self.db.one("SELECT value_json FROM settings WHERE key='llm_config'")
        if not row:
            return None
        cfg = json.loads(row["value_json"])
        if not cfg.get("base_url") and not cfg.get("api_key"):
            return None
        return LLM(self.db, cfg)

    def orchestrator(self) -> Orchestrator:
        return Orchestrator(self.db, self.evidence, self.probe, self.pipeline,
                            self.verifier, self.registry, self.runner, self.llm())

    def start_async(self, engagement_id: str, mode: str):
        orch = self.orchestrator()
        t = threading.Thread(target=self._run_guarded, args=(orch, engagement_id, mode),
                             daemon=True, name=f"eng-{engagement_id}")
        self._threads[engagement_id] = t
        t.start()

    def _run_guarded(self, orch, engagement_id, mode):
        try:
            orch.start(engagement_id, mode)
        except Exception as e:
            self.db.execute("UPDATE engagements SET status='failed', status_detail=?, finished_at=? WHERE id=?",
                            (str(e), time.time(), engagement_id))
            self.db.emit(engagement_id, "engagement_failed", {"error": str(e)})


def create_api(app: App) -> FastAPI:
    api = FastAPI(title="Libella", version="0.1.0")
    api.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
                       allow_methods=["*"], allow_headers=["*"])

    def auth(request: Request):
        if request.url.path in ("/api/health", "/"):
            return
        tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        tok = tok or request.query_params.get("token", "")
        if not secrets.compare_digest(tok, app.token):
            raise HTTPException(401, "invalid token")

    @api.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.1.0", "tools": app.registry.available()}

    @api.post("/api/engagements", dependencies=[Depends(auth)])
    def create_engagement(body: dict):
        name = body.get("name")
        scope_spec = body.get("scope")
        if not name or not scope_spec:
            raise HTTPException(400, "name and scope required")
        try:
            Scope(scope_spec)  # validate fail-closed at creation
        except ValueError as e:
            raise HTTPException(400, f"invalid scope: {e}")
        eid = new_id("eng")
        app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
            "objectives_json, window_start, window_end, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (eid, name, body.get("profile", "safe_active"), "draft", json.dumps(scope_spec),
             json.dumps(body.get("auth", {})), json.dumps(body.get("budgets", {})),
             json.dumps(body.get("objectives", [])), body.get("window_start"),
             body.get("window_end"), time.time()))
        app.db.emit(eid, "engagement_created", {"name": name})
        return {"id": eid}

    @api.get("/api/engagements", dependencies=[Depends(auth)])
    def list_engagements():
        rows = app.db.query("SELECT * FROM engagements ORDER BY created_at DESC")
        for r in rows:
            r["scope"] = json.loads(r.pop("scope_json"))
            r["budgets"] = json.loads(r.pop("budgets_json"))
            r["auth"] = {"identities": [
                {k: v for k, v in i.items() if k != "password"} for i in json.loads(r.pop("auth_json")).get("identities", [])
            ]}
            r["summary"] = app.db.one(
                "SELECT COUNT(*) n FROM findings WHERE engagement_id=?", (r["id"],))["n"]
        return rows

    @api.get("/api/engagements/{eid}", dependencies=[Depends(auth)])
    def get_engagement(eid: str):
        r = app.db.one("SELECT * FROM engagements WHERE id=?", (eid,))
        if not r:
            raise HTTPException(404)
        r["scope"] = json.loads(r.pop("scope_json"))
        r["budgets"] = json.loads(r.pop("budgets_json"))
        auth = json.loads(r.pop("auth_json"))
        r["auth"] = {**auth, "identities": [
            {k: v for k, v in i.items() if k != "password"} for i in auth.get("identities", [])]}
        r["spend"] = app.llm().spend(eid) if app.llm() else {"cost_usd": 0}
        return r

    @api.post("/api/engagements/{eid}/start", dependencies=[Depends(auth)])
    def start(eid: str, body: dict | None = None):
        r = app.db.one("SELECT status FROM engagements WHERE id=?", (eid,))
        if not r:
            raise HTTPException(404)
        if r["status"] not in ("draft", "done", "failed", "cancelled", "budget_exhausted"):
            raise HTTPException(409, f"cannot start from status {r['status']}")
        mode = (body or {}).get("mode", "deterministic")
        app.start_async(eid, mode)
        return {"started": True, "mode": mode}

    @api.post("/api/engagements/{eid}/pause", dependencies=[Depends(auth)])
    def pause(eid: str):
        app.orchestrator().pause(eid)
        return {"paused": True}

    @api.post("/api/engagements/{eid}/resume", dependencies=[Depends(auth)])
    def resume(eid: str, body: dict | None = None):
        mode = (body or {}).get("mode", "deterministic")
        t = threading.Thread(target=app._run_guarded,
                             args=(app.orchestrator(), eid, mode), daemon=True)
        app.db.execute("UPDATE engagements SET status='running' WHERE id=?", (eid,))
        t.start()
        return {"resumed": True}

    @api.post("/api/engagements/{eid}/cancel", dependencies=[Depends(auth)])
    def cancel(eid: str):
        app.orchestrator().cancel(eid)
        return {"cancelled": True}

    @api.get("/api/engagements/{eid}/assets", dependencies=[Depends(auth)])
    def assets(eid: str):
        rows = app.db.query("SELECT * FROM assets WHERE engagement_id=? ORDER BY first_seen", (eid,))
        for r in rows:
            r["value"] = json.loads(r.pop("value_json"))
        return rows

    @api.get("/api/engagements/{eid}/intents", dependencies=[Depends(auth)])
    def intents(eid: str):
        rows = app.db.query("SELECT * FROM intents WHERE engagement_id=? ORDER BY created_at", (eid,))
        for r in rows:
            r["depends_on"] = json.loads(r.pop("depends_on_json"))
            r["informed_by"] = json.loads(r.pop("informed_by_json"))
            if r.get("result_json"):
                r["result"] = json.loads(r.pop("result_json"))
        return rows

    @api.get("/api/engagements/{eid}/findings", dependencies=[Depends(auth)])
    def findings(eid: str):
        return app.pipeline.list(eid)

    @api.get("/api/engagements/{eid}/observations", dependencies=[Depends(auth)])
    def observations(eid: str):
        return app.db.query("SELECT * FROM observations WHERE engagement_id=? ORDER BY created_at", (eid,))

    @api.get("/api/engagements/{eid}/tool-calls", dependencies=[Depends(auth)])
    def tool_calls(eid: str):
        rows = app.db.query("SELECT * FROM tool_calls WHERE engagement_id=? ORDER BY created_at", (eid,))
        for r in rows:
            r["argv"] = json.loads(r.pop("argv_json") or "[]")
        return rows

    @api.get("/api/engagements/{eid}/events", dependencies=[Depends(auth)])
    def events(eid: str, since: int = 0):
        rows = app.db.query(
            "SELECT * FROM events WHERE engagement_id=? AND seq>? ORDER BY seq LIMIT 500",
            (eid, since))
        for r in rows:
            r["payload"] = json.loads(r.pop("payload_json"))
        return rows

    @api.get("/api/engagements/{eid}/stream", dependencies=[Depends(auth)])
    def stream(eid: str, since: int = 0):
        def gen():
            cursor = since
            idle = 0
            while idle < 600:
                rows = app.db.query(
                    "SELECT * FROM events WHERE engagement_id=? AND seq>? ORDER BY seq LIMIT 100",
                    (eid, cursor))
                if rows:
                    idle = 0
                    for r in rows:
                        cursor = r["seq"]
                        payload = json.loads(r["payload_json"])
                        yield f"id: {cursor}\nevent: {r['kind']}\ndata: {json.dumps(payload, default=str)}\n\n"
                else:
                    idle += 1
                    yield ": keepalive\n\n"
                    time.sleep(1)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @api.get("/api/findings/{fid}", dependencies=[Depends(auth)])
    def get_finding(fid: str):
        f = app.db.one("SELECT * FROM findings WHERE id=?", (fid,))
        if not f:
            raise HTTPException(404)
        f["evidence_ids"] = json.loads(f.pop("evidence_ids_json"))
        f["verifications"] = app.db.query(
            "SELECT * FROM verifications WHERE finding_id=? ORDER BY attempt", (fid,))
        f["retests"] = app.db.query("SELECT * FROM retests WHERE finding_id=? ORDER BY created_at", (fid,))
        f["exchanges"] = []
        for eid in f["evidence_ids"]:
            ex = app.db.one("SELECT * FROM exchanges WHERE evidence_id=?", (eid,))
            if ex:
                f["exchanges"].append(ex)
        return f

    @api.post("/api/findings/{fid}/verify", dependencies=[Depends(auth)])
    def verify(fid: str):
        f = app.db.one("SELECT engagement_id FROM findings WHERE id=?", (fid,))
        if not f:
            raise HTTPException(404)
        eng = app.db.one("SELECT scope_json FROM engagements WHERE id=?", (f["engagement_id"],))
        return app.verifier.verify(f["engagement_id"], Scope(json.loads(eng["scope_json"])), fid)

    @api.post("/api/findings/{fid}/retest", dependencies=[Depends(auth)])
    def retest(fid: str):
        f = app.db.one("SELECT engagement_id FROM findings WHERE id=?", (fid,))
        if not f:
            raise HTTPException(404)
        eng = app.db.one("SELECT scope_json FROM engagements WHERE id=?", (f["engagement_id"],))
        return app.verifier.retest(f["engagement_id"], Scope(json.loads(eng["scope_json"])), fid)

    @api.post("/api/findings/{fid}/state", dependencies=[Depends(auth)])
    def set_state(fid: str, body: dict):
        try:
            app.pipeline.transition(fid, body["state"], body.get("reason", "operator decision"))
        except (ValueError, KeyError) as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    @api.get("/api/evidence/{eid}", dependencies=[Depends(auth)])
    def get_evidence(eid: str):
        row = app.db.one("SELECT * FROM evidence WHERE id=?", (eid,))
        if not row:
            raise HTTPException(404)
        try:
            data = app.evidence.read(eid)
        except ValueError as e:
            raise HTTPException(409, str(e))
        from .report import redact
        return JSONResponse({"id": eid, "kind": row["kind"], "sha256": row["sha256"],
                             "content": redact(data.decode(errors="replace"))})

    @api.get("/api/evidence/{eid}/chain", dependencies=[Depends(auth)])
    def chain(eid: str):
        row = app.db.one("SELECT engagement_id FROM evidence WHERE id=?", (eid,))
        if not row:
            raise HTTPException(404)
        return app.evidence.verify_chain(row["engagement_id"])

    @api.get("/api/exchanges/{xid}", dependencies=[Depends(auth)])
    def get_exchange(xid: str):
        ex = app.db.one("SELECT * FROM exchanges WHERE id=?", (xid,))
        if not ex:
            raise HTTPException(404)
        if ex["evidence_id"]:
            from .report import redact
            blob = app.evidence.read_json(ex["evidence_id"])
            blob["request"]["body"] = redact(blob["request"].get("body", ""))
            blob["response"]["body"] = redact(blob["response"].get("body", ""))
            ex["blob"] = blob
        return ex

    @api.get("/api/engagements/{eid}/report", dependencies=[Depends(auth)])
    def report(eid: str, format: str = "json"):
        res = render_report(app.db, app.evidence, eid)
        p = Path(res["outdir"])
        if format == "md":
            return FileResponse(p / "report.md", media_type="text/markdown")
        if format == "sarif":
            return FileResponse(p / "report.sarif", media_type="application/json")
        return json.loads((p / "report.json").read_text())

    @api.get("/api/tools", dependencies=[Depends(auth)])
    def tools():
        return app.registry.available()

    @api.get("/api/settings", dependencies=[Depends(auth)])
    def get_settings():
        row = app.db.one("SELECT value_json FROM settings WHERE key='llm_config'")
        cfg = json.loads(row["value_json"]) if row else {}
        if cfg.get("api_key"):
            cfg["api_key"] = "[SET]"
        return {"llm": cfg}

    @api.put("/api/settings", dependencies=[Depends(auth)])
    def put_settings(body: dict):
        if "llm" in body:
            existing = app.db.one("SELECT value_json FROM settings WHERE key='llm_config'")
            cfg = json.loads(existing["value_json"]) if existing else {}
            new = body["llm"]
            if new.get("api_key") in ("[SET]", "", None):
                new.pop("api_key", None)
            cfg.update(new)
            app.db.execute("INSERT INTO settings(key, value_json) VALUES('llm_config', ?) "
                           "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                           (json.dumps(cfg),))
        return {"ok": True}

    @api.get("/api/engagements/{eid}/graph", dependencies=[Depends(auth)])
    def graph(eid: str):
        assets = app.db.query("SELECT * FROM assets WHERE engagement_id=?", (eid,))
        findings = app.db.query("SELECT * FROM findings WHERE engagement_id=?", (eid,))
        intents = app.db.query("SELECT * FROM intents WHERE engagement_id=?", (eid,))
        nodes, edges = [], []
        for a in assets:
            nodes.append({"id": a["id"], "type": "asset", "kind": a["kind"], "label": a["key"],
                          "data": json.loads(a["value_json"])})
            if a["parent_id"]:
                edges.append({"source": a["parent_id"], "target": a["id"], "kind": "contains"})
        for f in findings:
            nodes.append({"id": f["id"], "type": "finding", "kind": f["severity"],
                          "label": f["title"], "data": {"state": f["state"], "endpoint": f["endpoint"]}})
            if f["endpoint"]:
                ep = app.db.one("SELECT id FROM assets WHERE engagement_id=? AND key=?",
                                (eid, f["endpoint"]))
                if ep:
                    edges.append({"source": ep["id"], "target": f["id"], "kind": "affects",
                                  "verified": f["state"] in ("validated", "reported", "retested_persists")})
        for i in intents:
            nodes.append({"id": i["id"], "type": "intent", "kind": i["status"],
                          "label": i["objective"][:80], "data": {"role": i["role"]}})
            for dep in json.loads(i["depends_on_json"]):
                edges.append({"source": dep, "target": i["id"], "kind": "depends_on"})
        return {"nodes": nodes, "edges": edges}

    # static frontend (built)
    webdist = Path(__file__).parent.parent.parent / "web" / "dist"
    if webdist.exists():
        api.mount("/", StaticFiles(directory=str(webdist), html=True), name="web")

    return api