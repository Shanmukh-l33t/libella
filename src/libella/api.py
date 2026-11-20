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

from .auth_browser import STEP_ACTIONS, AuthBrowser
from .browser_crawl import browser_available
from .db import DB, new_id
from .evidence import EvidenceStore
from .findings import FindingPipeline
from .llm import LLM
from .orchestrator import Orchestrator
from . import __version__, mcp_client  # plugin/MCP extension framework
from .plugins import PluginHost
from .report import render_report
from .scope import Scope
from .secrets import SecretBox, is_encrypted
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
        from .tools.code_adapters import SPECS as CODE_SPECS
        from .tools.container_adapters import TRIVY_IMAGE
        for spec in CODE_SPECS + [TRIVY_IMAGE]:
            self.registry.register(spec)
        self.runner = ToolRunner(self.db, self.evidence, self.data_dir / "runs")
        # ---- plugins (extension framework) ----
        self.plugins = PluginHost(
            Path(os.environ.get("LIBELLA_PLUGIN_DIR") or self.data_dir / "plugins"),
            self.registry)
        try:
            self.plugins.load()
        except OSError as e:  # a bad plugin dir must not stop the platform
            self.plugins.errors.append({"plugin": "*", "error": str(e)[:300]})
        self._llm = None
        self._threads: dict[str, threading.Thread] = {}
        self.box = SecretBox(self.data_dir)
        token_row = self.db.one("SELECT value_json FROM settings WHERE key='api_token'")
        if token_row:
            stored = json.loads(token_row["value_json"])
            self.token = self.box.decrypt_or_plain(stored)  # wrong key raises, never ciphertext
            if not is_encrypted(stored):  # unambiguous legacy plaintext: re-encrypt once
                self.db.execute("UPDATE settings SET value_json=? WHERE key='api_token'",
                                (json.dumps(self.box.encrypt(self.token)),))
        else:
            self.token = os.environ.get("LIBELLA_TOKEN") or secrets.token_urlsafe(24)
            self.db.execute("INSERT INTO settings(key, value_json) VALUES('api_token', ?)",
                            (json.dumps(self.box.encrypt(self.token)),))

    def llm(self) -> LLM | None:
        row = self.db.one("SELECT value_json FROM settings WHERE key='llm_config'")
        if not row:
            return None
        cfg = json.loads(self.box.decrypt_or_plain(row["value_json"]))
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
    api = FastAPI(title="Libella", version=__version__)
    api.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
                       allow_methods=["*"], allow_headers=["*"])

    # one-shot SSE tickets: ticket -> (exact stream path, monotonic deadline). A ticket
    # opens one engagement's stream and nothing else, so a URL that leaks cannot
    # authorize another GET route.
    # shortcut: in-process store, so tickets only work with a single uvicorn worker;
    # upgrade to an HMAC-signed ticket if the API ever runs multiple workers.
    TICKET_TTL, MAX_TICKETS = 60.0, 64
    tickets: dict[str, tuple[str, float]] = {}
    tickets_lock = threading.Lock()

    def auth(request: Request):
        if request.url.path in ("/api/health", "/"):
            return
        scheme, _, tok = request.headers.get("Authorization", "").partition(" ")
        if scheme == "Bearer" and tok and secrets.compare_digest(tok, app.token):
            return
        ticket = request.query_params.get("ticket", "")
        if ticket:
            with tickets_lock:  # pop first: a mismatched or late use burns the ticket
                target, deadline = tickets.pop(ticket, ("", 0.0))
            if request.method == "GET" and target == request.url.path and deadline > time.monotonic():
                return  # EventSource cannot set headers; ticket is single-use, 60s, one stream
        raise HTTPException(401, "invalid token")

    @api.post("/api/ticket", dependencies=[Depends(auth)])
    def issue_ticket(body: dict):
        eid = body.get("engagement_id")
        if not isinstance(eid, str) or not eid:
            raise HTTPException(400, "engagement_id required")
        now = time.monotonic()
        t = secrets.token_urlsafe(24)
        with tickets_lock:
            for k in [k for k, (_, exp) in tickets.items() if exp <= now]:
                tickets.pop(k, None)
            while len(tickets) >= MAX_TICKETS:  # bound memory; oldest ticket goes first
                tickets.pop(next(iter(tickets)))
            tickets[t] = (f"/api/engagements/{eid}/stream", now + TICKET_TTL)
        return {"ticket": t, "expires_in": int(TICKET_TTL)}

    # Public liveness probe: no tool probing, no inventory (see docs/healthcheck.md).
    @api.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

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
             app.db.seal(json.dumps(body.get("auth", {}))), json.dumps(body.get("budgets", {})),
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
        r = app.db.one("SELECT status FROM engagements WHERE id=?", (eid,))
        if not r:
            raise HTTPException(404)
        if r["status"] not in ("draft", "paused", "failed", "cancelled", "budget_exhausted"):
            raise HTTPException(409, f"cannot resume from status {r['status']}")
        t = app._threads.get(eid)
        if t is not None and t.is_alive():
            raise HTTPException(409, "engagement worker already running")
        mode = (body or {}).get("mode", "deterministic")
        t = threading.Thread(target=app._run_guarded,
                             args=(app.orchestrator(), eid, mode), daemon=True)
        app._threads[eid] = t
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

    @api.post("/api/engagements/{eid}/cloud-audit", dependencies=[Depends(auth)])
    def cloud_audit(eid: str, body: dict):
        """Read-only AWS posture run against an operator-supplied endpoint."""
        eng = app.db.one("SELECT scope_json FROM engagements WHERE id=?", (eid,))
        if not eng:
            raise HTTPException(404)
        endpoint, region = body.get("endpoint"), body.get("region")
        creds = body.get("creds")
        if creds is None and body.get("creds_ref"):
            ref = body["creds_ref"]
            if not isinstance(ref, str) or not ref or not all(c.isalnum() or c in "_-" for c in ref):
                raise HTTPException(400, "invalid creds_ref")
            raw = os.environ.get(f"LIBELLA_CLOUD_CREDS_{ref.upper()}", "").split(":")
            if len(raw) < 2:
                raise HTTPException(400, f"creds_ref '{ref}' is not configured")
            creds = {"access_key_id": raw[0], "secret_access_key": raw[1]}
            if len(raw) > 2:
                creds["session_token"] = raw[2]
        if not endpoint or not region or not creds:
            raise HTTPException(400, "endpoint, region and creds (or creds_ref) required")
        from .cloud_audit import assess_cloud
        result = assess_cloud(endpoint, region, creds, app.db, app.evidence, app.pipeline,
                              Scope(json.loads(eng["scope_json"])), eid,
                              account_id=body.get("account_id"))
        if result.get("refused"):
            raise HTTPException(403, result["reason"])
        return result

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
        except (KeyError, OSError) as e:
            raise HTTPException(404, f"evidence blob unavailable: {e}")
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
        from .report import redact, redact_headers
        try:
            ex["req_headers"] = redact_headers(json.loads(ex.pop("req_headers_json") or "{}"))
            ex["resp_headers"] = redact_headers(json.loads(ex.pop("resp_headers_json") or "{}"))
        except json.JSONDecodeError:
            ex.pop("req_headers_json", None)
            ex.pop("resp_headers_json", None)
        if ex["evidence_id"]:
            try:
                blob = app.evidence.read_json(ex["evidence_id"])
            except ValueError as e:
                raise HTTPException(409, str(e))
            except (KeyError, OSError, json.JSONDecodeError) as e:
                raise HTTPException(404, f"exchange evidence unavailable: {e}")
            blob["request"]["body"] = redact(blob["request"].get("body", ""))
            blob["response"]["body"] = redact(blob["response"].get("body", ""))
            blob["request"]["headers"] = redact_headers(blob["request"].get("headers"))
            blob["response"]["headers"] = redact_headers(blob["response"].get("headers"))
            ex["blob"] = blob
        return ex

    @api.get("/api/engagements/{eid}/report", dependencies=[Depends(auth)])
    def report(eid: str, format: str = "json"):
        if not app.db.one("SELECT id FROM engagements WHERE id=?", (eid,)):
            raise HTTPException(404)
        res = render_report(app.db, app.evidence, eid)
        p = Path(res["outdir"])
        if format == "md":
            return FileResponse(p / "report.md", media_type="text/markdown")
        if format == "sarif":
            return FileResponse(p / "report.sarif", media_type="application/json")
        if format == "pdf":
            from .report_pdf import render_pdf
            pdf = render_pdf(json.loads((p / "report.json").read_text()), p / "report.pdf")
            return FileResponse(pdf, media_type="application/pdf", filename=f"{eid}.pdf")
        if format == "dojo":
            from .export_dojo import defectdojo_export
            body = defectdojo_export(json.loads((p / "report.json").read_text()))
            return JSONResponse(body, headers={
                "Content-Disposition": f'attachment; filename="libella-{eid}-defectdojo.json"'})
        return json.loads((p / "report.json").read_text())

    # ---------------- remediation tracking + historical comparison (WS-Report) ----
    @api.post("/api/findings/{fid}/remediation", dependencies=[Depends(auth)])
    def set_finding_remediation(fid: str, body: dict):
        from .remediation import set_remediation
        try:
            return set_remediation(app.db, fid, notes=body.get("notes"), owner=body.get("owner"),
                                   fix_commit=body.get("fix_commit"), due_at=body.get("due_at"),
                                   remediation_state=body.get("remediation_state"),
                                   state=body.get("state"))
        except KeyError:
            raise HTTPException(404, "finding not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @api.get("/api/findings/{fid}/activity", dependencies=[Depends(auth)])
    def finding_activity_route(fid: str, limit: int = 50):
        from .remediation import finding_activity
        try:
            return finding_activity(app.db, fid, limit)
        except KeyError:
            raise HTTPException(404, "finding not found")

    @api.get("/api/engagements/{eid}/remediation-board", dependencies=[Depends(auth)])
    def remediation_board_route(eid: str):
        from .remediation import remediation_board
        try:
            return remediation_board(app.db, eid)
        except KeyError:
            raise HTTPException(404, "engagement not found")

    @api.get("/api/compare", dependencies=[Depends(auth)])
    def compare(a: str, b: str):
        from .remediation import compare_engagements
        try:
            return compare_engagements(app.db, a, b)
        except KeyError as exc:
            raise HTTPException(404, f"engagement not found: {exc}")

    @api.get("/api/tools", dependencies=[Depends(auth)])
    def tools():
        return app.registry.available()

    @api.get("/api/settings", dependencies=[Depends(auth)])
    def get_settings():
        row = app.db.one("SELECT value_json FROM settings WHERE key='llm_config'")
        cfg = json.loads(app.box.decrypt_or_plain(row["value_json"])) if row else {}
        if cfg.get("api_key"):
            cfg["api_key"] = "[SET]"
        return {"llm": cfg}

    @api.put("/api/settings", dependencies=[Depends(auth)])
    def put_settings(body: dict):
        if "llm" in body:
            existing = app.db.one("SELECT value_json FROM settings WHERE key='llm_config'")
            cfg = json.loads(app.box.decrypt_or_plain(existing["value_json"])) if existing else {}
            new = body["llm"]
            if new.get("api_key") in ("[SET]", "", None):
                new.pop("api_key", None)
            cfg.update(new)
            app.db.execute("INSERT INTO settings(key, value_json) VALUES('llm_config', ?) "
                           "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                           (app.box.encrypt(json.dumps(cfg)),))
        return {"ok": True}

    @api.get("/api/engagements/{eid}/graph", dependencies=[Depends(auth)])
    def graph(eid: str, include: str | None = None):
        from .graph import build_graph
        inc = set(include.split(",")) if include else None
        return build_graph(app.db, eid, include=inc)

    @api.get("/api/engagements/{eid}/agent-runs", dependencies=[Depends(auth)])
    def agent_runs(eid: str):
        return app.db.query("SELECT * FROM agent_runs WHERE engagement_id=? ORDER BY started_at", (eid,))

    @api.get("/api/engagements/{eid}/investigation", dependencies=[Depends(auth)])
    def investigation(eid: str, run_id: str | None = None):
        if run_id:
            return app.db.query("SELECT * FROM investigation_steps WHERE engagement_id=? AND agent_run_id=? ORDER BY seq", (eid, run_id))
        return app.db.query("SELECT * FROM investigation_steps WHERE engagement_id=? ORDER BY created_at", (eid,))

    @api.get("/api/engagements/{eid}/hypotheses", dependencies=[Depends(auth)])
    def hypotheses(eid: str):
        return app.db.query("SELECT * FROM hypotheses WHERE engagement_id=? ORDER BY created_at", (eid,))

    @api.get("/api/engagements/{eid}/memory", dependencies=[Depends(auth)])
    def memory(eid: str, target: str = ""):
        from . import memory as mem
        eng = app.db.one("SELECT scope_json FROM engagements WHERE id=?", (eid,))
        if not target and eng:
            tgts = json.loads(eng["scope_json"]).get("targets", [])
            target = tgts[0]["value"] if tgts else ""
        return mem.recall(app.db, target)

    @api.post("/api/engagements/{eid}/drift", dependencies=[Depends(auth)])
    def drift(eid: str):
        from . import memory as mem
        return mem.detect_drift(app.db, eid)

    # ---------------- traffic intelligence (WS-Traffic) ----------------
    from . import traffic as traffic_mod

    def _traffic_scope(engagement_id: str) -> Scope:
        eng = app.db.one("SELECT scope_json FROM engagements WHERE id=?", (engagement_id,))
        if eng is None:
            raise HTTPException(404, "engagement not found")
        return Scope(json.loads(eng["scope_json"]))

    @api.get("/api/engagements/{eid}/traffic", dependencies=[Depends(auth)])
    def traffic_search(eid: str, url: str = "", method: str = "", status: str = "",
                       tool: str = "", body_text: str = "", page: int = 1, page_size: int = 50):
        _traffic_scope(eid)
        try:
            return traffic_mod.search_exchanges(
                app.db, eid, {"url_substring": url, "method": method, "status": status,
                              "tool": tool, "body_text": body_text},
                page, page_size, evidence=app.evidence)
        except ValueError as e:
            raise HTTPException(400, f"invalid filter: {e}")

    @api.get("/api/engagements/{eid}/traffic/correlate", dependencies=[Depends(auth)])
    def traffic_correlate(eid: str):
        _traffic_scope(eid)
        return traffic_mod.correlate(app.db, eid)

    @api.post("/api/exchanges/{xid}/replay", dependencies=[Depends(auth)])
    def replay_exchange(xid: str, body: dict | None = None):
        ex = app.db.one("SELECT engagement_id FROM exchanges WHERE id=?", (xid,))
        if not ex:
            raise HTTPException(404)
        raw = (body or {}).get("overrides") or body or {}
        res = traffic_mod.replay(app.db, app.evidence, app.probe,
                                 _traffic_scope(ex["engagement_id"]), ex["engagement_id"], xid,
                                 {k: raw[k] for k in ("headers", "body") if k in raw})
        if not res.get("ok"):
            raise HTTPException(403 if str(res.get("error", "")).startswith("out_of_scope")
                                else 409, res.get("error"))
        return res

    # ---------------- authenticated browser workflows (WS-AuthBrowser) ----------------
    def _need_browser():
        if not browser_available():
            raise HTTPException(503, "playwright/chromium not installed")

    def _auth_engagement(engagement_id: str) -> Scope:
        eng = app.db.one("SELECT scope_json FROM engagements WHERE id=?", (engagement_id,))
        if eng is None:
            raise HTTPException(404, "engagement not found")
        return Scope(json.loads(eng["scope_json"]))

    def _ctx_out(row: dict) -> dict:
        """auth_contexts row without cookie values (session secrets stay server-side)."""
        return {**{k: row.get(k) for k in ("id", "engagement_id", "name", "username", "status",
                                           "last_verified_at", "created_at")},
                "login_flow": json.loads(row.get("login_flow_json") or "{}"),
                "cookie_count": len(json.loads(row.get("cookies_json") or "[]"))}

    @api.post("/api/engagements/{eid}/auth-contexts",
              dependencies=[Depends(auth), Depends(_need_browser)])
    def create_auth_context(eid: str, body: dict):
        scope = _auth_engagement(eid)
        for field in ("base_url", "login_url", "username"):
            if not body.get(field):
                raise HTTPException(400, f"{field} required")
        with AuthBrowser(app.db, app.evidence, scope, eid) as browser:
            res = browser.login_flow(body["base_url"], body["login_url"], body["username"],
                                     body.get("password", ""), body.get("selectors"),
                                     body.get("success_assertion"), name=body.get("name"))
        if not res.get("id"):
            raise HTTPException(400, res.get("reason") or "login failed")
        row = app.db.one("SELECT * FROM auth_contexts WHERE id=?", (res["id"],))
        return {**_ctx_out(row), "evidence_id": res["evidence_id"], "reason": res["reason"]}

    @api.get("/api/engagements/{eid}/auth-contexts", dependencies=[Depends(auth)])
    def list_auth_contexts(eid: str):
        _auth_engagement(eid)
        return [_ctx_out(r) for r in app.db.query(
            "SELECT * FROM auth_contexts WHERE engagement_id=? ORDER BY created_at", (eid,))]

    @api.post("/api/auth-contexts/{aid}/verify",
              dependencies=[Depends(auth), Depends(_need_browser)])
    def verify_auth_context(aid: str):
        row = app.db.one("SELECT * FROM auth_contexts WHERE id=?", (aid,))
        if not row:
            raise HTTPException(404)
        scope = _auth_engagement(row["engagement_id"])
        with AuthBrowser(app.db, app.evidence, scope, row["engagement_id"]) as browser:
            res = browser.verify(row)
        return {**res, "context": _ctx_out(
            app.db.one("SELECT * FROM auth_contexts WHERE id=?", (aid,)))}

    @api.post("/api/engagements/{eid}/workflows", dependencies=[Depends(auth)])
    def create_workflow(eid: str, body: dict):
        _auth_engagement(eid)
        steps = body.get("steps")
        if not isinstance(steps, list) or not steps:
            raise HTTPException(400, "steps must be a non-empty list")
        if not all(isinstance(s, dict) for s in steps):
            raise HTTPException(400, "each step must be an object")
        bad = sorted({str(s.get("action")) for s in steps if s.get("action") not in STEP_ACTIONS})
        if bad:
            raise HTTPException(400, f"unknown actions: {bad}")
        aid = body.get("auth_context_id")
        if aid and not app.db.one(
                "SELECT id FROM auth_contexts WHERE id=? AND engagement_id=?", (aid, eid)):
            raise HTTPException(404, "auth context not found")
        wid = new_id("wf")
        name = body.get("name") or "workflow"
        app.db.execute(
            "INSERT INTO workflows(id, engagement_id, name, auth_context_id, steps_json, status, "
            "created_at) VALUES(?,?,?,?,?,?,?)",
            (wid, eid, name, aid, json.dumps(steps), "draft", time.time()))
        return {"id": wid, "engagement_id": eid, "name": name, "auth_context_id": aid,
                "steps": steps, "status": "draft"}

    @api.post("/api/workflows/{wid}/run",
              dependencies=[Depends(auth), Depends(_need_browser)])
    def run_workflow(wid: str):
        wf = app.db.one("SELECT * FROM workflows WHERE id=?", (wid,))
        if not wf:
            raise HTTPException(404)
        scope = _auth_engagement(wf["engagement_id"])
        ctx = app.db.one("SELECT * FROM auth_contexts WHERE id=?",
                         (wf["auth_context_id"],)) if wf["auth_context_id"] else None
        with AuthBrowser(app.db, app.evidence, scope, wf["engagement_id"]) as browser:
            res = browser.run_workflow(json.loads(wf["steps_json"] or "[]"), ctx)
        status = "passed" if res.get("ok") else "failed"
        app.db.execute("UPDATE workflows SET status=? WHERE id=?", (status, wid))
        return {**res, "workflow": {"id": wid, "status": status}}

    # ---- plugins + external MCP servers (extension framework) ----
    @api.get("/api/plugins", dependencies=[Depends(auth)])
    def plugins():
        return app.plugins.status()

    @api.post("/api/plugins/reload", dependencies=[Depends(auth)])
    def plugins_reload():
        return app.plugins.load()

    @api.get("/api/mcp/servers", dependencies=[Depends(auth)])
    def mcp_servers():
        out = []
        for conf in mcp_client.load_servers(app.db):
            with mcp_client.McpClient(conf, timeout=5) as client:
                out.append(client.health())
        return out

    @api.post("/api/mcp/servers", dependencies=[Depends(auth)])
    def mcp_register(body: dict):
        try:
            conf = mcp_client.register_server(app.db, body)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return conf

    @api.get("/api/mcp/{server}/tools", dependencies=[Depends(auth)])
    def mcp_tools(server: str):
        conf = mcp_client.find_server(app.db, server)
        if not conf:
            raise HTTPException(404, "unknown MCP server")
        with mcp_client.McpClient(conf, timeout=10) as client:
            try:
                specs = mcp_client.to_specs(client)
            except mcp_client.McpError as e:  # absent server degrades, never 500s
                return {"server": server, "available": False,
                        "error": str(e)[:300], "tools": []}
        return {"server": server, "available": True,
                "tools": [s.schema() for s in specs]}

    # static frontend (built). Resolve robustly: env override, container path,
    # then source-tree relative (pip-installed packages live in site-packages,
    # so __file__-relative alone breaks in the image).
    webdist = None
    env_dist = os.environ.get("LIBELLA_WEB_DIST")
    candidates = ([Path(env_dist)] if env_dist else []) + [
        Path("/app/web/dist"),
        Path(__file__).parent.parent.parent / "web" / "dist",
    ]
    for p in candidates:
        if p.is_dir() and (p / "index.html").exists():
            webdist = p
            break
    if webdist:
        api.mount("/", StaticFiles(directory=str(webdist), html=True), name="web")

    return api
