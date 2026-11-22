"""Composition root + FastAPI API + SSE. Localhost-only by default, token auth."""
import json
import os
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .auth_browser import STEP_ACTIONS, AuthBrowser
from .browser_crawl import browser_available
from .db import DB, new_id
from .evidence import EvidenceStore
from .report import _write_atomic
from .findings import FindingPipeline
from .llm import LLM
from .orchestrator import MODES, Orchestrator
from . import __version__, mcp_client  # plugin/MCP extension framework

from .plugins import PluginHost
from .policy import DEFAULT_PROFILE, PROFILES
from .provider_diagnostic import normalize_base, diagnostic_result, same_base, test_connection
from .report import render_report
from .scope import Scope
from .secrets import SecretBox, is_encrypted
from .tools import Registry
from .tools.adapters import ALL_ADAPTERS
from .tools.http_probe import HttpProbe
from .tools.runner import ToolRunner
from .verifier import Verifier

# Report kinds are declared here so the API can reject an unsupported request before
# rendering anything, and the UI can discover what this build actually offers.
REPORT_KINDS = [
    {"id": "technical", "title": "Technical penetration-test report",
     "description": "Every observation with evidence, verification history, coverage and limitations.",
     "formats": ["json", "md", "pdf", "html", "docx", "xlsx", "csv", "sarif", "dojo"]},
    {"id": "executive", "title": "Executive security summary",
     "description": "Risk, verified findings and what was not tested, for a non-technical reader.",
     "formats": ["md", "html", "pdf"]},
    {"id": "coverage", "title": "Methodology and coverage report",
     "description": "WSTG test status with the reason each test was not completed.",
     "formats": ["md", "html", "pdf"]},
    {"id": "evidence", "title": "Evidence appendix",
     "description": "Hash-chain ledger of every captured artifact (metadata only, no bodies).",
     "formats": ["csv", "md", "html", "pdf"]},
    {"id": "gitlab", "title": "GitLab DAST report",
     "description": "GitLab DAST 15.0.0 JSON built from independently verified findings.",
     "formats": ["json"]},
]
REPORT_KINDS_BY_ID = {k["id"]: k for k in REPORT_KINDS}


class SPAStaticFiles(StaticFiles):
    async def get_response(self, path, scope):
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404:
                raise
            response = None
        missing = response is None or response.status_code == 404
        if missing and not scope['path'].startswith(('/api/', '/assets/')):
            return FileResponse(Path(str(self.directory)) / 'index.html', status_code=200)
        if response is None:
            raise StarletteHTTPException(status_code=404)
        return response


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

    def llm_settings(self) -> dict:
        row = self.db.one("SELECT value_json FROM settings WHERE key='llm_config'")
        return json.loads(self.box.decrypt_or_plain(row["value_json"])) if row else {}

    def llm(self) -> LLM | None:
        cfg = self.llm_settings()
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
            # a finished run must keep its truthful terminal status: an error while the
            # run was already done (e.g. rendering) is a limitation, not a failed run
            row = self.db.one("SELECT status FROM engagements WHERE id=?", (engagement_id,)) or {}
            if row.get("status") in ("done", "budget_exhausted", "cancelled", "window_closed"):
                self.db.emit(engagement_id, "degradation", {
                    "code": "post_run_error",
                    "detail": f"the run finished as {row['status']} but post-run work raised: {e}"})
                return
            self.db.execute("UPDATE engagements SET status='failed', status_detail=?, finished_at=? WHERE id=?",
                            (str(e), time.time(), engagement_id))
            self.db.emit(engagement_id, "engagement_failed", {"error": str(e)})


def _public_auth(auth: dict) -> dict:
    """Display schema for engagement auth: identity usernames only.

    auth_json also carries passwords, OpenAPI paths and operator test hints; an
    allowlist keeps every future field server-side by default.
    """
    return {"identities": [{"username": i.get("username")}
                           for i in auth.get("identities") or [] if isinstance(i, dict)]}


def _public_url(url) -> str | None:
    """Login URL without userinfo, query or fragment (tokens ride in both)."""
    try:
        p = urlparse(url or "")
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    return urlunparse((p.scheme, p.netloc.rpartition("@")[2], p.path, "", "", ""))


def _exchange_summary(row: dict) -> dict:
    """Finding-bound exchange list row: no raw request/response material."""
    return {k: row.get(k) for k in ("id", "engagement_id", "evidence_id", "method", "url",
                                    "status", "duration_ms", "tool", "peer_ip", "created_at")}


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
        profile = body.get("profile", DEFAULT_PROFILE)
        if profile not in PROFILES:
            raise HTTPException(400, f"unknown profile {profile!r}; expected one of "
                                     f"{', '.join(PROFILES)}")
        budgets = body.get("budgets", {})
        if not isinstance(budgets, dict):
            raise HTTPException(400, "budgets must be an object")
        for key in ("max_duration_s", "max_usd", "max_plan_rounds"):
            value = budgets.get(key)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                      or not value > 0):
                raise HTTPException(400, f"budget {key} must be a positive number")
        eid = new_id("eng")
        app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
            "objectives_json, window_start, window_end, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (eid, name, profile, "draft", json.dumps(scope_spec),
             app.db.seal(json.dumps(body.get("auth", {}))), json.dumps(budgets),
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
            r["auth"] = _public_auth(json.loads(r.pop("auth_json")))
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
        r["auth"] = _public_auth(json.loads(r.pop("auth_json")))
        r["standards"] = json.loads(r.pop("standards_json") or "{}")
        r["spend"] = app.llm().spend(eid) if app.llm() else {"cost_usd": 0}
        return r

    def _check_startable(mode: str, profile: str):
        """Refuse a run that cannot honour its mode or a profile the engine cannot enforce."""
        if mode not in MODES:
            raise HTTPException(400, f"unknown mode {mode!r}; expected one of {', '.join(MODES)}")
        if profile not in PROFILES:
            raise HTTPException(400, f"engagement has unknown profile {profile!r}; "
                                     f"expected one of {', '.join(PROFILES)}")
        if mode in ("llm", "agent") and app.llm() is None:
            raise HTTPException(400, f"mode {mode!r} requires a configured LLM provider; "
                                     "configure one in Settings or start in deterministic mode")

    def _check_closed_window(status: str):
        if status == "window_closed":
            raise HTTPException(409, "This assessment window closed. Its results remain available. "
                                     "Create a new engagement with an authorized window.")

    @api.post("/api/engagements/{eid}/start", dependencies=[Depends(auth)])
    def start(eid: str, body: dict | None = None):
        r = app.db.one("SELECT status, profile FROM engagements WHERE id=?", (eid,))
        if not r:
            raise HTTPException(404)
        _check_closed_window(r["status"])
        if r["status"] not in ("draft", "done", "failed", "cancelled", "budget_exhausted"):
            raise HTTPException(409, f"cannot start from status {r['status']}")
        mode = (body or {}).get("mode", "deterministic")
        _check_startable(mode, r["profile"])
        app.start_async(eid, mode)
        return {"started": True, "mode": mode}

    @api.post("/api/engagements/{eid}/pause", dependencies=[Depends(auth)])
    def pause(eid: str):
        app.orchestrator().pause(eid)
        return {"paused": True}

    @api.post("/api/engagements/{eid}/resume", dependencies=[Depends(auth)])
    def resume(eid: str, body: dict | None = None):
        r = app.db.one("SELECT status, profile FROM engagements WHERE id=?", (eid,))
        if not r:
            raise HTTPException(404)
        _check_closed_window(r["status"])
        if r["status"] not in ("draft", "paused", "failed", "cancelled", "budget_exhausted"):
            raise HTTPException(409, f"cannot resume from status {r['status']}")
        t = app._threads.get(eid)
        if t is not None and t.is_alive():
            raise HTTPException(409, "engagement worker already running")
        mode = (body or {}).get("mode", "deterministic")
        _check_startable(mode, r["profile"])
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
                f["exchanges"].append(_exchange_summary(ex))
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
        if ex.get("req_body"):
            ex["req_body"] = redact(ex["req_body"])
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

    @api.get("/api/engagements/{eid}/report/kinds", dependencies=[Depends(auth)])
    def report_kinds(eid: str):
        """What can be generated for this engagement, and in which formats."""
        if not app.db.one("SELECT id FROM engagements WHERE id=?", (eid,)):
            raise HTTPException(404)
        return {"kinds": REPORT_KINDS}

    @api.get("/api/engagements/{eid}/report", dependencies=[Depends(auth)])
    def report(eid: str, format: str = "json", kind: str = "technical"):
        if not app.db.one("SELECT id FROM engagements WHERE id=?", (eid,)):
            raise HTTPException(404)
        if kind not in REPORT_KINDS_BY_ID:
            raise HTTPException(400, f"unknown report kind {kind!r}; expected one of "
                                     f"{', '.join(REPORT_KINDS_BY_ID)}")
        if format not in REPORT_KINDS_BY_ID[kind]["formats"]:
            raise HTTPException(400, f"kind {kind!r} supports "
                                     f"{', '.join(REPORT_KINDS_BY_ID[kind]['formats'])}, not {format!r}")
        if kind != "technical":
            return _focused_report(eid, kind, format)
        try:
            res = render_report(app.db, app.evidence, eid)
        except Exception as exc:  # an unwritable output path must read as a report problem
            raise HTTPException(500, f"Report render failed: {type(exc).__name__}: {exc}. "
                                     "The previous report on disk is unchanged; fix the report "
                                     "output path, then regenerate.")
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
        if format in ("html", "docx", "xlsx", "csv"):
            from . import report_formats
            doc = json.loads((p / "report.json").read_text())
            if format == "html":
                return HTMLResponse(report_formats.render_html(doc))
            if format == "csv":
                return PlainTextResponse(report_formats.render_csv(doc), media_type="text/csv",
                                         headers={"Content-Disposition": f'attachment; filename="{eid}.csv"'})
            if format == "docx":
                path = report_formats.render_docx(doc, p / "report.docx")
                return FileResponse(path, filename=f"{eid}.docx",
                                    media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            path = report_formats.render_xlsx(doc, p / "report.xlsx")
            return FileResponse(path, filename=f"{eid}.xlsx",
                                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        return json.loads((p / "report.json").read_text())

    def _focused_report(eid: str, kind: str, format: str):
        """Executive, coverage, evidence-ledger and GitLab views of the same report."""
        from . import report_kinds

        res = render_report(app.db, app.evidence, eid)  # one source of truth, rendered first
        doc = json.loads((Path(res["outdir"]) / "report.json").read_text())
        if kind == "gitlab":
            return JSONResponse(report_kinds.gitlab_json(doc), headers={
                "Content-Disposition": f'attachment; filename="libella-{eid}-gitlab-dast.json"'})
        if kind == "evidence":
            csv_text = report_kinds.evidence_csv(app.db, eid)
            if format == "csv":
                out = Path(res["outdir"]) / "evidence.csv"
                _write_atomic(out, csv_text)
                return FileResponse(out, media_type="text/csv",
                                    filename=f"libella-{eid}-evidence.csv")
            md = ("# Evidence appendix (chain metadata)\n\n"
                  "This appendix lists the evidence ledger, not raw captured content: id, kind, "
                  "SHA-256 and chain hash, in insertion order. Bodies and headers stay redacted "
                  "in the platform and are never exported here.\n\n```csv\n"
                  + csv_text.strip() + "\n```\n")
        elif kind == "executive":
            md = report_kinds.executive_md(doc)
        else:
            md = report_kinds.coverage_md(doc)
        title = {"executive": "Executive security summary", "coverage": "Methodology and coverage",
                 "evidence": "Evidence appendix"}[kind]
        if format == "md":
            out = Path(res["outdir"]) / f"{kind}.md"
            _write_atomic(out, md)
            return FileResponse(out, media_type="text/markdown",
                                filename=f"libella-{eid}-{kind}.md")
        html = report_kinds.html_doc(f"{title} — {title}", report_kinds.md_to_html(md))
        if format == "html":
            return HTMLResponse(html)
        from .tools.browser_fetch import render_pdf
        pdf = render_pdf(html, Path(res["outdir"]) / f"{kind}.pdf")
        return FileResponse(pdf, media_type="application/pdf", filename=f"libella-{eid}-{kind}.pdf")

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

    # ---- standards coverage ledger (per-requirement accounting, no execution) ----
    from .standards import available as _standards_available

    @api.get("/api/standards", dependencies=[Depends(auth)])
    def list_standards():
        return {"standards": _standards_available()}

    @api.get("/api/engagements/{eid}/coverage/{framework}", dependencies=[Depends(auth)])
    def coverage_workspace(eid: str, framework: str = "wstg"):
        from .coverage import workspace
        try:
            return workspace(app.db, eid, framework, app.evidence)
        except KeyError as exc:  # unknown standard id
            raise HTTPException(404, f"unknown standard: {exc}") from None
        except LookupError as exc:
            raise HTTPException(404, str(exc))

    @api.put("/api/engagements/{eid}/coverage/{framework}/{requirement_id}",
             dependencies=[Depends(auth)])
    def coverage_record(eid: str, framework: str, requirement_id: str, body: dict):
        from .coverage import record
        try:
            return record(app.db, eid, requirement_id, body.get("status"), body.get("note"),
                          body.get("evidence_id"), framework)
        except LookupError as exc:  # covers KeyError for an unknown standard id
            raise HTTPException(404, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @api.post("/api/engagements/{eid}/coverage/{framework}/{requirement_id}/links",
              dependencies=[Depends(auth)])
    def coverage_link(eid: str, framework: str, requirement_id: str, body: dict):
        """Analyst correction of finding -> requirement attribution, kept as history."""
        from .coverage import link
        try:
            return link(app.db, eid, framework, requirement_id, body.get("finding_id"),
                        body.get("action"), body.get("note"))
        except LookupError as exc:
            raise HTTPException(404, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @api.put("/api/engagements/{eid}/standards", dependencies=[Depends(auth)])
    def set_standards(eid: str, body: dict):
        """Select which standards this engagement is assessed against, and their level.

        The body replaces the selection: {"asvs": {"level": 2}, "api-top10": {}}.
        A standard with verification levels needs one; a standard without levels
        must not be given one. WSTG is always reported and needs no selection.
        """
        from .standards import levels
        if not app.db.one("SELECT id FROM engagements WHERE id=?", (eid,)):
            raise HTTPException(404, "engagement not found")
        if not isinstance(body, dict):
            raise HTTPException(400, "body must map standard id to its settings")
        chosen = {}
        for framework, cfg in body.items():
            try:
                allowed = levels(framework)
            except KeyError:
                raise HTTPException(404, f"unknown standard: {framework}") from None
            level = (cfg or {}).get("level") if isinstance(cfg, dict) else None
            if allowed and level not in allowed:
                raise HTTPException(400, f"{framework} level must be one of {allowed}")
            if not allowed and level is not None:
                raise HTTPException(400, f"{framework} has no verification levels")
            chosen[framework] = {"level": level} if allowed else {}
        app.db.execute("UPDATE engagements SET standards_json=? WHERE id=?",
                       (json.dumps(chosen), eid))
        return chosen

    @api.get("/api/tools", dependencies=[Depends(auth)])
    def tools():
        return app.registry.available()

    from .routes_tools import register as register_tool_routes
    register_tool_routes(api, app, auth)

    @api.post("/api/tools/{name}/version-check", dependencies=[Depends(auth)])
    def tool_version_check(name: str):
        from .tools.diagnostics import diagnose
        # Caller picks a registered tool only; executable and arguments are server-side.
        try:
            spec = app.registry.get(name)
        except KeyError:
            raise HTTPException(404, "Tool not registered.") from None
        return diagnose(spec)

    @api.get("/api/settings", dependencies=[Depends(auth)])
    def get_settings():
        cfg = app.llm_settings()
        if cfg.get("api_key"):
            cfg["api_key"] = "[SET]"
        return {"llm": cfg}

    @api.put("/api/settings", dependencies=[Depends(auth)])
    def put_settings(body: dict):
        if "llm" in body:
            cfg = app.llm_settings()
            new = body["llm"]
            if not isinstance(new, dict) or ("base_url" in new and not isinstance(new["base_url"], str)):
                raise HTTPException(400, "Invalid provider settings.")
            if isinstance(new.get("api_key"), str):
                new["api_key"] = new["api_key"].strip()
            if new.get("api_key") in ("[SET]", "", None):
                new.pop("api_key", None)
            if "base_url" in new:
                if new["base_url"].strip():
                    try:
                        new["base_url"] = normalize_base(new["base_url"].strip())
                    except ValueError:
                        raise HTTPException(400, "Use an HTTPS base URL without credentials, a query, "
                                                 "or a fragment. Plain HTTP is allowed only for a loopback IP.") from None
                if not same_base(cfg.get("base_url"), new["base_url"]):
                    cfg.pop("api_key", None)
            cfg.update(new)
            app.db.execute("INSERT INTO settings(key, value_json) VALUES('llm_config', ?) "
                           "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                           (app.box.encrypt(json.dumps(cfg)),))
        return {"ok": True}

    # shortcut: per-process lock, so "busy" only holds with a single uvicorn worker (as tickets above).
    provider_test_lock = threading.Lock()

    @api.post("/api/settings/provider-test", dependencies=[Depends(auth)])
    async def provider_test(request: Request):
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > 8192:
                raise HTTPException(413, "Provider settings are too large.")
            raw.extend(chunk)
        try:
            draft = json.loads(raw)
        except (ValueError, RecursionError):
            raise HTTPException(400, "Invalid provider settings.") from None
        if not isinstance(draft, dict) or any(
            k not in {"base_url", "default_model", "api_key"} or not isinstance(v, str) or len(v) > 2048
            for k, v in draft.items()
        ):
            raise HTTPException(400, "Invalid provider settings.")
        if not provider_test_lock.acquire(blocking=False):
            return diagnostic_result("busy")
        try:
            return await test_connection(app.llm_settings(), draft)
        finally:
            provider_test_lock.release()

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
        flow = json.loads(row.get("login_flow_json") or "{}")
        return {**{k: row.get(k) for k in ("id", "engagement_id", "name", "username", "status",
                                           "last_verified_at", "created_at")},
                "login_flow": {"base_url": _public_url(flow.get("base_url")),
                               "login_url": _public_url(flow.get("login_url")),
                               "selectors": flow.get("selectors"),
                               "success_assertion": flow.get("success_assertion")},
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

    # target credentials: sealed at rest, tested only inside an authorized scope
    from .routes_target_auth import register as register_target_auth
    register_target_auth(api, app, auth)

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
        api.mount("/", SPAStaticFiles(directory=str(webdist), html=True), name="web")

    return api
