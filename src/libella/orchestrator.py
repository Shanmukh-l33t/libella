"""Orchestrator: supervisor planner + leased worker intents.

Two planner modes:
  deterministic - code emits the standard assessment plan (works offline,
                  reproducible, used for benchmarks)
  llm           - model proposes typed intent deltas through a compile gate

Workers claim intents with a fencing token + lease; expired leases return
to the frontier. Budgets, pause, cancel and degradation are enforced here,
not in prompts.
"""
import json
import threading
import time
import uuid
from contextlib import contextmanager

from .assessment_window import window_state
from .checks import WebChecks
from .crawl import Crawler
from .db import DB, new_id
from .evidence import EvidenceStore
from .findings import FindingPipeline
from .llm import LLM, LLMError
from .policy import DEFAULT_PROFILE, permits
from .scope import Scope
from .tools import Registry
from .tools.adapters import NMAP_MAX_RATE, NUCLEI_MAX_RATE, PARSERS
from .tools.http_probe import HttpProbe
from .tools.runner import ToolRunner
from .verifier import Verifier

LEASE_S = 120
MODES = ("deterministic", "llm", "agent")
ROLES = {"recon", "crawl", "web_checks", "nuclei_scan", "infra_scan", "verify", "report",
         "code_audit", "api_audit", "container_scan", "graphql_audit",
         "jwt_audit", "oauth_audit", "session_audit", "privesc_audit",
         "injection_audit", "web_protocol_audit", "impact_proof"}


class ConcurrencyGate:
    """Bounded admission shared by intent execution (scope.max_concurrency is a ceiling)."""

    def __init__(self, limit: int):
        self.limit = max(1, int(limit))
        self._sem = threading.BoundedSemaphore(self.limit)

    @contextmanager
    def slot(self):
        self._sem.acquire()
        try:
            yield
        finally:
            self._sem.release()


def _object_collections(checks, endpoints, base: str, cookie_header: str = "") -> list[str]:
    """Discovered collections that serve an object by id, found by asking, not by name.

    A collection is a discovered path (no query) that answers one bare request and then a
    single-record document at ``/<n>``. The suffix is not assumed: it is whatever the
    first probe shows, so ``/api/orders`` and ``/rest/invoices`` are treated alike.
    """
    out = []
    root = base.rstrip("/")
    for ep in endpoints:
        if "?" in ep or not ep.startswith(root) or ep.rstrip("/") == root:
            continue
        if ep.endswith((".js", ".css", ".ico", ".png", ".jpg", ".svg", ".json")):
            continue
        # A collection is recognised from its own listing, not from a guessed id: probing
        # "/1" fails on any dataset whose ids do not start at 1 (measured: invoices 5001..),
        # and a collection that needs a session answers 401 anonymously, which looked
        # exactly like "this route does not exist".
        headers = {"Cookie": cookie_header} if cookie_header else None
        r = checks._req(ep, headers=headers, tool="collection_probe")
        if r.get("ok") and r["status"] == 200 and checks.is_collection(r["body"]):
            out.append(ep)
    return out


def _looks_like_one_record(body: str) -> bool:
    """A single JSON object (not a list, not an HTML page) is an object resource."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return False
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return True
    return isinstance(data, dict) and bool(data)


def _declared_rate(scope: Scope, ceiling: int) -> int:
    """Pass the declared rate, clamped to the tool's own conservative ceiling."""
    return max(1, min(ceiling, int(scope.rate_limit_rps)))


class Orchestrator:
    def __init__(self, db: DB, evidence: EvidenceStore, probe: HttpProbe,
                 pipeline: FindingPipeline, verifier: Verifier, registry: Registry,
                 runner: ToolRunner, llm: LLM | None = None):
        self.db = db
        self.evidence = evidence
        self.probe = probe
        self.pipeline = pipeline
        self.verifier = verifier
        self.registry = registry
        self.runner = runner
        self.llm = llm
        # one limiter per engagement, shared with the probe, so HTTP requests and
        # external tool launches together honor scope.rate_limit_rps
        self.runner.limiter = probe._limiter
        # a serial loop still runs one intent at a time; the gate is the ceiling
        # max_concurrency imposes on any concurrent executor (tools, workers).
        self.gate = ConcurrencyGate(1)

    # ---- engagement control ----

    def start(self, engagement_id: str, mode: str = "deterministic"):
        eng = self.db.one("SELECT * FROM engagements WHERE id=?", (engagement_id,))
        if eng is None:
            raise KeyError(engagement_id)
        self._check_mode(mode)
        scope = Scope(json.loads(eng["scope_json"]))
        if not self._window_allows(engagement_id, eng):
            return
        self.gate = self._gate_for(scope)
        # A continuation ('paused', or 'running' left behind by a crashed worker) must resume
        # the existing plan; a deliberate run from 'done'/'failed'/'draft' is a fresh plan.
        # This distinction has to be read BEFORE the status is updated below, and /resume
        # must not pre-flip it (it used to, which made every continuation look fresh).
        continuation = eng["status"] in ("paused", "running")
        self.db.execute("UPDATE engagements SET status='running', started_at=? WHERE id=?",
                        (time.time(), engagement_id))
        self.db.emit(engagement_id, "engagement_started", {"mode": mode})
        # Re-planning on every start duplicated the whole intent set per restart (in every
        # mode), which also defeated the duplicate-work guard: it compares against intents
        # already marked done, so a clone of a still-open intent read as new work.
        resumed = self._reopen_unfinished(engagement_id) if continuation else False
        if not resumed:
            if mode == "agent":
                self._plan_agent(engagement_id, scope, eng)
            else:
                self._plan_deterministic(engagement_id, scope, eng)
                if mode == "llm":
                    self._plan_llm(engagement_id, scope, eng)
        self._run_loop(engagement_id, scope, eng, mode)

    def _reopen_unfinished(self, engagement_id: str) -> bool:
        """True when the engagement already has planned work: resume, do not replan.

        "Published" is the test, not "unfinished". A restart must continue an existing plan
        whatever state its intents are in, because the alternative is cloning the whole plan
        and paying for a second investigation. Two cases make this subtle:

        * A run killed mid-flight leaves intents 'running' (re-opened below, since the
          claim token belongs to a dead worker) and possibly 'blocked'.
        * A run that FAILED leaves every intent 'blocked' (agent_run_failed, provider
          outage). There is then no open intent at all, and an earlier version of this gate
          treated that as "nothing planned" and replanned: measured 6 intents -> 12.

        Only a run that produced NO intents is a fresh plan. A blocker that was not the
        worker dying is still independent of intent status: a resume must not re-run work
        a policy refusal or an inclusive target wall genuinely blocked, so 'blocked' stays
        blocked and only the dead worker's leases are reopened.
        """
        published = self.db.query(
            "SELECT id FROM intents WHERE engagement_id=? AND status != 'stopped'",
            (engagement_id,))
        if not published:
            return False
        self.db.execute(
            "UPDATE intents SET status='open', claim_token=NULL, finished_at=NULL "
            "WHERE engagement_id=? AND status='running'", (engagement_id,))
        self.db.emit(engagement_id, "plan_resumed",
                     {"planned_intents": len(published),
                      "detail": f"{len(published)} intent(s) already planned: continuing the "
                                f"existing plan instead of cloning it"})
        return True

    def _check_mode(self, mode: str):
        """Refuse a run that cannot be what it claims (no silent deterministic fallback)."""
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}; expected one of {', '.join(MODES)}")
        if mode in ("llm", "agent") and self.llm is None:
            raise ValueError(f"mode {mode!r} requires a configured LLM provider; configure one "
                             "in Settings or start in deterministic mode")

    def cancel(self, engagement_id: str):
        from . import specialists
        self.db.execute("UPDATE engagements SET status='cancelled', finished_at=? WHERE id=?",
                        (time.time(), engagement_id))
        self.db.execute("UPDATE intents SET status='stopped' WHERE engagement_id=? AND status IN ('open','running')",
                        (engagement_id,))
        specialists.cancel_running(self.db, engagement_id)
        self.db.emit(engagement_id, "engagement_cancelled", {})

    def pause(self, engagement_id: str):
        self.db.execute("UPDATE engagements SET status='paused' WHERE id=?", (engagement_id,))
        self.db.emit(engagement_id, "engagement_paused", {})

    def resume(self, engagement_id: str, mode: str = "deterministic"):
        from . import specialists
        eng = self.db.one("SELECT * FROM engagements WHERE id=?", (engagement_id,))
        self._check_mode(mode)
        scope = Scope(json.loads(eng["scope_json"]))
        if not self._window_allows(engagement_id, eng):
            return
        self.gate = self._gate_for(scope)
        self.db.execute("UPDATE engagements SET status='running' WHERE id=?", (engagement_id,))
        self.db.emit(engagement_id, "engagement_resumed", {"mode": mode})
        # a specialist left 'running' by the interrupted run is re-opened like the
        # intents whose expired leases _run_loop sweeps; the claim token still fences
        # the dead worker out
        specialists.reopen_running(self.db, engagement_id)
        self._run_loop(engagement_id, scope, eng, mode)

    def _window_allows(self, engagement_id: str, eng: dict) -> bool:
        """Refuse to start/resume outside the authorized window; malformed fails closed."""
        try:
            ok, detail = window_state(eng)
        except ValueError as e:
            ok, detail = False, f"invalid assessment window: {e}"
        if ok:
            return True
        self.db.execute(
            "UPDATE engagements SET status='failed', status_detail=?, finished_at=? WHERE id=?",
            (detail, time.time(), engagement_id))
        self.db.emit(engagement_id, "engagement_refused", {"reason": detail})
        return False

    def _gate_for(self, scope: Scope) -> ConcurrencyGate:
        return ConcurrencyGate(scope.max_concurrency)

    # ---- policy ----

    def _profile(self, engagement_id: str) -> str:
        row = self.db.one("SELECT profile FROM engagements WHERE id=?", (engagement_id,))
        return (row or {}).get("profile") or DEFAULT_PROFILE

    def _policy_skip(self, engagement_id: str, unit: str, profile: str,
                     intent_id: str | None = None):
        """Skipped work is never silent: it lands in the report's limitations."""
        payload = {"code": "policy_restriction", "unit": unit,
                   "detail": f"{unit} needs a higher assessment profile than "
                             f"{profile!r}: policy restriction"}
        if intent_id:
            payload["intent_id"] = intent_id
        self.db.emit(engagement_id, "degradation", payload)

    # ---- planning ----

    def _add_intent(self, engagement_id, role, objective, depends=None, informed=None, assets=None):
        profile = self._profile(engagement_id)
        if not permits(role, profile):
            from . import specialists
            # a registered specialist is a schedulable role; its charter's own
            # capabilities are policy-checked when it is executed
            if specialists.get(self.db, engagement_id, role) is None:
                self._policy_skip(engagement_id, role, profile)
                return None
        iid = new_id("i")
        self.db.execute(
            "INSERT INTO intents(id, engagement_id, role, objective, status, depends_on_json, "
            "informed_by_json, asset_ids_json, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (iid, engagement_id, role, objective, "open",
             json.dumps([d for d in (depends or []) if d]),
             json.dumps(informed or []), json.dumps(assets or []), time.time()),
        )
        self.db.emit(engagement_id, "intent_created", {"intent_id": iid, "role": role,
                                                        "objective": objective})
        return iid

    def _plan_deterministic(self, engagement_id: str, scope: Scope, eng: dict):
        targets = json.loads(eng["scope_json"])["targets"]
        urls = [t["value"] for t in targets if t["kind"] == "url"]
        domains = [t["value"] for t in targets if t["kind"] == "domain"]
        recon_ids = []
        for u in urls:
            recon_ids.append(self._add_intent(engagement_id, "recon", f"Fingerprint and probe {u}"))
        for d in domains:
            self._add_intent(engagement_id, "recon", f"Passive subdomain discovery for {d}")
        crawl_ids, check_ids, audit_ids = [], [], []
        if "web" in scope.categories:
            crawl_ids = [self._add_intent(engagement_id, "crawl", f"Crawl {u}", depends=recon_ids)
                         for u in urls]
            check_ids = [self._add_intent(engagement_id, "web_checks", f"Web security checks on {u}",
                                          depends=crawl_ids) for u in urls]
            for u in urls:
                audit_ids.append(self._add_intent(engagement_id, "nuclei_scan",
                                                  f"Template scan {u}", depends=recon_ids))
        for u in urls:
            if u.startswith("https://"):
                audit_ids.append(self._add_intent(engagement_id, "infra_scan",
                                                  f"TLS and service audit {u}", depends=recon_ids))
        auth = json.loads(eng["auth_json"])
        if auth.get("openapi") and urls:
            audit_ids.append(self._add_intent(engagement_id, "api_audit",
                                              f"OpenAPI-driven API audit {urls[0]}", depends=recon_ids))
        if ((auth.get("test_hints") or {}).get("jwt")) and urls:
            audit_ids.append(self._add_intent(engagement_id, "jwt_audit",
                                              "Self-contained token attacks on the declared verifier",
                                              depends=recon_ids))
        if auth.get("oauth") and urls:
            audit_ids.append(self._add_intent(engagement_id, "oauth_audit",
                                              f"OAuth client audit {auth['oauth']}",
                                              depends=recon_ids))
        if auth.get("session") and urls:
            audit_ids.append(self._add_intent(engagement_id, "session_audit",
                                              "Session lifecycle audit for the declared identity",
                                              depends=recon_ids))
        if len(auth.get("identities") or []) >= 2 and urls:
            audit_ids.append(self._add_intent(engagement_id, "privesc_audit",
                                              "Role matrix across the declared identities",
                                              depends=recon_ids))
        hints = auth.get("test_hints") or {}
        if (hints.get("injection") or {}).get("targets") and urls:
            audit_ids.append(self._add_intent(engagement_id, "injection_audit",
                                              "Injection depth on the declared parameters",
                                              depends=recon_ids))
        if hints.get("web_protocol") and urls:
            audit_ids.append(self._add_intent(engagement_id, "web_protocol_audit",
                                              "Web protocol attacks on the declared endpoint",
                                              depends=recon_ids))
        if auth.get("graphql"):
            audit_ids.append(self._add_intent(engagement_id, "graphql_audit",
                                              f"GraphQL audit {auth['graphql']}", depends=recon_ids))
        for t in targets:
            if t["kind"] == "repo":
                audit_ids.append(self._add_intent(engagement_id, "code_audit",
                                                  f"Source and supply-chain audit {t['value']}"))
            if t["kind"] == "image":
                audit_ids.append(self._add_intent(engagement_id, "container_scan",
                                                  f"Container image scan {t['value']}"))
        # verify must wait for EVERY finding-producing intent; report waits for verify
        verify_id = self._add_intent(engagement_id, "verify",
                                     "Independently verify all candidate findings",
                                     depends=check_ids + audit_ids)
        # impact proof is a SEPARATE dimension: verified means reproduced, not "impact
        # demonstrated". It runs only when the operator authorizes a lab.
        report_deps = [verify_id]
        if ((auth.get("test_hints") or {}).get("impact_proof") or {}).get("lab") is True:
            report_deps.append(self._add_intent(
                engagement_id, "impact_proof",
                "Demonstrate impact for validated findings (authorized lab)",
                depends=[verify_id]))
        self._add_intent(engagement_id, "report", "Render assessment report",
                         depends=report_deps)

    def _plan_llm(self, engagement_id: str, scope: Scope, eng: dict):
        """LLM proposes additional intents; compile gate validates before write."""
        state = self._state_projection(engagement_id)
        system = (
            "You are the planning agent of an authorized penetration test. "
            + scope.prompt_block()
            + "\nPropose ADDITIONAL investigation intents as JSON: "
              '{"intents":[{"role":"recon|crawl|web_checks|nuclei_scan|infra_scan","objective":"...",'
              '"target":"<in-scope url or host>"}]}. Max 4. Only propose work not already covered. '
              'If the existing intents and findings already cover the attack surface, return '
              '{"intents":[]} and stop. Objectives must be specific and testable. '
              "Do not propose destructive actions."
        )
        try:
            out = self.llm.complete("planner", system, json.dumps(state), engagement_id,
                                    json_schema={"type": "object"})
        except LLMError as e:
            self.db.emit(engagement_id, "degradation", {"code": "llm_planner_failed", "detail": str(e)})
            return
        for it in (out.get("parsed") or {}).get("intents", [])[:4]:
            role = it.get("role")
            target = it.get("target", "")
            objective = it.get("objective", "")
            if role not in ROLES - {"verify", "report"} or not objective:
                self.db.emit(engagement_id, "compile_reject", {"intent": it, "reason": "bad role/objective"})
                continue
            if target:
                if "://" in target:
                    d = scope.check_url(target)
                else:
                    host, _, port = target.partition(":")
                    d = scope.check_host_port(host, int(port) if port.isdigit() else 0)
                if not d.allowed:
                    self.db.emit(engagement_id, "compile_reject",
                                 {"intent": it, "reason": f"out of scope: {d.reason}"})
                    continue
            self._add_intent(engagement_id, role, objective[:500])

    def _plan_agent(self, engagement_id: str, scope: Scope, eng: dict):
        """LLM planner decomposes the engagement into specialist intents (gated).
        Falls back to the deterministic plan on failure. verify/report always added."""
        targets = json.loads(eng["scope_json"])["targets"]
        objectives = json.loads(eng["objectives_json"]) if eng.get("objectives_json") else []
        state = {"targets": targets, "objectives": objectives,
                 "categories": sorted(scope.categories),
                 "auth_identities": len(json.loads(eng["auth_json"]).get("identities", []))}
        system = (
            "You are the Assessment Planning agent for an authorized penetration test. "
            + scope.prompt_block()
            + "\nDecompose the engagement into specialist investigation intents. JSON only: "
              '{"intents":[{"role":"recon|web|api|authz|infra|correlator|risk","objective":"...","target":"<in-scope url/host>"}]}. '
              "Start with recon. Assign web/api/authz/infra specialists to the relevant targets. "
              "Objectives must be specific, testable, and within scope. Max 8 intents. "
              "Do not plan destructive actions or expand scope."
        )
        planned = []
        if self.llm:
            try:
                out = self.llm.complete("planner", system, json.dumps(state), engagement_id,
                                        json_schema={"type": "object"})
                for it in (out.get("parsed") or {}).get("intents", [])[:8]:
                    role = it.get("role")
                    obj = it.get("objective", "")
                    target = it.get("target", "")
                    if role not in ("recon", "web", "api", "authz", "infra", "correlator", "risk") or not obj:
                        self.db.emit(engagement_id, "compile_reject", {"intent": it, "reason": "bad role/objective"})
                        continue
                    if target:
                        d = scope.check_url(target) if "://" in target else scope.check_host_port(target, 0)
                        if not d.allowed:
                            self.db.emit(engagement_id, "compile_reject",
                                         {"intent": it, "reason": f"out of scope: {d.reason}"})
                            continue
                    planned.append(self._add_intent(engagement_id, role, obj[:500]))
            except LLMError as e:
                self.db.emit(engagement_id, "degradation", {"code": "agent_planner_failed", "detail": str(e)})
        planned = [i for i in planned if i]
        if not planned:
            # fallback: deterministic plan provides the specialist intents, visibly
            self.db.emit(engagement_id, "degradation",
                         {"code": "agent_plan_fallback",
                          "detail": "no specialist intents were planned; fell back to the "
                                    "deterministic pipeline"})
            self._plan_deterministic(engagement_id, scope, eng)
            return
        verify_id = self._add_intent(engagement_id, "verify",
                                     "Independently verify all candidate findings", depends=planned)
        self._add_intent(engagement_id, "report", "Render assessment report", depends=[verify_id])

    def _state_projection(self, engagement_id: str) -> dict:
        intents = self.db.query(
            "SELECT role, objective, status FROM intents WHERE engagement_id=? ORDER BY created_at DESC LIMIT 30",
            (engagement_id,))
        findings = self.db.query(
            "SELECT title, severity, state, endpoint FROM findings WHERE engagement_id=? LIMIT 30",
            (engagement_id,))
        assets = self.db.query(
            "SELECT kind, key FROM assets WHERE engagement_id=? LIMIT 50", (engagement_id,))
        return {"intents": intents, "findings": findings, "assets": assets}

    # ---- execution loop ----

    def _run_loop(self, engagement_id: str, scope: Scope, eng: dict, mode: str):
        budgets = json.loads(eng["budgets_json"])
        deadline = time.time() + budgets.get("max_duration_s", 3600)
        max_usd = budgets.get("max_usd", 10.0)
        max_plan_rounds = int(budgets.get("max_plan_rounds", 3))
        plan_rounds = 0
        while True:
            status = self.db.one("SELECT status FROM engagements WHERE id=?",
                                 (engagement_id,))["status"]
            if status in ("cancelled", "paused", "done", "failed", "window_closed"):
                return
            try:
                may_run, window_detail = window_state(eng)
            except ValueError as e:
                may_run, window_detail = False, f"invalid assessment window: {e}"
            if not may_run:
                self._finish(engagement_id, "window_closed", window_detail)
                return
            if time.time() > deadline:
                self._finish(engagement_id, "budget_exhausted", "max_duration_s reached")
                return
            if self.llm:
                spend = self.llm.spend(engagement_id)
                if spend["cost_usd"] >= max_usd:
                    self._finish(engagement_id, "budget_exhausted", "max_usd reached")
                    return
            self._sweep_leases(engagement_id)
            intent = self._claim_next(engagement_id)
            if intent is None:
                if mode == "llm" and self.llm and plan_rounds < max_plan_rounds:
                    plan_rounds += 1
                    self._plan_llm(engagement_id, scope, eng)
                    intent = self._claim_next(engagement_id)
                if intent is None:
                    self._finish(engagement_id, "done", "all intents resolved")
                    return
            try:
                with self.gate.slot():
                    status, result = self._execute(engagement_id, scope, eng, intent, mode)
                if self._paused(engagement_id):
                    # a pause interrupts in-flight work: re-open the intent so resume
                    # redoes it instead of recording a partial step as done
                    self.db.execute(
                        "UPDATE intents SET status='open', claim_token=NULL, finished_at=NULL, "
                        "result_json=NULL WHERE id=? AND claim_token=?",
                        (intent["id"], intent.get("claim_token")))
                    return
                if self._complete(intent, status, result) and status == "done":
                    self.db.emit(engagement_id, "intent_done", {"intent_id": intent["id"]})
            except Exception as e:
                if self._complete(intent, "blocked", {"error": str(e)}):
                    self.db.emit(engagement_id, "degradation",
                                 {"code": "intent_blocked", "intent_id": intent["id"], "detail": str(e)})

    def _complete(self, intent: dict, status: str, result: dict | None = None) -> bool:
        """Finish an intent only while this worker still holds its lease (fencing).

        A worker whose lease expired and was re-claimed must not overwrite the
        new owner's state.
        """
        cur = self.db.execute(
            "UPDATE intents SET status=?, finished_at=?, result_json=? WHERE id=? AND claim_token=?",
            (status, time.time(), json.dumps(result) if result is not None else None,
             intent["id"], intent.get("claim_token")))
        if not cur.rowcount:
            self.db.emit(intent["engagement_id"], "lease_lost",
                         {"intent_id": intent["id"], "rejected_status": status})
            return False
        return True

    def _claim_next(self, engagement_id: str):
        rows = self.db.query(
            "SELECT * FROM intents WHERE engagement_id=? AND status='open' ORDER BY created_at",
            (engagement_id,))
        for it in rows:
            deps = json.loads(it["depends_on_json"])
            if deps:
                done = {r["id"] for r in self.db.query(
                    "SELECT id FROM intents WHERE engagement_id=? AND status IN ('done','blocked','exhausted','stopped')",
                    (engagement_id,))}
                if not set(deps) <= done:
                    continue
            token = uuid.uuid4().hex
            cur = self.db.execute(
                "UPDATE intents SET status='running', claim_token=?, lease_expires=?, attempts=attempts+1 "
                "WHERE id=? AND status='open'",
                (token, time.time() + LEASE_S, it["id"]))
            if cur.rowcount:
                it["claim_token"] = token
                return it
        return None

    def _paused(self, engagement_id: str) -> bool:
        row = self.db.one("SELECT status FROM engagements WHERE id=?", (engagement_id,))
        return bool(row) and row["status"] == "paused"

    def _sweep_leases(self, engagement_id: str):
        self.db.execute(
            "UPDATE intents SET status='open', claim_token=NULL WHERE engagement_id=? "
            "AND status='running' AND lease_expires < ?",
            (engagement_id, time.time()))

    def _finish(self, engagement_id: str, status: str, detail: str):
        from . import specialists
        self.db.execute("UPDATE engagements SET status=?, finished_at=?, status_detail=? WHERE id=?",
                        (status, time.time(), detail, engagement_id))
        self.db.emit(engagement_id, "engagement_finished", {"status": status, "detail": detail})
        # a specialist registered but never reached by this run expires with it
        specialists.expire_unrun(self.db, engagement_id)
        # A terminal engagement must not carry a dead worker's bookkeeping: an unsettled
        # reservation keeps counting against max_usd, and an agent run left 'running' makes
        # a finished investigation look like it is still in flight.
        leaked = self.db.execute(
            "UPDATE budget_ledger SET state='released', settled_at=? "
            "WHERE engagement_id=? AND state='reserved'", (time.time(), engagement_id)).rowcount
        orphaned = self.db.execute(
            "UPDATE agent_runs SET status='interrupted', finished_at=? "
            "WHERE engagement_id=? AND status='running'", (time.time(), engagement_id)).rowcount
        if leaked or orphaned:
            self.db.emit(engagement_id, "worker_state_released",
                         {"reservations_released": leaked, "agent_runs_interrupted": orphaned,
                          "detail": "leftovers of a worker that did not finish were closed at "
                                    "termination so the ledger counts no phantom spend and no "
                                    "investigation reads as still running"})
        if status in ("done", "budget_exhausted", "window_closed"):
            # independent verification + report always run at termination, so findings
            # are validated and reported even if the investigation budget capped early.
            # A closed window forbids further target traffic: report only, no replays.
            try:
                eng = self.db.one("SELECT scope_json FROM engagements WHERE id=?", (engagement_id,))
                scope = Scope(json.loads(eng["scope_json"]))
                cands = self.db.query(
                    "SELECT id FROM findings WHERE engagement_id=? AND state IN ('suspected','observed')",
                    (engagement_id,))
                if status == "window_closed" and cands:
                    self.db.emit(engagement_id, "degradation", {
                        "code": "verification_skipped_window_closed",
                        "detail": f"{len(cands)} candidate(s) left unverified: the authorized window closed"})
                    cands = []
                for f in cands:
                    try:
                        self.verifier.verify(engagement_id, scope, f["id"])
                    except Exception as e:
                        self.db.emit(engagement_id, "degradation",
                                     {"code": "verify_failed", "finding_id": f["id"], "detail": str(e)})
            except Exception as e:
                self.db.emit(engagement_id, "degradation", {"code": "finish_verify_error", "detail": str(e)})
            from .report import render_report
            render_report(self.db, self.evidence, engagement_id)
            from . import memory as mem
            mem.record_facts(self.db, engagement_id)

    # ---- intent execution ----

    def _execute(self, engagement_id: str, scope: Scope, eng: dict, intent: dict,
                 mode: str = "deterministic") -> tuple[str, dict]:
        """Run one intent; return (intent status, result) so the caller records it honestly."""
        from . import specialists
        from .agent_runtime import AgentRunner, CHARTERS
        role = intent["role"]
        obj = intent["objective"]
        result: dict = {}
        profile = eng.get("profile") or DEFAULT_PROFILE
        specialist = None
        if role not in CHARTERS and role not in ROLES:
            # any other role must be a specialist registered for THIS engagement:
            # an arbitrary role name was never granted authority
            if mode == "agent" and self.llm:
                specialist = specialists.get(self.db, engagement_id, role)
            if specialist is None:
                self.db.emit(engagement_id, "degradation", {
                    "code": "unknown_specialist", "intent_id": intent["id"], "role": role,
                    "detail": f"intent role {role!r} is not a built-in role and no specialist by "
                              f"that slug is registered for this engagement: refused"})
                return "exhausted", {"skipped": "unknown_specialist", "role": role}
            if specialist["state"] not in specialists.RUNNABLE:
                self.db.emit(engagement_id, "degradation", {
                    "code": "specialist_not_runnable", "intent_id": intent["id"],
                    "specialist": role, "state": specialist["state"],
                    "detail": f"specialist {role!r} is {specialist['state']}: not run again"})
                return "exhausted", {"skipped": "specialist_not_runnable", "specialist": role}
            denied = specialists.denied_units(specialist["charter"], profile)
            if denied:
                # the charter's ACTUAL capabilities decide, not its name: a passive
                # engagement must not run a specialist that can do active work
                self.db.emit(engagement_id, "degradation", {
                    "code": "policy_restriction", "unit": ", ".join(denied), "specialist": role,
                    "intent_id": intent["id"],
                    "detail": f"specialist {role!r} needs {', '.join(denied)}, which the "
                              f"{profile!r} profile forbids: not run"})
                specialists.transition(self.db, engagement_id, role, "failed",
                                       f"policy restriction: {', '.join(denied)}")
                return "exhausted", {"skipped": "policy_restriction", "specialist": role,
                                     "units": denied}
        elif not permits(role, profile):
            # defense in depth: a pre-existing or model-proposed intent is not authority
            self._policy_skip(engagement_id, role, profile, intent["id"])
            return "exhausted", {"skipped": "policy_restriction", "profile": profile}
        self.db.emit(engagement_id, "intent_running", {"intent_id": intent["id"], "role": role})
        # agent mode: genuine specialist investigation via the autonomous runtime.
        # verification and reporting stay deterministic/independent in every mode.
        if mode == "agent" and self.llm and role not in ("verify", "report"):
            if role in CHARTERS or specialist is not None:
                ar = AgentRunner(self.db, self.evidence, self.pipeline, self.probe,
                                 self.registry, self.runner, self.llm, scope, engagement_id)
                charter = None
                if specialist is not None:
                    specialists.transition(self.db, engagement_id, role, "scheduled",
                                           f"intent {intent['id']} claimed")
                    charter = specialist["charter"]
                res = (ar.run(intent, role) if charter is None
                       else ar.run(intent, role, charter=charter))
                result = {"agent_run": res["run_id"], "exit_reason": res["exit_reason"]}
                if res["status"] != "completed":
                    # a run that did not finish its investigation is not a pass
                    self.db.emit(engagement_id, "degradation",
                                 {"code": "agent_run_failed", "intent_id": intent["id"],
                                  "detail": f"{role} run ended {res['exit_reason']}: "
                                            f"{res.get('summary') or ''}"[:500]})
                    return "blocked", result
                return "done", result
        if role == "recon":
            self._do_recon(engagement_id, scope, obj, intent["id"])
        elif role == "crawl":
            result = self._do_crawl(engagement_id, scope, obj, intent["id"]) or {}
        elif role == "web_checks":
            result = self._do_web_checks(engagement_id, scope, eng, obj, intent["id"]) or {}
        elif role == "nuclei_scan":
            self._do_nuclei(engagement_id, scope, eng, obj, intent["id"])
        elif role == "infra_scan":
            self._do_infra(engagement_id, scope, obj, intent["id"])
        elif role == "impact_proof":
            self._do_impact_proof(engagement_id, scope, eng, intent["id"])
        elif role == "verify":
            self._do_verify(engagement_id, scope)
        elif role == "code_audit":
            self._do_code_audit(engagement_id, scope, obj, intent["id"])
        elif role == "api_audit":
            self._do_api_audit(engagement_id, scope, eng, obj, intent["id"])
        elif role == "jwt_audit":
            self._do_jwt_audit(engagement_id, scope, eng, intent["id"])
        elif role == "oauth_audit":
            self._do_oauth_audit(engagement_id, scope, eng, intent["id"])
        elif role == "session_audit":
            self._do_session_audit(engagement_id, scope, eng, intent["id"])
        elif role == "privesc_audit":
            self._do_privesc_audit(engagement_id, scope, eng, intent["id"])
        elif role == "injection_audit":
            self._do_injection_audit(engagement_id, scope, eng, intent["id"])
        elif role == "web_protocol_audit":
            self._do_web_protocol_audit(engagement_id, scope, eng, intent["id"])
        elif role == "container_scan":
            self._do_container_scan(engagement_id, scope, obj, intent["id"])
        elif role == "graphql_audit":
            self._do_graphql_audit(engagement_id, scope, eng, intent["id"])
        elif role == "report":
            from .report import render_report
            render_report(self.db, self.evidence, engagement_id)
        else:
            raise ValueError(f"unknown role {role}")
        return "done", result

    def _upsert_asset(self, engagement_id, kind, key, value=None, parent=None, by="recon"):
        existing = self.db.one("SELECT id FROM assets WHERE engagement_id=? AND kind=? AND key=?",
                               (engagement_id, kind, key))
        now = time.time()
        if existing:
            self.db.execute("UPDATE assets SET last_seen=?, value_json=? WHERE id=?",
                            (now, json.dumps(value or {}), existing["id"]))
            return existing["id"]
        aid = new_id("a")
        self.db.execute(
            "INSERT INTO assets(id, engagement_id, kind, key, value_json, parent_id, discovered_by, first_seen, last_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (aid, engagement_id, kind, key, json.dumps(value or {}), parent, by, now, now))
        self.db.emit(engagement_id, "asset_discovered", {"asset_id": aid, "kind": kind, "key": key})
        return aid

    def _target_from_obj(self, obj: str) -> str | None:
        for token in obj.split():
            if token.startswith("http://") or token.startswith("https://"):
                return token.rstrip(".,;")
        return None

    def _do_recon(self, engagement_id, scope, obj, intent_id):
        url = self._target_from_obj(obj)
        if url:
            root = self._upsert_asset(engagement_id, "root", url, {"url": url})
            spec = self.registry.get("httpx")
            r = self.runner.run(spec, {"target": url}, scope, engagement_id, intent_id, url, "recon")
            if r.get("ok"):
                for rec in PARSERS["httpx"](r["stdout"]):
                    self._upsert_asset(engagement_id, "app", rec.get("url") or url, rec, parent=root)
                    self.pipeline.record_observation(
                        engagement_id, intent_id, "fingerprint",
                        f"{rec.get('url')} status={rec.get('status_code')} tech={rec.get('technologies')}",
                        r.get("artifact_id"))
            else:
                self.pipeline.record_observation(engagement_id, intent_id, "degradation",
                                                 f"httpx: {r.get('error')}", r.get("artifact_id"))
            # platform probe always runs (works without httpx binary)
            pr = self.probe.request(engagement_id, scope, url, tool="recon_probe")
            if pr.get("ok"):
                self._upsert_asset(engagement_id, "endpoint", url,
                                   {"status": pr["status"]}, parent=root)
        else:
            domain = obj.split()[-1]
            spec = self.registry.get("subfinder")
            r = self.runner.run(spec, {"domain": domain}, scope, engagement_id, intent_id, domain, "recon")
            if r.get("ok"):
                for line in r["stdout"].splitlines():
                    sub = line.strip()
                    if sub and scope.check_host_port(sub, 443, "recon").allowed:
                        self._upsert_asset(engagement_id, "subdomain", sub, {"domain": domain})
            else:
                self.pipeline.record_observation(engagement_id, intent_id, "degradation",
                                                 f"subfinder: {r.get('error')}", r.get("artifact_id"))

    def _do_crawl(self, engagement_id, scope, obj, intent_id):
        url = self._target_from_obj(obj)
        if not url:
            return
        crawler = Crawler(self.probe, engagement_id, scope)
        result = crawler.crawl(url)
        # browser-rendered crawling for SPA coverage (degrades loudly if absent)
        try:
            from .browser_crawl import BrowserCrawler, browser_available
            if browser_available():
                bc = BrowserCrawler(self.db, self.evidence, scope, engagement_id)
                bres = bc.crawl(url)
                result["endpoints"] = sorted(set(result["endpoints"]) | set(bres.get("endpoints", [])))
                result["api_requests"] = bres.get("api_requests", [])
                result["browser_pages"] = bres.get("pages", [])
                result["screenshots"] = bres.get("screenshots", [])
                if bres.get("degraded"):
                    result["browser_degradation"] = "; ".join(bres["degraded"])
            else:
                result["browser_degradation"] = "playwright/chromium not installed; static JS mining only"
        except Exception as e:
            result["browser_degradation"] = f"browser crawl failed: {e}"
        ev = self.evidence.put_json(engagement_id, result, "crawl_map")
        root = self._upsert_asset(engagement_id, "root", url)
        for page in result["pages"]:
            self._upsert_asset(engagement_id, "endpoint", page["url"],
                               {"status": page["status"], "title": page["title"]}, parent=root, by="crawl")
        for ep in result["endpoints"]:
            if ep not in {p["url"] for p in result["pages"]}:
                self._upsert_asset(engagement_id, "endpoint", ep, {"discovered": "js_mining"},
                                   parent=root, by="crawl")
        self.pipeline.record_observation(
            engagement_id, intent_id, "crawl",
            f"{result['crawled']} pages, {len(result['endpoints'])} endpoints, {len(result['forms'])} forms"
            + (f", {len(result.get('api_requests', []))} runtime API requests (browser)"
               if result.get("api_requests") else ""),
            ev["id"])
        if result.get("browser_degradation"):
            self.pipeline.record_observation(engagement_id, intent_id, "degradation",
                                             result["browser_degradation"], ev["id"])
        # returned, not written here: _complete persists the handler's result under the
        # same lease fence, so a write here was overwritten with {} and every later
        # web_checks intent found zero endpoints to test.
        return {"endpoints": result["endpoints"], "forms": result["forms"],
                "pages": result["pages"]}

    def _do_web_checks(self, engagement_id, scope, eng, obj, intent_id):
        url = self._target_from_obj(obj)
        if not url:
            return
        # duplicate-work prevention: skip if this base URL was already checked
        prior = self.db.query(
            "SELECT objective FROM intents WHERE engagement_id=? AND role='web_checks' "
            "AND status='done' AND id != ?", (engagement_id, intent_id))
        base = url.rstrip("/")
        if any(self._target_from_obj(p["objective"]) and
               self._target_from_obj(p["objective"]).rstrip("/") == base for p in prior):
            self.db.emit(engagement_id, "duplicate_work_prevented",
                         {"intent_id": intent_id, "url": base})
            return {"skipped": "already_covered", "url": base}
        checks = WebChecks(self.probe, engagement_id, scope, self.db)
        profile = eng.get("profile") or DEFAULT_PROFILE
        skipped: list[str] = []

        def allow(unit: str) -> bool:
            if permits(unit, profile):
                return True
            if unit not in skipped:
                skipped.append(unit)
            return False

        candidates = []
        if allow("security_headers"):
            candidates += checks.security_headers(url)
        if allow("cors"):
            candidates += checks.cors(url)
        if allow("sensitive_paths"):
            candidates += checks.sensitive_paths(url)
        signals = checks.version_signals(url) if allow("version_signals") else []
        for s in signals:
            self.pipeline.record_observation(engagement_id, intent_id, "version_signal",
                                             f"{s['header']}: {s['value']} (not a finding)", s["evidence_id"])
        # gather endpoints+params from crawl results
        crawl_intents = self.db.query(
            "SELECT id, result_json FROM intents WHERE engagement_id=? AND role='crawl' "
            "AND result_json IS NOT NULL", (engagement_id,))
        endpoints, forms = set(), []
        for ci in crawl_intents:
            try:
                res = json.loads(ci["result_json"])
            except ValueError:
                res = None
            if not isinstance(res, dict) or "endpoints" not in res:
                # An absent inventory is not an empty one: say the state is missing so the
                # ledger records a gap instead of a silent clean sweep of zero endpoints.
                self.db.emit(engagement_id, "degradation", {
                    "code": "crawl_result_missing", "intent_id": intent_id, "unit": "web_checks",
                    "detail": f"crawl intent {ci['id']} holds no endpoint inventory "
                              f"({(ci['result_json'] or '')[:120]}); its endpoints were never "
                              f"tested. Re-run the crawl before trusting this engagement's "
                              f"parameter coverage."})
                continue
            endpoints.update(res["endpoints"])
            forms.extend(res.get("forms") or [])
        for ep in sorted(endpoints):
            if "?" not in ep:
                # parameter guessing on mined API routes (bounded)
                if ("/rest/" in ep or "/api/" in ep) and not ep.endswith((".js", ".css", ".ico")):
                    for guess in ("q", "id"):
                        gbase = ep
                        if allow("reflected_xss"):
                            candidates += checks.reflected_xss(gbase, guess)
                        if allow("sqli"):
                            candidates += checks.sqli(gbase, guess)
                continue
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(ep).query)
            base = ep.split("?")[0]
            for p in params:
                if allow("reflected_xss"):
                    candidates += checks.reflected_xss(base, p)
                if allow("sqli"):
                    candidates += checks.sqli(base, p)
                if allow("ssti"):
                    candidates += checks.ssti(base, p)
                if allow("path_traversal"):
                    candidates += checks.path_traversal(base, p)
                if allow("open_redirect"):
                    candidates += checks.open_redirect(base, p)
        # login cookie check via forms (posting credentials needs an active profile)
        auth = json.loads(eng["auth_json"])
        if allow("auth_bypass"):
            for ident in auth.get("identities", []):
                lu = ident.get("login_url")
                if lu and scope.check_url(lu).allowed:
                    body = f"{ident.get('username_field','username')}={ident['username']}&{ident.get('password_field','password')}={ident['password']}"
                    candidates += checks.cookie_flags(lu, method="POST", body=body,
                                                      headers={"Content-Type": "application/x-www-form-urlencoded"})
        # operator-supplied lab/test hints (explicit, in-scope only)
        hints = auth.get("test_hints", {})
        if "ssrf" in hints and allow("ssrf"):
            h = hints["ssrf"]
            if scope.check_url(h["internal_url"]).allowed:
                candidates += checks.ssrf(h["url"], h["param"], h["internal_url"], h["marker"])
        if "sqli_union" in hints and allow("sqli_union"):
            h = hints["sqli_union"]
            candidates += checks.sqli_union(h["url"], h["param"], h["payload"], h["marker"])
        # parameter mining on common endpoint patterns
        from .checks import COMMON_PARAM_ENDPOINTS, COMMON_API_PATHS
        from urllib.parse import urlparse, parse_qs
        base = url.rstrip("/")
        # Every discovered endpoint is asked which parameters it reacts to, so the checks
        # stop depending on an operator hint naming the endpoint and its parameter. The
        # fixed list below stays as a fallback for paths a crawl never linked.
        for ep in sorted(endpoints):
            if "?" in ep or ep.endswith((".js", ".css", ".ico", ".png", ".jpg", ".svg")):
                continue
            if not scope.check_url(ep).allowed:
                continue
            for p in checks.live_params(ep, limit=4):
                if allow("ssrf"):
                    candidates += checks.fetch_param(ep, p)
                if allow("reflected_xss"):
                    candidates += checks.reflected_xss(ep, p)
                if allow("sqli"):
                    candidates += checks.sqli(ep, p)
                if allow("ssti"):
                    candidates += checks.ssti(ep, p)
                if allow("path_traversal"):
                    candidates += checks.path_traversal(ep, p)
                if allow("open_redirect"):
                    candidates += checks.open_redirect(ep, p)
        for ep in COMMON_PARAM_ENDPOINTS:
            full = base + ep
            if not scope.check_url(full).allowed:
                continue
            probe_r = self.probe.request(engagement_id, scope, full, tool="param_mining")
            if not probe_r.get("ok") or probe_r["status"] == 404:
                continue
            pbase = full.split("?")[0]
            for p in parse_qs(urlparse(full).query):
                if allow("reflected_xss"):
                    candidates += checks.reflected_xss(pbase, p)
                if allow("sqli"):
                    candidates += checks.sqli(pbase, p)
                if allow("ssti"):
                    candidates += checks.ssti(pbase, p)
                if allow("path_traversal"):
                    candidates += checks.path_traversal(pbase, p)
                if allow("open_redirect"):
                    candidates += checks.open_redirect(pbase, p)
        for ap in COMMON_API_PATHS:
            if allow("cors") and scope.check_url(base + ap).allowed:
                candidates += checks.cors(base + ap)
        if allow("file_upload") and scope.check_url(base + "/upload").allowed:
            candidates += checks.file_upload(base + "/upload", base)
        # authenticated checks: login each identity, test auth bypass + IDOR
        import httpx
        for ident in auth.get("identities", []):
            lu = ident.get("login_url")
            if not allow("auth_bypass") or not lu or not scope.check_url(lu).allowed:
                continue
            uf, pf = ident.get("username_field", "username"), ident.get("password_field", "password")
            candidates += checks.auth_bypass(lu, uf, pf)
            client = httpx.Client(timeout=15, verify=False, trust_env=False)
            try:
                client.post(lu, data={uf: ident["username"], pf: ident["password"]})
                cookie_header = "; ".join(f"{k}={v}" for k, v in client.cookies.items())
                if cookie_header and "idor" in hints:
                    h = hints["idor"]
                    if h.get("identity") == ident["username"]:
                        for oid in h.get("foreign_ids", []):
                            obj_url = h["url_template"].format(id=oid)
                            if scope.check_url(obj_url).allowed:
                                candidates += checks.idor(obj_url, cookie_header,
                                                          h["foreign_marker"], ident["username"],
                                                          ident.get("uid"))
                # Without a hint, walk object ids under the collections the crawl actually
                # found: the operator should not have to name an endpoint for the engine to
                # notice that /api/<collection>/{id} serves other users' records.
                if cookie_header and allow("idor"):
                    for coll in _object_collections(checks, sorted(endpoints), base,
                                                    cookie_header):
                        # ids come from the collection's own listing when it publishes one:
                        # a sequential guess of 1..3 misses sparse ids (5001, 5002) and any
                        # dataset that did not start at 1.
                        candidates += checks.object_enumeration(
                            coll, cookie_header, ident["username"], ident.get("uid"),
                            ids=checks.collection_ids(coll, cookie_header))
            except httpx.HTTPError:
                pass
            finally:
                client.close()
        for cand in candidates:
            self.pipeline.submit_candidate(engagement_id, cand, intent_id)
        if skipped:
            self._policy_skip(engagement_id, ", ".join(skipped), profile, intent_id)
        if checks.mitigated:
            # A challenge page is a non-answer: say so once, as a limitation, not a finding.
            kinds = sorted({m.split(": ", 1)[-1] for m in checks.mitigated})
            self.db.emit(engagement_id, "degradation", {
                "code": "target_mitigated", "intent_id": intent_id,
                # which checks were answered by an interstitial, so coverage can say so
                "units": sorted({m.split(": ", 1)[0] for m in checks.mitigated}),
                "detail": f"{len(checks.mitigated)} request(s) to {url} were answered by a bot/WAF "
                          f"challenge ({', '.join(kinds)}). Those checks are inconclusive, not "
                          f"findings; supply a browser session or allow-list the assessment "
                          f"client to assess the application itself."})
        self.db.emit(engagement_id, "checks_complete",
                     {"intent_id": intent_id, "candidates": len(candidates),
                      "mitigated": len(checks.mitigated)})
        return {"candidates": len(candidates), "mitigated": len(checks.mitigated),
                "skipped": skipped}

    def _do_nuclei(self, engagement_id, scope, eng, obj, intent_id):
        url = self._target_from_obj(obj)
        if not url:
            return
        # nuclei's OAST templates call back to public interactsh servers the engagement does
        # not authorize (and must not). The egress policy refuses every callback, so those
        # templates can never fire: disable them and say so, instead of collecting hundreds
        # of denials and reporting a partial scan as if it were complete.
        self.pipeline.record_observation(
            engagement_id, intent_id, "limitation",
            "nuclei runs with -no-interactsh: interactsh callbacks go to public OAST servers "
            "this engagement does not authorize and the egress policy correctly refuses them. "
            "OAST-dependent templates (blind SSRF/RCE/XXE, callback-based) are unsupported here "
            "and are not counted as tested.")
        self.db.emit(engagement_id, "degradation", {
            "code": "oast_unsupported", "unit": "nuclei_scan", "intent_id": intent_id,
            "detail": "out-of-band templates disabled: their callback destinations are out of "
                      "scope by policy, so they are recorded unsupported, never silently pass"})
        spec = self.registry.get("nuclei")
        progress: dict = {}
        # A scan profile is an operator choice, so it must reach argv: the previous build
        # always ran the whole medium+ tree, so "focused" was unselectable and every scan
        # burned its 600s cap. Absent a profile the behaviour is unchanged (comprehensive).
        profile = (json.loads(eng.get("scope_json") or "{}").get("scan_profile") or {})
        if profile:
            self.db.emit(engagement_id, "scan_profile",
                         {"intent_id": intent_id, "profile": profile})

        def on_progress(line: str) -> None:
            sample = PARSERS["nuclei_stats"](line)
            if not sample or sample["percent"] is None:
                return
            progress.update(sample)
            self.db.emit(engagement_id, "scan_progress",
                         {"tool": "nuclei", "intent_id": intent_id, "url": url, **sample})

        params = {"target": url, "severity": profile.get("severity") or "medium,high,critical",
                  "rate_limit": _declared_rate(scope, NUCLEI_MAX_RATE)}
        if profile.get("tags"):
            params["tags"] = profile["tags"]
        r = self.runner.run(spec, params, scope, engagement_id, intent_id, url, "web",
                            on_progress=on_progress)
        if progress.get("percent") is not None and progress["percent"] < 100:
            # say what was NOT scanned, in the engine's own numbers
            why = "the scan hit its time limit" if r.get("error") == "timeout" else (
                "the scanner stopped before reporting 100% request progress")
            self.db.emit(engagement_id, "degradation", {
                "code": "scan_partial", "intent_id": intent_id, "units": ["nuclei"],
                "detail": f"nuclei last reported {progress['percent']}% request progress "
                          f"({progress.get('requests')} requests, {progress.get('matched')} matches): {why}. "
                          "Executed and unfinished template counts are not reported."})
        if not r.get("ok"):
            self.pipeline.record_observation(engagement_id, intent_id, "degradation",
                                             f"nuclei: {r.get('error')}", r.get("artifact_id"))
            return
        for rec in PARSERS["nuclei"](r["stdout"]):
            cand = {
                "title": f"[nuclei] {rec.get('name') or rec.get('template_id')}",
                "cwe": (rec.get("classification") or {}).get("cwe-id", [None])[0] if isinstance(rec.get("classification"), dict) else None,
                "owasp": None, "severity": rec.get("severity", "info"),
                "confidence": "medium", "endpoint": rec.get("matched_at") or url,
                "description": f"nuclei template {rec.get('template_id')} matched at {rec.get('matched_at')}.",
                "impact": "Scanner-reported; requires independent validation.",
                "remediation": "See template references.",
                "evidence_ids": [r["artifact_id"]],
                "quote": rec.get("template_id") or "", "quote_in": "body",
                "proof_request": {"method": "GET", "url": rec.get("matched_at") or url},
                "dedup_key": f"nuclei:{rec.get('template_id')}:{rec.get('matched_at')}",
            }
            self.pipeline.submit_candidate(engagement_id, cand, intent_id)

    def _do_infra(self, engagement_id, scope, obj, intent_id):
        url = self._target_from_obj(obj)
        host = url.split("//")[-1].split("/")[0].split(":")[0] if url else obj.split()[-1]
        if url and url.startswith("https://"):
            from urllib.parse import urlparse
            from .tls_audit import audit_tls
            pu = urlparse(url)
            audit_tls(host, pu.port or 443, self.db, self.evidence, self.pipeline,
                      scope, engagement_id, intent_id)
        spec = self.registry.get("nmap")
        params = {"target": host, "service_detect": True,
                  "rate_limit": _declared_rate(scope, NMAP_MAX_RATE)}
        authorized = scope.authorized_ports(host)
        if authorized:
            # a URL target authorizes its own port only: never a top-100 sweep
            params["ports"] = ",".join(str(p) for p in authorized)
        else:
            params["top_ports"] = 100
        r = self.runner.run(spec, params, scope, engagement_id, intent_id, host, "infra")
        if not r.get("ok"):
            self.pipeline.record_observation(engagement_id, intent_id, "degradation",
                                             f"nmap: {r.get('error')}", r.get("artifact_id"))
            return
        for h in PARSERS["nmap"](r["stdout"]):
            self._upsert_asset(engagement_id, "host", h["addr"], {"ports": h["ports"]}, by="nmap")
            for p in h["ports"]:
                self._upsert_asset(engagement_id, "service", f"{h['addr']}:{p['port']}", p, by="nmap")

    def _do_impact_proof(self, engagement_id, scope, eng, intent_id):
        """Demonstrate impact for already-validated findings, lab-authorised only.

        The module re-checks the lab flag and scope on every call; this only picks
        which findings are eligible (verified ones) so a suspected signal is never
        dressed up as demonstrated impact.
        """
        from .impact_proof import prove_impact
        auth = json.loads(eng["auth_json"])
        findings = self.db.query(
            "SELECT * FROM findings WHERE engagement_id=? AND state IN "
            "('validated','reported','retested_persists')", (engagement_id,))
        for f in findings:
            prove_impact(self.db, self.evidence, self.probe, scope, engagement_id, f,
                         auth, self.pipeline, intent_id)

    def _do_verify(self, engagement_id, scope):
        findings = self.db.query(
            "SELECT id FROM findings WHERE engagement_id=? AND state IN ('suspected','observed')",
            (engagement_id,))
        for f in findings:
            self.verifier.verify(engagement_id, scope, f["id"])

    def _do_code_audit(self, engagement_id, scope, obj, intent_id):
        path = obj.split()[-1]
        decision = scope.check_repo(path)
        if not decision.allowed:
            self.db.emit(engagement_id, "scope_refusal",
                         {"url": path, "reason": decision.reason, "tool": "code_audit"})
            return
        from .codeaudit import assess_repo
        assess_repo(path, self.db, self.evidence, self.pipeline, engagement_id, intent_id)

    def _do_api_audit(self, engagement_id, scope, eng, obj, intent_id):
        url = self._target_from_obj(obj)
        if not url:
            return
        auth = json.loads(eng["auth_json"])
        openapi = auth.get("openapi")
        if not openapi:
            return
        from .api_audit import assess_api
        assess_api(url, openapi, auth.get("identities", []), self.db, self.evidence,
                   self.pipeline, self.probe, scope, engagement_id)

    # ---- offensive audits: each needs a declared target in auth_json ----

    def _do_jwt_audit(self, engagement_id, scope, eng, intent_id):
        from .jwt_audit import audit_jwt
        audit_jwt(self.db, self.evidence, self.probe, scope, engagement_id,
                  json.loads(eng["auth_json"]), self.pipeline, intent_id)

    def _do_oauth_audit(self, engagement_id, scope, eng, intent_id):
        from .oauth_audit import audit_oauth
        audit_oauth(self.db, self.evidence, self.probe, scope, engagement_id,
                    json.loads(eng["auth_json"]), self.pipeline, intent_id)

    def _do_session_audit(self, engagement_id, scope, eng, intent_id):
        from .session_audit import audit_session
        audit_session(self.db, self.evidence, self.probe, scope, engagement_id,
                      json.loads(eng["auth_json"]), self.pipeline, intent_id)

    def _do_privesc_audit(self, engagement_id, scope, eng, intent_id):
        from .privesc_audit import audit_role_matrix
        out = audit_role_matrix(self.db, self.evidence, self.probe, scope, engagement_id,
                                json.loads(eng["auth_json"]), self.pipeline, intent_id)
        # the expected-permission verdicts are the point of this audit: persist them so an
        # analyst can review a judgement, not just the findings it produced
        authz = out.get("authorization") or {}
        return {"verdict": out.get("verdict"), "status": out.get("status"),
                "identities": out.get("identities"), "endpoints": out.get("endpoints"),
                "candidates": len(out.get("candidates") or []),
                "authorization": {"model": authz.get("model"),
                                  "verdicts": authz.get("verdicts"),
                                  "hypotheses": authz.get("hypotheses")}}

    def _do_injection_audit(self, engagement_id, scope, eng, intent_id):
        from .injection_audit import audit_injection
        audit_injection(self.db, self.evidence, self.probe, scope, engagement_id,
                        json.loads(eng["auth_json"]), self.pipeline, intent_id)

    def _do_web_protocol_audit(self, engagement_id, scope, eng, intent_id):
        from .web_protocol_audit import audit_web_protocol
        audit_web_protocol(self.db, self.evidence, self.probe, scope, engagement_id,
                           json.loads(eng["auth_json"]), self.pipeline, intent_id)

    def _do_container_scan(self, engagement_id, scope, obj, intent_id):
        image = obj.split()[-1]
        decision = scope.check_image(image)
        if not decision.allowed:
            self.db.emit(engagement_id, "scope_refusal",
                         {"url": image, "reason": decision.reason, "tool": "container_scan"})
            return
        from .tools.container_adapters import assess_image
        assess_image(image, self.db, self.evidence, self.pipeline, engagement_id, intent_id)

    def _do_graphql_audit(self, engagement_id, scope, eng, intent_id):
        auth = json.loads(eng["auth_json"])
        endpoint = auth.get("graphql")
        if not endpoint:
            return
        from .graphql_audit import assess_graphql
        assess_graphql(endpoint, self.db, self.evidence, self.pipeline, self.probe,
                       scope, engagement_id, auth.get("identities"))
