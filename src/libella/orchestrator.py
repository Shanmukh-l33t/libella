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
import time
import uuid

from .checks import WebChecks
from .crawl import Crawler
from .db import DB, new_id
from .evidence import EvidenceStore
from .findings import FindingPipeline
from .llm import LLM, LLMError
from .policy import DEFAULT_PROFILE, permits
from .scope import Scope
from .tools import Registry
from .tools.adapters import PARSERS
from .tools.http_probe import HttpProbe
from .tools.runner import ToolRunner
from .verifier import Verifier

LEASE_S = 120
MODES = ("deterministic", "llm", "agent")
ROLES = {"recon", "crawl", "web_checks", "nuclei_scan", "infra_scan", "verify", "report",
         "code_audit", "api_audit", "container_scan", "graphql_audit"}


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

    # ---- engagement control ----

    def start(self, engagement_id: str, mode: str = "deterministic"):
        eng = self.db.one("SELECT * FROM engagements WHERE id=?", (engagement_id,))
        if eng is None:
            raise KeyError(engagement_id)
        self._check_mode(mode)
        scope = Scope(json.loads(eng["scope_json"]))
        self.db.execute("UPDATE engagements SET status='running', started_at=? WHERE id=?",
                        (time.time(), engagement_id))
        self.db.emit(engagement_id, "engagement_started", {"mode": mode})
        if mode == "agent":
            self._plan_agent(engagement_id, scope, eng)
        else:
            self._plan_deterministic(engagement_id, scope, eng)
            if mode == "llm":
                self._plan_llm(engagement_id, scope, eng)
        self._run_loop(engagement_id, scope, eng, mode)

    def _check_mode(self, mode: str):
        """Refuse a run that cannot be what it claims (no silent deterministic fallback)."""
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}; expected one of {', '.join(MODES)}")
        if mode in ("llm", "agent") and self.llm is None:
            raise ValueError(f"mode {mode!r} requires a configured LLM provider; configure one "
                             "in Settings or start in deterministic mode")

    def cancel(self, engagement_id: str):
        self.db.execute("UPDATE engagements SET status='cancelled', finished_at=? WHERE id=?",
                        (time.time(), engagement_id))
        self.db.execute("UPDATE intents SET status='stopped' WHERE engagement_id=? AND status IN ('open','running')",
                        (engagement_id,))
        self.db.emit(engagement_id, "engagement_cancelled", {})

    def pause(self, engagement_id: str):
        self.db.execute("UPDATE engagements SET status='paused' WHERE id=?", (engagement_id,))
        self.db.emit(engagement_id, "engagement_paused", {})

    def resume(self, engagement_id: str, mode: str = "deterministic"):
        eng = self.db.one("SELECT * FROM engagements WHERE id=?", (engagement_id,))
        self._check_mode(mode)
        scope = Scope(json.loads(eng["scope_json"]))
        self.db.execute("UPDATE engagements SET status='running' WHERE id=?", (engagement_id,))
        self.db.emit(engagement_id, "engagement_resumed", {"mode": mode})
        self._run_loop(engagement_id, scope, eng, mode)

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
        self._add_intent(engagement_id, "report", "Render assessment report",
                         depends=[verify_id])

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
            status = self.db.one("SELECT status FROM engagements WHERE id=?", (engagement_id,))["status"]
            if status in ("cancelled", "paused", "done", "failed"):
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
                status, result = self._execute(engagement_id, scope, eng, intent, mode)
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

    def _sweep_leases(self, engagement_id: str):
        self.db.execute(
            "UPDATE intents SET status='open', claim_token=NULL WHERE engagement_id=? "
            "AND status='running' AND lease_expires < ?",
            (engagement_id, time.time()))

    def _finish(self, engagement_id: str, status: str, detail: str):
        self.db.execute("UPDATE engagements SET status=?, finished_at=?, status_detail=? WHERE id=?",
                        (status, time.time(), detail, engagement_id))
        self.db.emit(engagement_id, "engagement_finished", {"status": status, "detail": detail})
        if status in ("done", "budget_exhausted"):
            # independent verification + report always run at termination, so findings
            # are validated and reported even if the investigation budget capped early.
            try:
                eng = self.db.one("SELECT scope_json FROM engagements WHERE id=?", (engagement_id,))
                scope = Scope(json.loads(eng["scope_json"]))
                cands = self.db.query(
                    "SELECT id FROM findings WHERE engagement_id=? AND state IN ('suspected','observed')",
                    (engagement_id,))
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
        role = intent["role"]
        obj = intent["objective"]
        profile = eng.get("profile") or DEFAULT_PROFILE
        if not permits(role, profile):
            # defense in depth: a pre-existing or model-proposed intent is not authority
            self._policy_skip(engagement_id, role, profile, intent["id"])
            return "exhausted", {"skipped": "policy_restriction", "profile": profile}
        self.db.emit(engagement_id, "intent_running", {"intent_id": intent["id"], "role": role})
        # agent mode: genuine specialist investigation via the autonomous runtime.
        # verification and reporting stay deterministic/independent in every mode.
        if mode == "agent" and self.llm and role not in ("verify", "report"):
            from .agent_runtime import AgentRunner, CHARTERS
            if role in CHARTERS:
                ar = AgentRunner(self.db, self.evidence, self.pipeline, self.probe,
                                 self.registry, self.runner, self.llm, scope, engagement_id)
                res = ar.run(intent, role)
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
            self._do_crawl(engagement_id, scope, obj, intent["id"])
        elif role == "web_checks":
            self._do_web_checks(engagement_id, scope, eng, obj, intent["id"])
        elif role == "nuclei_scan":
            self._do_nuclei(engagement_id, scope, obj, intent["id"])
        elif role == "infra_scan":
            self._do_infra(engagement_id, scope, obj, intent["id"])
        elif role == "verify":
            self._do_verify(engagement_id, scope)
        elif role == "code_audit":
            self._do_code_audit(engagement_id, scope, obj, intent["id"])
        elif role == "api_audit":
            self._do_api_audit(engagement_id, scope, eng, obj, intent["id"])
        elif role == "container_scan":
            self._do_container_scan(engagement_id, scope, obj, intent["id"])
        elif role == "graphql_audit":
            self._do_graphql_audit(engagement_id, scope, eng, intent["id"])
        elif role == "report":
            from .report import render_report
            render_report(self.db, self.evidence, engagement_id)
        else:
            raise ValueError(f"unknown role {role}")
        return "done", {}

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
        self.db.execute("UPDATE intents SET result_json=? WHERE id=?",
                        (json.dumps({"endpoints": result["endpoints"], "forms": result["forms"],
                                     "pages": result["pages"]}), intent_id))

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
            self.db.execute("UPDATE intents SET result_json=? WHERE id=?",
                            (json.dumps({"skipped": "already_covered", "url": base}), intent_id))
            self.db.emit(engagement_id, "duplicate_work_prevented",
                         {"intent_id": intent_id, "url": base})
            return
        checks = WebChecks(self.probe, engagement_id, scope)
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
            "SELECT result_json FROM intents WHERE engagement_id=? AND role='crawl' AND result_json IS NOT NULL",
            (engagement_id,))
        endpoints, forms = set(), []
        for ci in crawl_intents:
            res = json.loads(ci["result_json"])
            endpoints.update(res.get("endpoints", []))
            forms.extend(res.get("forms", []))
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
                                                          h["foreign_marker"], ident["username"])
            except httpx.HTTPError:
                pass
            finally:
                client.close()
        for cand in candidates:
            self.pipeline.submit_candidate(engagement_id, cand, intent_id)
        if skipped:
            self._policy_skip(engagement_id, ", ".join(skipped), profile, intent_id)
        self.db.emit(engagement_id, "checks_complete",
                     {"intent_id": intent_id, "candidates": len(candidates)})

    def _do_nuclei(self, engagement_id, scope, obj, intent_id):
        url = self._target_from_obj(obj)
        if not url:
            return
        spec = self.registry.get("nuclei")
        r = self.runner.run(spec, {"target": url, "severity": "medium,high,critical",
                                   "rate_limit": int(scope.rate_limit_rps * 5)},
                            scope, engagement_id, intent_id, url, "web")
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
        r = self.runner.run(spec, {"target": host, "top_ports": 100, "service_detect": True},
                            scope, engagement_id, intent_id, host, "infra")
        if not r.get("ok"):
            self.pipeline.record_observation(engagement_id, intent_id, "degradation",
                                             f"nmap: {r.get('error')}", r.get("artifact_id"))
            return
        for h in PARSERS["nmap"](r["stdout"]):
            self._upsert_asset(engagement_id, "host", h["addr"], {"ports": h["ports"]}, by="nmap")
            for p in h["ports"]:
                self._upsert_asset(engagement_id, "service", f"{h['addr']}:{p['port']}", p, by="nmap")

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
