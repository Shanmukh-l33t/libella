"""Authenticated browser workflows: login sessions, authenticated crawl, scripted
flows and multi-identity access comparison.

One persistent Playwright browser context per session carries the cookies a form
login sets into the crawl and every scripted step. Scope is enforced at the
request boundary (same guard as browser_crawl): out-of-scope navigations and
subresources are aborted and audited, never followed. Artifacts the runner
produces (per-step screenshots, the network log) are written to the evidence
store, so an access-control conclusion is bound to something that really happened.
"""
import json
import time
from urllib.parse import urlparse

from .browser_crawl import IDLE_MS, BrowserCrawler
from .db import new_id

STEP_ACTIONS = {"navigate", "click", "fill", "submit", "extract", "assert"}
WORKFLOW_SHOT_CAP = 10  # one screenshot per step is evidence; ten is plenty for a flow
NET_CAP = 200
DEFAULT_SELECTORS = {"username": "input[name=username]", "password": "input[name=password]",
                     "submit": "button[type=submit]"}


def _cookies(auth_context: dict) -> list[dict]:
    """Cookies from a stored row (cookies_json) or an in-memory auth_context."""
    raw = auth_context.get("cookies")
    if raw is None:
        raw = auth_context.get("cookies_json") or "[]"
    cookies = json.loads(raw) if isinstance(raw, str) else list(raw or [])
    return [c for c in cookies if isinstance(c, dict) and c.get("name")]


def _json(value, default):
    try:
        return json.loads(value) if isinstance(value, str) else (value or default)
    except json.JSONDecodeError:
        return default


class _CtxBrowser:
    """browser.new_page() shim onto one persistent context, so cookies persist."""

    def __init__(self, ctx):
        self.ctx = ctx

    def new_page(self):
        return self.ctx.new_page()

    def close(self):
        self.ctx.browser.close()


class AuthBrowser(BrowserCrawler):
    """BrowserCrawler with one sticky session (cookies) instead of a fresh context."""

    def __init__(self, db, evidence, scope, engagement_id, timeout_ms: int = 15000):
        self._ctx = None
        self._session_cookies: list[dict] = []
        self._page_url = ""
        super().__init__(db, evidence, scope, engagement_id, timeout_ms=timeout_ms)

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        super().__enter__()
        try:
            self._ctx = self._browser.new_context(ignore_https_errors=True)
            # context-level route: page.route() does not cover popups a target may
            # open, and a popup inherits this context's cookies
            self._ctx.route("**/*", self._guard)
            if self._session_cookies:
                self._ctx.add_cookies(self._session_cookies)
            self._browser = _CtxBrowser(self._ctx)
        except BaseException:
            self._close()
            raise
        return self

    def _ensure(self):
        if self._ctx is None:
            self.__enter__()

    def use(self, auth_context: dict) -> list[dict]:
        """Load a stored auth_context's cookies into the session context."""
        cookies = _cookies(auth_context)
        self._session_cookies = cookies
        if self._ctx is not None and cookies:
            self._ctx.add_cookies(cookies)
        return cookies

    # -- request guard (scope) --------------------------------------------
    def _guard(self, route):
        req = route.request
        if urlparse(req.url).scheme not in ("http", "https"):
            return route.continue_()  # data:/blob: never leaves the browser
        if not self._allowed(req.url):
            return route.abort()
        if req.resource_type in ("xhr", "fetch"):
            self._note_api(req.method, req.url, self._page_url)
        return route.continue_()

    @staticmethod
    def _matches(page, assertion) -> bool:
        if not assertion:
            return True
        try:
            return page.locator(assertion).count() > 0
        except Exception:
            return False

    @staticmethod
    def _at_login(url: str) -> bool:
        return urlparse(url).path.rstrip("/").endswith("/login")

    # -- login -------------------------------------------------------------
    def _login(self, page, login_url, username, password, selectors, assertion) -> bool:
        s = {**DEFAULT_SELECTORS, **(selectors or {})}
        page.goto(login_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        page.fill(s["username"], username)
        page.fill(s["password"], password)
        page.click(s["submit"])
        try:
            page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, IDLE_MS))
        except Exception:
            pass  # polling pages never idle; the success assertion decides
        return self._matches(page, assertion)

    def login_flow(self, base_url: str, login_url: str, username: str, password: str,
                   selectors: dict | None = None, success_assertion: str | None = None,
                   name: str | None = None) -> dict:
        """Form login -> auth_contexts row (status active|failed).

        The password is used for this attempt only; it is never persisted.
        """
        self._ensure()
        self.shots = []
        if not self._allowed(login_url):
            return {"id": None, "status": "failed", "reason": "login_url out of scope",
                    "cookie_count": 0}
        page = self._ctx.new_page()
        page.route("**/*", self._guard)
        shot, reason, ok = None, None, False
        self._page_url = login_url
        try:
            page.set_default_timeout(self.timeout_ms)
            ok = self._login(page, login_url, username, password, selectors, success_assertion)
            landed = page.url
            if not self._same_origin(landed, urlparse(base_url).netloc) or not self._allowed(landed):
                ok, reason = False, "login left the scope origin"
            elif not ok:
                reason = f"success assertion {success_assertion!r} not met after submit"
            shot = self._screenshot(page, landed)
        except Exception as e:
            reason = f"login_failed: {type(e).__name__}: {e}"[:300]
        finally:
            cookies = [c for c in self._ctx.cookies() if c.get("name")]
            try:
                page.close()
            except Exception:
                pass
        self._session_cookies = cookies
        flow = {"base_url": base_url, "login_url": login_url,
                "selectors": {**DEFAULT_SELECTORS, **(selectors or {})},
                "success_assertion": success_assertion}
        row = {"id": new_id("ac"), "engagement_id": self.eng, "name": name or username,
               "username": username, "login_flow_json": json.dumps(flow),
               "cookies_json": json.dumps(cookies), "status": "active" if ok else "failed",
               "last_verified_at": time.time(), "created_at": time.time()}
        self.db.execute(
            "INSERT INTO auth_contexts(id, engagement_id, name, username, login_flow_json, "
            "cookies_json, status, last_verified_at, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            tuple(row[k] for k in ("id", "engagement_id", "name", "username", "login_flow_json",
                                   "cookies_json", "status", "last_verified_at", "created_at")))
        self.db.emit(self.eng, "auth_context",
                     {"id": row["id"], "username": username, "status": row["status"]})
        return {"id": row["id"], "engagement_id": self.eng, "name": row["name"],
                "username": username, "status": row["status"], "cookie_count": len(cookies),
                "login_flow": flow, "evidence_id": shot, "reason": reason}

    def verify(self, auth_context: dict, check_url: str | None = None) -> dict:
        """Replay the stored session against a protected page: active|expired."""
        flow = _json(auth_context.get("login_flow_json"), {})
        url = check_url or flow.get("base_url") or ""
        self._ensure()
        if not url or not self._allowed(url):
            return {"id": auth_context.get("id"), "status": "expired",
                    "reason": "check url out of scope"}
        self.use(auth_context)
        page = self._ctx.new_page()
        page.route("**/*", self._guard)
        shot, ok, reason = None, False, None
        try:
            self._page_url = url
            page.set_default_timeout(self.timeout_ms)
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            landed = page.url
            if not self._same_origin(landed, urlparse(url).netloc):
                reason = "verification left the scope origin"
            elif self._at_login(landed):
                reason = "session redirected to login"
            elif not self._matches(page, flow.get("success_assertion")):
                reason = "protected assertion missing"
            else:
                ok = True
            shot = self._screenshot(page, landed)
        except Exception as e:
            reason = f"verify_failed: {type(e).__name__}: {e}"[:300]
        finally:
            try:
                page.close()
            except Exception:
                pass
        status = "active" if ok else "expired"
        self.db.execute("UPDATE auth_contexts SET status=?, last_verified_at=? WHERE id=?",
                        (status, time.time(), auth_context.get("id")))
        self.db.emit(self.eng, "auth_context_verify",
                     {"id": auth_context.get("id"), "status": status, "reason": reason})
        return {"id": auth_context.get("id"), "status": status, "url": url,
                "evidence_id": shot, "reason": reason}

    # -- authenticated crawl ----------------------------------------------
    def authenticated_crawl(self, base_url: str, auth_context: dict) -> dict:
        """Crawl with the stored session: protected routes + runtime API."""
        self.use(auth_context)
        result = self.crawl(base_url)
        result["auth_context_id"] = auth_context.get("id")
        return result

    # -- workflow ----------------------------------------------------------
    def _step(self, page, i: int, step: dict) -> dict:
        action, sel, val = step.get("action"), step.get("selector"), step.get("value")
        base = {"index": i, "action": action, "selector": sel, "ok": False}
        if action not in STEP_ACTIONS:
            return {**base, "fatal": True, "reason": f"unknown action {action!r}"}
        try:
            if action == "navigate":
                url = val or sel
                if not self._allowed(url):
                    return {**base, "url": url, "fatal": True,
                            "reason": "navigation refused: out of scope"}
                self._page_url = url
                resp = page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                landed = page.url
                if not self._same_origin(landed, urlparse(url).netloc) or not self._allowed(landed):
                    self._refuse(landed, "workflow redirect left scope origin")
                    return {**base, "url": landed, "fatal": True, "reason": "redirect left scope"}
                try:
                    page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, IDLE_MS))
                except Exception:
                    pass
                return {**base, "url": landed, "status": resp.status if resp else None, "ok": True}
            if action == "click":
                page.click(sel)
                return {**base, "ok": True}
            if action == "fill":
                page.fill(sel, "" if val is None else str(val))
                return {**base, "ok": True}
            if action == "submit":
                if sel:
                    page.click(sel)
                else:
                    page.keyboard.press("Enter")
                try:
                    page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, IDLE_MS))
                except Exception:
                    pass
                return {**base, "url": page.url, "ok": True}
            if action == "extract":
                return {**base, "value": (page.text_content(sel) or "").strip()[:2000], "ok": True}
            hit = page.locator(sel).count() > 0 if sel else True
            if val:
                hit = hit and str(val) in page.inner_text("body")
            return {**base, "ok": bool(hit), "reason": None if hit else "assertion failed"}
        except Exception as e:
            return {**base, "fatal": True, "reason": f"{type(e).__name__}: {e}"[:300]}

    def _run_steps(self, page, steps: list[dict]) -> tuple[bool, list[dict]]:
        results, ok = [], True
        for i, step in enumerate(steps):
            res = self._step(page, i, step)
            res["screenshot"] = (self._screenshot(page, page.url)
                                 if len(self.shots) < WORKFLOW_SHOT_CAP else None)
            results.append(res)
            ok = ok and res["ok"]
            if res.get("fatal"):
                break
        return ok, results

    def run_workflow(self, steps, auth_context: dict | None = None) -> dict:
        """Execute steps_json via Playwright, scope-checked per navigation."""
        if not isinstance(steps, list) or not steps:
            return {"ok": False, "steps": [], "error": "steps must be a non-empty list"}
        if not all(isinstance(s, dict) for s in steps):
            return {"ok": False, "steps": [], "error": "each step must be an object"}
        bad = [s.get("action") for s in steps if s.get("action") not in STEP_ACTIONS]
        if bad:
            return {"ok": False, "steps": [], "error": f"unknown actions {bad}"}
        if auth_context:
            self.use(auth_context)
        self._ensure()
        self.shots = []  # per-run screenshot budget
        page = self._ctx.new_page()
        page.route("**/*", self._guard)
        net: list[dict] = []
        page.on("response", lambda r: len(net) < NET_CAP and net.append(
            {"method": r.request.method, "url": r.url, "status": r.status}))
        try:
            page.set_default_timeout(self.timeout_ms)
            ok, results = self._run_steps(page, steps)
        finally:
            try:
                page.close()
            except Exception:
                pass
        ev = self.evidence.put_json(self.eng, {"steps": results, "network": net},
                                   "auth_workflow")
        self.db.emit(self.eng, "workflow_run",
                     {"ok": ok, "steps": len(results), "evidence_id": ev["id"]})
        return {"ok": ok, "steps": results, "network": net, "screenshots": list(self.shots),
                "evidence_id": ev["id"], "degraded": list(self.degraded)}

    # -- multi-identity access comparison ----------------------------------
    def _as_identity(self, ident: dict, target, login_url, selectors, assertion) -> dict:
        expected = ident.get("expected", "deny")
        out = {"username": ident.get("username"), "expected": expected}
        ctx = self._ctx.browser.new_context(ignore_https_errors=True)
        ctx.route("**/*", self._guard)  # popups included, same as the main context
        page = ctx.new_page()
        page.route("**/*", self._guard)
        try:
            page.set_default_timeout(self.timeout_ms)
            if login_url:
                out["logged_in"] = self._login(page, login_url, ident.get("username", ""),
                                               ident.get("password", ""), selectors, assertion)
                if not out["logged_in"]:
                    return {**out, "observed": "denied", "exposed": False,
                            "reason": "identity login failed"}
            if isinstance(target, list):
                ok, out["steps"] = self._run_steps(page, target)
                observed = "allow" if ok else "denied"
            else:
                self._page_url = target
                resp = page.goto(target, wait_until="domcontentloaded", timeout=self.timeout_ms)
                landed = page.url
                allowed = (resp is not None and resp.status < 400 and not self._at_login(landed))
                observed = "allow" if allowed else "denied"
                out["status"] = resp.status if resp else None
                out["url"] = landed
                out["screenshot"] = self._screenshot(page, landed)
            out["observed"] = observed
            out["exposed"] = expected == "deny" and observed == "allow"
            out["mismatch"] = observed != expected
            return out
        except Exception as e:
            return {**out, "observed": "error", "exposed": False, "mismatch": True,
                    "reason": f"{type(e).__name__}: {e}"[:300]}
        finally:
            try:
                page.close()
                ctx.close()
            except Exception:
                pass

    def multi_role_check(self, object_url_or_workflow, identities: list[dict],
                         login_url: str | None = None, selectors: dict | None = None,
                         success_assertion: str | None = None) -> dict:
        """Run the same object/workflow as each identity; expected vs observed access.

        identities: [{username, password, expected: allow|deny}]. Evidence: one
        screenshot per identity plus the per-step DOM results.
        """
        if not identities:
            return {"results": [], "unexpected_access": [], "consistent": True}
        self._ensure()
        self.shots = []
        results = [self._as_identity(i, object_url_or_workflow, login_url, selectors,
                                     success_assertion) for i in identities]
        unexpected = [r["username"] for r in results if r.get("exposed")]
        self.db.emit(self.eng, "multi_role_check",
                     {"target": object_url_or_workflow if isinstance(object_url_or_workflow, str)
                      else "workflow", "results": results, "unexpected_access": unexpected})
        return {"results": results, "unexpected_access": unexpected,
                "consistent": not unexpected}
