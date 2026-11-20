"""Browser crawl vs static crawl on an Angular SPA (OWASP Juice Shop).

Juice Shop renders its routes client-side, so the static crawler only sees the
shell + a few assets. This measures what a rendered crawl adds: runtime
XHR/fetch API surface that static HTML/JS mining never observes.

Usage: python benchmarks/run_browser_crawl.py [--base http://127.0.0.1:3001]
Requires: .venv/bin/playwright install chromium
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from libella.browser_crawl import BrowserCrawler, browser_available  # noqa: E402
from libella.crawl import Crawler  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:3001")
    ap.add_argument("--max-pages", type=int, default=25)
    args = ap.parse_args()

    if not browser_available():
        print(json.dumps({"error": "playwright/chromium not installed"}))
        raise SystemExit(2)

    data_dir = ROOT / "benchmark_runs" / "browser_crawl"
    data_dir.mkdir(parents=True, exist_ok=True)
    db = DB(data_dir / "bench.db")
    ev = EvidenceStore(db, data_dir / "evidence")
    scope = Scope({"targets": [{"kind": "url", "value": args.base}],
                   "categories": ["recon", "web", "api"], "rate_limit_rps": 15})
    eid = f"eng_browser_bench_{int(time.time())}"
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, "Juice Shop browser crawl", "safe_active", "draft", "{}", "{}", "{}", time.time()))

    t0 = time.time()
    static = Crawler(HttpProbe(db, ev), eid, scope).crawl(args.base)
    static_s = time.time() - t0
    t0 = time.time()
    with BrowserCrawler(db, ev, scope, eid, max_pages=args.max_pages) as crawler:
        rendered = crawler.crawl(args.base)
    rendered_s = time.time() - t0

    def paths(urls):
        return sorted({u.split(args.base, 1)[-1] or "/" for u in urls})

    static_paths, browser_paths = paths(static["endpoints"]), paths(rendered["endpoints"])
    rest = [p for p in browser_paths if p.startswith("/rest/")]
    # path-level view: static mining guesses paths without query, so compare them as paths
    rest_path = {p.split("?")[0].rstrip("/") for p in static_paths if p.startswith("/rest/")}
    observed_rest = {p.split("?")[0].rstrip("/") for p in rest}
    routes = [p for p in browser_paths if p in ("/",) or p.startswith("/#")]
    out = {
        "target": args.base,
        "static": {"pages": static["crawled"], "endpoints": len(static["endpoints"]),
                   "seconds": round(static_s, 2), "paths": static_paths},
        "browser": {"pages": len(rendered["pages"]), "endpoints": len(rendered["endpoints"]),
                    "api_requests": len(rendered["api_requests"]),
                    "screenshots": len(rendered["screenshots"]),
                    "limit_hit": rendered["limit_hit"], "degraded": rendered["degraded"],
                    "seconds": round(rendered_s, 2), "paths": browser_paths},
        "rendered_routes": routes,
        "new_vs_static": sorted(set(browser_paths) - set(static_paths)),
        "rest_endpoints": rest,
        "rest_paths_new_vs_static": sorted(observed_rest - rest_path),
        "titles": [p["title"] for p in rendered["pages"] if p["title"]],
        "evidence_chain": ev.verify_chain(eid),
    }
    out_path = data_dir / "browser_crawl_results.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(json.dumps({k: v for k, v in out.items() if k not in ("static", "browser")}, indent=2))
    print(f"static: {out['static']['pages']} pages, {out['static']['endpoints']} endpoints")
    print(f"browser: {out['browser']['pages']} rendered routes, {out['browser']['api_requests']} live api "
          f"requests, {len(rest)} observed /rest/ endpoints, {out['browser']['endpoints']} endpoints")
    print(f"static discovered 0 live API calls (its {out['static']['endpoints']} endpoints are "
          f"regex guesses from HTML/JS); browser-only /rest/ paths: {out['rest_paths_new_vs_static']}")
    print(f"results: {out_path}")


if __name__ == "__main__":
    main()
