"""Bounded same-origin crawler + JS/API route extraction."""
import re
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

from .tools.http_probe import HttpProbe

LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.I)
SCRIPT_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
JS_URL_RE = re.compile(r"""["'`](/(?:api|rest|graphql|v1|v2|ftp|administration|socket\.io)[^"'`\s]{0,200})["'`]""")
FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
INPUT_RE = re.compile(r"<input[^>]*name\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.I)


class Crawler:
    def __init__(self, probe: HttpProbe, engagement_id: str, scope,
                 max_pages: int = 40, max_depth: int = 3, max_scripts: int = 12):
        self.probe = probe
        self.eng = engagement_id
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_scripts = max_scripts

    def crawl(self, base_url: str) -> dict:
        base = base_url.rstrip("/")
        origin = urlparse(base)
        seen = set()
        pages = []
        endpoints = set()
        forms = []
        scripts_seen = set()
        scripts_done = 0
        q = deque([(base + "/", 0)])
        while q and len(pages) < self.max_pages:
            url, depth = q.popleft()
            url, _ = urldefrag(url)
            if url in seen or depth > self.max_depth:
                continue
            p = urlparse(url)
            if p.netloc != origin.netloc or p.scheme not in ("http", "https"):
                continue
            seen.add(url)
            r = self.probe.request(self.eng, self.scope, url, tool="crawl")
            if not r.get("ok"):
                continue
            ct = r["headers"].get("content-type", "")
            body = r["body"]
            page = {"url": url, "status": r["status"], "exchange_id": r["exchange_id"],
                    "title": None, "links": [], "params": []}
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if m:
                page["title"] = m.group(1).strip()[:120]
            if "html" in ct:
                for link in LINK_RE.findall(body):
                    absu = urljoin(url, link)
                    absu, _ = urldefrag(absu)
                    pu = urlparse(absu)
                    if pu.netloc == origin.netloc and pu.scheme in ("http", "https"):
                        page["links"].append(absu)
                        if absu not in seen:
                            q.append((absu, depth + 1))
                    if JS_URL_RE.search(link):
                        endpoints.add(absu)
                for fm in FORM_RE.finditer(body):
                    form_html = fm.group(0)
                    action = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_html, re.I)
                    method = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_html, re.I)
                    names = INPUT_RE.findall(form_html)
                    forms.append({
                        "page": url,
                        "action": urljoin(url, action.group(1)) if action else url,
                        "method": (method.group(1) if method else "GET").upper(),
                        "inputs": names,
                    })
                # query params already present
                if p.query:
                    page["params"] = [kv.split("=")[0] for kv in p.query.split("&") if "=" in kv]
            for js in JS_URL_RE.findall(body):
                endpoints.add(urljoin(url, js))
            # fetch same-origin JS bundles and mine API routes (SPA coverage)
            if "html" in ct:
                for ssrc in SCRIPT_RE.findall(body):
                    surl = urljoin(url, ssrc)
                    sp = urlparse(surl)
                    if sp.netloc != origin.netloc or surl in scripts_seen:
                        continue
                    if scripts_done >= self.max_scripts:
                        break
                    scripts_seen.add(surl)
                    scripts_done += 1
                    sr = self.probe.request(self.eng, self.scope, surl, tool="js_mining",
                                            body_cap=2 * 1024 * 1024)
                    if sr.get("ok") and sr["status"] == 200:
                        for route in JS_URL_RE.findall(sr["body"]):
                            endpoints.add(urljoin(url, route))
            pages.append(page)
            if url not in endpoints:
                endpoints.add(url)
        return {"pages": pages, "endpoints": sorted(endpoints), "forms": forms,
                "crawled": len(pages), "limit_hit": len(pages) >= self.max_pages}
