"""Multi-level tool readiness: installed -> compatible -> functional -> assessment-ready.

A version string is not a working scanner. Each level is proven for real:

  installed        the binary resolves on disk
  compatible       a declared minimum version is met (an unknown version is not)
  functional       the version command exits 0
  assessment_ready the tool scans a CONTROLLED local fixture and its output parses
                   with the same parser the adapters use

A tool that works with a known limitation (no template library, no chromium,
no parseable ZAP report, a version below the minimum) reports `degraded`, never
`assessment_ready`. The fixture is an in-process http.server bound to 127.0.0.1
on an ephemeral port; no external host is ever dialled and every subprocess is
bounded by DEEP_TIMEOUT_S.
"""
import contextlib
import http.server
import os
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from . import ToolSpec, resolve_binary
from .adapters import PARSERS, _httpx_argv, _nmap_argv
from ..browser_crawl import browser_available
from .diagnostics import diagnose
from .zap_adapter import _zap_argv, parse_zap_report

CACHE_TTL_S = 300.0
DEEP_TIMEOUT_S = 30
FIXTURE_DIR = Path(__file__).parent / "fixtures"
MARKER = "libella-readiness-fixture"
PAGE = (f"<html><head><title>{MARKER}</title></head>"
        f"<body><h1>{MARKER}</h1><p>local fixture</p></body></html>")

# Declared minimum per tool. A build older than this is not exercised by
# Libella's tests, so it is reported as degraded rather than usable.
MIN_VERSIONS = {
    "nmap": "7.0",
    "nuclei": "3.0",
    "httpx": "1.3",
    "subfinder": "2.5",
    "ffuf": "2.0",
    "semgrep": "1.50",
    "trivy_fs": "0.40",
    "trivy_image": "0.40",
    "gitleaks": "8.0",
    "zap_baseline": "2.10",
    "browser": "0",
}

# Plain-English meaning, shown in the Tool Center: an operator must be able to
# tell "installed" from "I can rely on this scanner".
LEVELS = [
    ("missing", "Not installed. Checks that need it are skipped, so coverage is narrower."),
    ("installed", "On disk, but its version command failed. Treat it as broken."),
    ("compatible", "Reports a supported version, but the version command did not exit cleanly."),
    ("functional", "The version command runs. Libella has not exercised it against a fixture."),
    ("assessment_ready", "It scanned a local fixture and Libella parsed the result. Safe to rely on."),
    ("degraded", "It runs with a known limitation (listed). Do not count its coverage as complete."),
    ("unverified", "Libella cannot test this entry automatically. Its coverage is unproven."),
]

# shortcut: cached per binary for CACHE_TTL_S; a binary replaced inside the
# window reads stale until the next deep run.
_CACHE: dict[str, tuple[float, dict]] = {}
_DEEP_LOCK = threading.Lock()  # one fixture scan at a time: no scanner storms

# Assembled from parts so a secret scanner pointed at this repo does not flag
# the readiness fixture (gitleaks' github-pat rule needs the prefix + 36 chars).
_FAKE_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


class _NoTarget:
    """Scope-decision stand-in: the fixture is loopback, so no IP is resolved."""

    resolved_ips: list[str] = []


@contextlib.contextmanager
def _fixture():
    """Serve one static page on an ephemeral 127.0.0.1 port for the check."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            code = 200 if self.path in ("/", "/index.html", "/admin") else 404
            body = (PAGE if code == 200 else "not found").encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # a probe must not spam the server log
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def _exec(argv: list[str], timeout: float):
    """Run a bounded fixture scan and return (stdout, stderr, exit_code, timed_out)."""
    from .runner import _run_capped

    with tempfile.TemporaryDirectory() as home:
        out, err, code, timed_out, _ = _run_capped(
            argv, Path(home),
            {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home,
             "LANG": "C.UTF-8", "NO_COLOR": "1"},
            timeout)
    return out.decode(errors="replace"), err.decode(errors="replace"), code, timed_out


def _verdict(ok: bool, detail: str, limitation: str | None = None):
    return ok, detail, ([] if ok or limitation is None else [limitation])


def _deep_nmap(path: str):
    with _fixture() as base:
        port = urlparse(base).port
        argv = [path, *_nmap_argv({"target": "127.0.0.1", "ports": str(port)}, _NoTarget())[1:]]
        out, err, code, timed_out = _exec(argv, DEEP_TIMEOUT_S)
    if timed_out:
        return _verdict(False, "nmap did not finish the loopback scan in time",
                        "nmap timed out on a one-port loopback scan")
    if any(p["port"] == port for h in PARSERS["nmap"](out) for p in h["ports"]):
        return _verdict(True, f"nmap found the fixture port {port} open")
    return _verdict(False, f"nmap reported no open fixture port (exit {code})",
                    (err.strip() or "nmap returned no parsable XML")[:200])


def _deep_httpx(path: str):
    with _fixture() as base:
        argv = [path, *_httpx_argv({"target": base, "timeout": 10}, _NoTarget())[1:]]
        out, err, code, timed_out = _exec(argv, DEEP_TIMEOUT_S)
    if timed_out:
        return _verdict(False, "httpx did not finish the loopback probe in time",
                        "httpx timed out on the loopback fixture")
    rows = PARSERS["httpx"](out)
    if any(r["status_code"] == 200 for r in rows):
        return _verdict(True, "httpx probed the fixture and parsed a 200")
    # the Python `httpx` CLI shares the name: it prints usage, not JSONL
    return _verdict(False, f"httpx produced no parsable result (exit {code})",
                    "httpx output did not parse as ProjectDiscovery JSONL; "
                    "the binary on PATH may be the Python httpx CLI")


def _deep_nuclei(path: str):
    template = FIXTURE_DIR / "readiness.yaml"
    if not template.is_file():
        return _verdict(False, "the fixture template is missing from the install",
                        f"missing fixture template {template}")
    with _fixture() as base:
        argv = [path, "-u", base + "/", "-jsonl", "-silent", "-no-color",
                "-t", str(template), "-rate-limit", "20", "-timeout", "10",
                "-retries", "0", "-disable-update-check"]
        out, err, code, timed_out = _exec(argv, DEEP_TIMEOUT_S)
    if timed_out:
        return _verdict(False, "nuclei did not finish the fixture scan in time",
                        "nuclei timed out against the loopback fixture")
    hits = PARSERS["nuclei"](out)
    if not hits:
        return _verdict(False, f"nuclei matched nothing on the fixture (exit {code})",
                        (err.strip() or "nuclei returned no parsable JSONL")[:200])
    if _templates_dir() is None:
        return _verdict(False, "the fixture template matched",
                        "no nuclei-templates directory: the bundled template library "
                        "would match nothing on a real target")
    return _verdict(True, f"nuclei matched the fixture with {len(hits)} template hit(s)")


def _templates_dir() -> Path | None:
    candidates = (os.environ.get("LIBELLA_TEMPLATE_DIR") or "~/nuclei-templates",
                  "/usr/share/nuclei-templates")
    for candidate in candidates:
        p = Path(os.path.expanduser(candidate))
        if p.is_dir():
            return p
    return None


def _deep_ffuf(path: str):
    wordlist = FIXTURE_DIR / "wordlist.txt"
    if not wordlist.is_file():
        return _verdict(False, "the fixture wordlist is missing from the install",
                        f"missing fixture wordlist {wordlist}")
    with _fixture() as base, tempfile.TemporaryDirectory() as out_dir:
        # shortcut: the report goes to a file because ffuf prints matched paths
        # to stdout ahead of the JSON when -o is /dev/stdout; keep the remaining
        # flags in sync with adapters._ffuf_argv.
        report = Path(out_dir) / "ffuf.json"
        argv = [path, "-u", base + "/FUZZ", "-w", str(wordlist), "-of", "json",
                "-o", str(report), "-s", "-mc", "200", "-t", "4", "-timeout", "10"]
        _out, err, code, timed_out = _exec(argv, DEEP_TIMEOUT_S)
        out = report.read_text() if report.exists() else ""
    if timed_out:
        return _verdict(False, "ffuf did not finish the fixture run in time",
                        "ffuf timed out against the loopback fixture")
    hits = PARSERS["ffuf"](out)
    if hits:
        return _verdict(True, f"ffuf found {len(hits)} fixture path(s)")
    return _verdict(False, f"ffuf found nothing on the fixture (exit {code})",
                    (err.strip() or "ffuf returned no parsable JSON")[:200])


def _deep_code(name: str, path: str):
    """semgrep / trivy fs / gitleaks: scan a seeded temp dir with the real argv."""
    from .code_adapters import GITLEAKS, SEMGREP, TRIVY_FS
    from .code_adapters import PARSERS as CODE_PARSERS
    from .code_adapters import LocalCtx

    spec = {"semgrep": SEMGREP, "trivy_fs": TRIVY_FS, "gitleaks": GITLEAKS}[name]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text("eval(input())\n")  # matches the local ruleset
        (root / "secret.txt").write_text(f"token = {_FAKE_TOKEN}\n")
        ctx = LocalCtx(str(root / "ctx"), roots=[str(root)])
        params = {"repo": str(root)}
        if name == "trivy_fs":
            params["scanners"] = "secret,misconfig"
        argv = [path, *spec.handler(params, ctx)[1:]]
        out, err, code, timed_out = _exec(argv, DEEP_TIMEOUT_S)
        if name == "gitleaks":  # this adapter writes its report to a file
            report = Path(ctx.workdir) / "gitleaks.json"
            out = report.read_text() if report.exists() else ""
    if timed_out:
        return _verdict(False, f"{name} did not finish the temp-dir scan in time",
                        f"{name} timed out on a two-file directory")
    parsed = CODE_PARSERS[name](out)
    found = any(parsed.values()) if isinstance(parsed, dict) else bool(parsed)
    if found:
        return _verdict(True, f"{name} reported the seeded finding")
    return _verdict(False, f"{name} reported nothing on the seeded fixture (exit {code})",
                    (err.strip() or f"{name} output did not parse")[:200])


def _deep_zap(path: str):
    with _fixture() as base:
        argv = [path, *_zap_argv({"target": base + "/"}, _NoTarget())[1:]]
        out, err, code, timed_out = _exec(argv, DEEP_TIMEOUT_S)
    obs = parse_zap_report(out)
    if obs:  # only an actual baseline that Libella can parse counts
        return _verdict(True, f"ZAP baseline produced {len(obs)} parsed observation(s)")
    if timed_out:
        return _verdict(False, "ZAP did not finish a baseline in time",
                        "ZAP timed out after 30s against the fixture; a baseline run "
                        "is not proven (daemon/API mode is not managed by Libella)")
    return _verdict(False, f"ZAP produced no parsable report (exit {code})",
                    "ZAP did not produce a parsable baseline report against the "
                    "fixture; only a proven baseline would be assessment-ready")


def _render_probe(base: str):
    """Render the fixture in chromium and read the marker back out of the DOM."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(base + "/", timeout=15000)
            text = page.inner_text("h1")
            browser.close()
    except Exception as e:  # any driver/launch failure is a limitation, not a crash
        return False, f"rendering the fixture failed: {type(e).__name__}"
    return (MARKER in text), f"rendered the fixture page (h1={text[:40]!r})"


def _deep_browser(_path: str):
    if not browser_available():
        return _verdict(False, "no chromium build is installed",
                        "no chromium build: JS-rendered pages and the crawl phase are skipped")
    with _fixture() as base:
        ok, detail = _render_probe(base)
    return _verdict(ok, detail, "chromium did not render the fixture page")


DEEP = {
    "nmap": _deep_nmap,
    "httpx": _deep_httpx,
    "nuclei": _deep_nuclei,
    "ffuf": _deep_ffuf,
    "zap_baseline": _deep_zap,
    "browser": _deep_browser,
    "semgrep": lambda path: _deep_code("semgrep", path),
    "trivy_fs": lambda path: _deep_code("trivy_fs", path),
    "gitleaks": lambda path: _deep_code("gitleaks", path),
}


def clear_cache() -> None:
    _CACHE.clear()


def _at_least(version: str | None, minimum: str | None) -> bool:
    if not version:
        return False  # unknown version => not compatible
    if not minimum:
        return True
    parse = lambda v: tuple(int(x) for x in v.split("."))  # noqa: E731
    a, b = parse(version), parse(minimum)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) >= b + (0,) * (width - len(b))


def _row(name: str, status: str, level: str, detail: str, version: str | None = None,
         limitations: list[str] | None = None) -> dict:
    return {"name": name, "status": status, "level": level, "version": version,
            "minimum": MIN_VERSIONS.get(name), "degraded": status == "degraded",
            "limitations": limitations or [], "detail": detail, "checked_at": time.time()}


def _evaluate(spec: ToolSpec) -> dict:
    name = spec.name
    if spec.binary is None:
        if name not in DEEP:
            return _row(name, "unverified", "unverified",
                        "In-process adapter; no version probe configured.",
                        limitations=["no automatic check: coverage unproven"])
        # a capability with no CLI (browser automation) is judged by its fixture run
        with _DEEP_LOCK:
            ok, detail, limitations = DEEP[name]("")
        return _row(name, "assessment_ready" if ok else "degraded",
                    "assessment_ready" if ok else "functional", detail, limitations=limitations)

    diag = diagnose(spec)
    path = resolve_binary(spec.binary)
    version = diag["version"]
    if path is None:
        return _row(name, "missing", "missing", diag["detail"],
                    limitations=["not installed: checks that need this tool are skipped"])
    if diag["status"] != "ready":  # version command failed, hung, or printed nothing
        compatible = _at_least(version, MIN_VERSIONS.get(name))
        return _row(name, "compatible" if compatible else "installed",
                    "compatible" if compatible else "installed", diag["detail"], version,
                    limitations=[f"version command failed: {diag['detail']}"])
    if not _at_least(version, MIN_VERSIONS.get(name)):
        minimum = MIN_VERSIONS.get(name)
        why = (f"version {version} is below the supported minimum {minimum}"
               if version else f"version could not be recognised (minimum {minimum})")
        return _row(name, "degraded", "functional", diag["detail"], version,
                    limitations=[why])
    if name not in DEEP:
        return _row(name, "functional", "functional", diag["detail"], version,
                    limitations=["no local fixture check for this tool: assessment "
                                 "readiness is unproven"])
    with _DEEP_LOCK:
        ok, detail, limitations_ = DEEP[name](path)
    if ok:
        return _row(name, "assessment_ready", "assessment_ready", detail, version)
    return _row(name, "degraded", "functional", detail, version, limitations=limitations_)


def check(spec: ToolSpec, force: bool = False) -> dict:
    """Full readiness row for one tool, cached for CACHE_TTL_S unless forced."""
    key = spec.name  # keyed by name: two tools may share one binary (trivy fs/image)
    hit = _CACHE.get(key)
    if not force and hit and time.monotonic() - hit[0] < CACHE_TTL_S:
        return dict(hit[1])
    row = _evaluate(spec)
    _CACHE[key] = (time.monotonic(), row)
    return dict(row)


# Browser automation gates the API's browser routes but has no registry entry
# (there is no binary to probe), so it is reported alongside the tools.
EXTRA = [ToolSpec(name="browser", description="Chromium automation for the crawl phase.",
                  category="browser", params={}, required=[], binary=None)]


def report(registry) -> dict:
    """Readiness for every registered tool, plus the meaning of each level."""
    specs = list(registry.tools.values())
    specs += [s for s in EXTRA if s.name not in {t.name for t in specs}]
    rows = [check(spec) for spec in specs]
    return {"tools": rows,
            "levels": [{"name": name, "meaning": meaning} for name, meaning in LEVELS],
            # "as of" the newest cached row, so a cached report looks cached
            "checked_at": max((row["checked_at"] for row in rows), default=0.0)}
