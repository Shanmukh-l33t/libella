"""The Overview must not contradict Coverage and the report on a long run.

Defect: degradation banners came from the newest 400 feed events, so a coverage limit followed
by more than 400 later events silently left the Overview. Banners now come from the whole
cursor-filled event log. The page is rendered for real (esbuild bundle, react-dom/server).
"""
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from libella.api import App, create_api  # noqa: E402

WEB = ROOT / "web"
ESBUILD = WEB / "node_modules/.bin/esbuild"
pytestmark = pytest.mark.skipif(not (ESBUILD.exists() and shutil.which("node")), reason="web toolchain absent")

ENTRY = """
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import Overview from "%(ov)s";
import { feedView } from "%(feed)s";
const { eng, rows } = JSON.parse(require("fs").readFileSync(0, "utf8"));
const view = feedView(rows);
process.stdout.write(renderToStaticMarkup(
  <Overview eid="eng_x" eng={eng} live={0} events={view.events} degradations={view.degradations} />));
"""


def _render(tmp_path, eng, rows):
    entry = tmp_path / "entry.tsx"
    entry.write_text(ENTRY % {"ov": WEB / "src/pages/engagement/Overview.tsx",
                              "feed": WEB / "src/lib/feed.ts"})
    out = tmp_path / "entry.cjs"
    env = {"PATH": str(Path(shutil.which("node")).parent) + ":/usr/bin:/bin", "NODE_PATH": str(WEB / "node_modules")}
    subprocess.run([str(ESBUILD), str(entry), "--bundle", "--platform=node", "--format=cjs",
                    "--jsx=automatic", f"--outfile={out}", "--log-level=error"],
                   check=True, env=env, cwd=WEB)
    res = subprocess.run(["node", str(out)], input=json.dumps({"eng": eng, "rows": rows}),
                         capture_output=True, text=True, check=True, env=env)
    return res.stdout


def _engagement(tmp_path, noisy_after, degrade):
    app = App(tmp_path / "data")
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}], "categories": ["web"]}
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng_x", "ops", "safe_active", "running", json.dumps(scope), "{}", "{}", time.time()))
    app.db.emit("eng_x", "engagement_started", {"mode": "deterministic"})
    if degrade:
        app.db.emit("eng_x", "degradation", {"code": "target_mitigated", "detail": "WAF challenge on /login"})
    for n in range(noisy_after):
        app.db.emit("eng_x", "tool_call", {"tool": "httpx", "n": n})
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    rows, cursor = [], 0  # the client's own cursor fill, paging at 500
    while True:
        page = c.get("/api/engagements/eng_x/events", params={"since": cursor}).json()
        rows += page
        if len(page) < 500:
            break
        cursor = page[-1]["seq"]
    return c.get("/api/engagements/eng_x").json(), rows


def test_old_degradation_still_shown_after_400_later_events(tmp_path):
    eng, rows = _engagement(tmp_path, 450, degrade=True)
    assert not any(r["kind"] == "degradation" for r in sorted(rows, key=lambda r: -r["seq"])[:400])
    html = _render(tmp_path, eng, rows)
    assert "The target answered with a bot/WAF challenge" in html
    assert "WAF challenge on /login" in html


def test_no_degradation_no_banner(tmp_path):
    eng, rows = _engagement(tmp_path, 450, degrade=False)
    html = _render(tmp_path, eng, rows)
    assert "bot/WAF challenge" not in html and "coverage limits recorded" not in html
    assert "Tool call" in html  # the page did render
