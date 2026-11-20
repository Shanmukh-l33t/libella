"""Fixtures for PDF reporting / remediation tests: real App + seeded findings."""
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.api import App, create_api  # noqa: E402

SCOPE = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
         "categories": ["recon", "web", "api"], "rate_limit_rps": 20}

FINDINGS = [
    {"key": "sqli-products", "title": "SQL injection in parameter 'category'",
     "severity": "critical", "cwe": "CWE-89", "owasp": "A03:2021 Injection",
     "state": "validated", "endpoint": "http://127.0.0.1:8801/api/products",
     "description": "UNION payload extracts rows; marker 'alice' present.",
     "impact": "Arbitrary data extraction.", "remediation": "Parameterized queries."},
    {"key": "debug-exposed", "title": "Debug endpoint exposes configuration",
     "severity": "high", "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
     "state": "validated", "endpoint": "http://127.0.0.1:8801/debug",
     "description": "GET /debug returns 200 with db password=hunter2secret7 and "
                    "api_key=SUPERSECRETVALUE99",
     "impact": "Secret disclosure.", "remediation": "Remove the endpoint."},
    {"key": "missing-hsts", "title": "Missing HSTS header",
     "severity": "low", "cwe": "CWE-319", "owasp": "A02:2021 Cryptographic Failures",
     "state": "reported", "endpoint": "http://127.0.0.1:8802/",
     "description": "No strict-transport-security header.", "impact": "Downgrade risk.",
     "remediation": "Send HSTS."},
]


def add_engagement(app: App, eid: str, name: str, findings: list[dict] | None = None) -> str:
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at, started_at, finished_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (eid, name, "safe_active", "done", json.dumps(SCOPE), "{}", "{}",
         time.time(), time.time(), time.time()))
    for i, f in enumerate(findings if findings is not None else FINDINGS):
        now = time.time() + i
        app.db.execute(
            "INSERT INTO findings(id, engagement_id, title, cwe, owasp, severity, confidence, "
            "endpoint, state, description, impact, remediation, dedup_key, evidence_ids_json, "
            "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"f_{eid}_{i}", eid, f["title"], f["cwe"], f["owasp"], f["severity"], "high",
             f["endpoint"], f["state"], f["description"], f["impact"], f["remediation"],
             f["key"], "[]", now, now))
    app.db.emit(eid, "degradation", {"code": "tls_unreachable", "detail": "port 443 filtered"})
    return eid


@pytest.fixture
def app(tmp_path):
    return App(tmp_path / "data")


@pytest.fixture
def client(app):
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    return c


@pytest.fixture
def pair(app):
    """Two engagements sharing dedup keys, plus one new and one dropped finding."""
    add_engagement(app, "eng_a", "PairLab vuln")
    add_engagement(app, "eng_b", "PairLab hardened", [
        {**FINDINGS[0], "key": "sqli-products"},  # persisting
        {**FINDINGS[1], "key": "debug-exposed", "severity": "medium"},  # severity changed
        {**FINDINGS[2], "key": "open-redirect", "title": "Open redirect in 'next'",
         "severity": "medium"},  # new
    ])
    return app


@pytest.fixture
def report_json_path(pair):
    from libella.report import render_report
    res = render_report(pair.db, pair.evidence, "eng_a")
    return Path(res["outdir"]) / "report.json"
