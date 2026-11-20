"""Regression: refusal paths must work when scanner binaries are absent (CI).

The original code crashed with TypeError on the missing-binary/invalid-params
audit calls because the target argument was omitted. Locally the tools were
installed so the paths never ran; CI (no semgrep/trivy) exposed it.
"""
import tempfile

import pytest

from libella import codeaudit
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.tools.code_adapters import SEMGREP


@pytest.fixture
def platform(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    pipe = FindingPipeline(db, ev)
    return db, ev, pipe


def test_missing_binary_degrades_gracefully(platform, tmp_path, monkeypatch):
    db, ev, pipe = platform
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    monkeypatch.setattr(codeaudit, "_binary", lambda name: None)
    res = codeaudit.assess_repo(str(repo), db, ev, pipe, "eng", roots=[str(tmp_path)],
                                dependencies=False)
    assert res["degradations"], "missing tools must be visible degradations"
    calls = db.query("SELECT * FROM tool_calls WHERE engagement_id='eng'")
    assert calls, "refusal must be audited"
    assert all(c["scope_decision"].startswith("refused") for c in calls)
    assert all(c["error"] for c in calls)


def test_invalid_params_refusal_audited(platform, tmp_path):
    db, ev, pipe = platform
    repo = tmp_path / "repo"
    repo.mkdir()
    ctx = codeaudit.LocalCtx(tempfile.mkdtemp(prefix="libella-test-"), roots=[str(tmp_path)])
    res = codeaudit._exec(SEMGREP, {"repo": str(repo), "ruleset": "bogus-value"},
                          ctx, db, ev, "eng", None)
    assert res["ok"] is False
    assert res["error"].startswith("invalid_params")
    calls = db.query("SELECT * FROM tool_calls WHERE engagement_id='eng'")
    assert calls and calls[0]["scope_decision"].startswith("refused")
    assert calls[0]["error"]
