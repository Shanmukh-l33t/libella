"""Fixtures for the source-code assessment tests.

Local fixture repos only; the sole network use is the OSV advisory lookup.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.codeaudit import assess_repo  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402

LABS = ROOT / "labs"


@pytest.fixture(scope="session")
def assessed(tmp_path_factory):
    """Assess both fixture repos once; every test reads the recorded results."""
    tmp = tmp_path_factory.mktemp("code")
    db = DB(tmp / "db.sqlite")
    evidence = EvidenceStore(db, tmp / "evidence")
    pipeline = FindingPipeline(db, evidence)
    runs = {}
    for name in ("vulnrepo", "cleanrepo"):
        eid = f"eng_code_{name}"
        db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (eid, name, "safe_active", "draft", "{}", "{}", "{}", 0.0),
        )
        runs[name] = assess_repo(LABS / name, db, evidence, pipeline, eid,
                                 roots=[str(LABS)])
    return SimpleNamespace(db=db, evidence=evidence, pipeline=pipeline, runs=runs,
                           labs=LABS)


@pytest.fixture
def findings(assessed):
    def get(name):
        return assessed.db.query(
            "SELECT * FROM findings WHERE engagement_id=? ORDER BY id",
            (assessed.runs[name]["engagement_id"],))
    return get


@pytest.fixture
def observations(assessed):
    def get(name):
        return assessed.db.query(
            "SELECT * FROM observations WHERE engagement_id=? ORDER BY created_at",
            (assessed.runs[name]["engagement_id"],))
    return get
