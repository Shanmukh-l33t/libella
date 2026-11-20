"""CloudLab twins (out-of-process moto) + per-test audit environment."""
import importlib.util
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402
from libella.scope import Scope  # noqa: E402


def _load(name: str, rel: str):
    """Private module load: tests/api and tests/authbrowser also own a `labctl`."""
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


labctl = _load("cloudlab_labctl", "labs/cloudlab/labctl.py")


def make_env(tmp_path: Path, endpoint: str, account_scope: str | None = None,
             eid: str = "eng_cloud") -> SimpleNamespace:
    db = DB(Path(tmp_path) / f"{eid}.db")
    evidence = EvidenceStore(db, Path(tmp_path) / "evidence")
    scope_spec = {"targets": [{"kind": "cloud", "value": account_scope or endpoint}],
                  "categories": ["cloud"]}
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
        "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, "cloud", "safe_active", "draft", json.dumps(scope_spec), "{}", "{}",
         time.time()))
    return SimpleNamespace(db=db, evidence=evidence,
                           pipeline=FindingPipeline(db, evidence),
                           scope=Scope(scope_spec), eid=eid, endpoint=endpoint)


@pytest.fixture(scope="session")
def cloud():
    """The CloudLab control module (start_lab/stop_lab/creds)."""
    return labctl


@pytest.fixture
def app(tmp_path):
    from libella.api import App
    return App(Path(tmp_path) / "data")


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    from libella.api import create_api
    return TestClient(create_api(app))


@pytest.fixture(scope="session")
def labs():
    started = {mode: labctl.start_lab(mode) for mode in ("vuln", "hardened")}
    yield {mode: url for mode, (url, _proc) in started.items()}
    for _url, proc in started.values():
        labctl.stop_lab(proc)


@pytest.fixture
def audit_env(tmp_path):
    """audit_env(endpoint, account_scope=None, eid=...) -> env namespace."""
    return lambda endpoint, account_scope=None, eid="eng_cloud": make_env(
        tmp_path, endpoint, account_scope, eid)


@pytest.fixture
def vuln(tmp_path, labs):
    """(env, assess result) for one run against the vulnerable twin."""
    from libella.cloud_audit import assess_cloud

    env = make_env(tmp_path, labs["vuln"], eid="eng_vuln")
    result = assess_cloud(env.endpoint, "us-east-1", labctl.creds(), env.db, env.evidence,
                          env.pipeline, env.scope, env.eid)
    return env, result
