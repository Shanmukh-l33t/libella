"""Fixtures for the API module: real ApiLab twins on localhost + a Libella engine.

Twins are started in-process on ephemeral ports so the same module can serve
both modes; every request still crosses a real socket and goes through HttpProbe.
"""
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "labs/apilab"))

import labctl  # noqa: E402
from libella.api import App  # noqa: E402
from libella.api_audit import assess_api, load_openapi  # noqa: E402
from libella.scope import Scope  # noqa: E402

OPENAPI = ROOT / "labs/apilab/openapi.json"
GT = json.loads((ROOT / "labs/apilab/ground_truth.json").read_text())


@pytest.fixture(scope="session")
def labs():
    started = {mode: labctl.start_lab(mode) for mode in ("vuln", "hardened")}
    yield {mode: base for mode, (base, _) in started.items()}
    for _, srv in started.values():
        srv.shutdown()


@pytest.fixture(scope="session")
def spec():
    return load_openapi(OPENAPI)


class Engine:
    """One engagement over one lab twin: DB, evidence store, probe, pipeline."""

    def __init__(self, data_dir: Path, base: str):
        self.app = App(data_dir)
        self.base = base
        # "web" is included because the verifier replays proofs under its default category
        self.scope = Scope({"targets": [{"kind": "url", "value": base}],
                            "categories": ["api", "web"], "rate_limit_rps": 1000})
        self.eid = f"eng_api_{int(time.time() * 1e6)}"
        self.app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (self.eid, "apilab", "safe_active", "draft",
             json.dumps({"targets": [{"kind": "url", "value": base}]}), "{}", "{}", time.time()))

    def assess(self, identities=None):
        return assess_api(self.base, OPENAPI, identities or GT["identities"], self.app.db,
                          self.app.evidence, self.app.pipeline, self.app.probe, self.scope, self.eid)

    def findings(self):
        return self.app.pipeline.list(self.eid)


@pytest.fixture(scope="session")
def results(tmp_path_factory, labs):
    """assess_api once per mode (slow part), shared by the check tests."""
    out = {}
    for mode in ("vuln", "hardened"):
        eng = Engine(tmp_path_factory.mktemp(mode), labs[mode])
        out[mode] = (eng, eng.assess())
    return out


@pytest.fixture
def engine(tmp_path, labs):
    return Engine(tmp_path / "data", labs["vuln"])


@pytest.fixture
def engine_for(tmp_path, labs):
    def make(mode):
        return Engine(tmp_path / mode, labs[mode])
    return make
