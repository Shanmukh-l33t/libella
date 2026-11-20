"""Fixtures for the GraphQL module: real GraphLab twins on localhost + an engine.

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
sys.path.insert(0, str(ROOT / "labs/graphlab"))

import graphlab_labctl as labctl  # noqa: E402
from libella.api import App  # noqa: E402
from libella.graphql_audit import assess_graphql  # noqa: E402
from libella.scope import Scope  # noqa: E402

GT = json.loads((ROOT / "labs/graphlab/ground_truth.json").read_text())


@pytest.fixture(scope="session")
def seeds():
    """Every check the module must land, with the CWE it must carry."""
    return [
        ("gql:introspection", "CWE-200"),
        ("gql:sqli:users", "CWE-89"),
        ("gql:fieldauthz:user", "CWE-639"),
        ("gql:fieldauthz:adminstats", "CWE-639"),
        ("gql:depth", "CWE-770"),
        ("gql:alias", "CWE-770"),
        ("gql:batch", "CWE-770"),
    ]


@pytest.fixture(scope="session")
def labs():
    started = {mode: labctl.start_lab(mode) for mode in ("vuln", "hardened")}
    yield {mode: base for mode, (base, _) in started.items()}
    for _, srv in started.values():
        srv.shutdown()


class Engine:
    """One engagement over one lab twin: DB, evidence store, probe, pipeline."""

    def __init__(self, data_dir: Path, base: str):
        self.app = App(data_dir)
        self.base = base
        # "web" is included because the verifier replays proofs under its default category
        self.scope = Scope({"targets": [{"kind": "url", "value": base}],
                            "categories": ["api", "web"], "rate_limit_rps": 1000})
        self.eid = f"eng_gql_{int(time.time() * 1e6)}"
        self.app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (self.eid, "graphlab", "safe_active", "draft",
             json.dumps({"targets": [{"kind": "url", "value": base}]}), "{}", "{}", time.time()))

    def assess(self, identities=None, scope=None):
        return assess_graphql(self.base + "/graphql", self.app.db, self.app.evidence,
                              self.app.pipeline, self.app.probe, scope or self.scope, self.eid,
                              identities or GT["identities"])

    def findings(self):
        return self.app.pipeline.list(self.eid)

    def proof_spec(self, finding):
        for eid in finding["evidence_ids"]:
            row = self.app.db.one("SELECT kind FROM evidence WHERE id=?", (eid,))
            if row and row["kind"] == "proof_spec":
                return self.app.evidence.read_json(eid)
        return None


@pytest.fixture(scope="session")
def results(tmp_path_factory, labs):
    """assess_graphql once per mode (slow part), shared by the check tests."""
    out = {}
    for mode in ("vuln", "hardened"):
        eng = Engine(tmp_path_factory.mktemp(mode), labs[mode])
        out[mode] = (eng, eng.assess())
    return out


@pytest.fixture
def engine(tmp_path, labs):
    return Engine(tmp_path / "data", labs["vuln"])
