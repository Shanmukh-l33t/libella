"""Fixtures for technology modules: real TechLab twins on localhost + an engine.

Both twins run in-process on ephemeral ports; every probe still crosses a real
socket and goes through HttpProbe, so detection sees real headers and bodies.
"""
import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.api import App  # noqa: E402

from libella.scope import Scope  # noqa: E402
from libella.tech_modules import TechAssess  # noqa: E402

# load by path: every lab ships its own labctl.py and a bare `import labctl`
# resolves to whichever lab imported first
_spec = importlib.util.spec_from_file_location("techlab_labctl",
                                               ROOT / "labs/techlab/labctl.py")
labctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(labctl)

GT = json.loads((ROOT / "labs/techlab/ground_truth.json").read_text())
PREFIX = GT["prefixes"]
TECHS = list(PREFIX)


@pytest.fixture(scope="session")
def labs():
    started = {mode: labctl.start_lab(mode) for mode in ("vuln", "hardened")}
    yield {mode: v[0] for mode, v in started.items()}
    for _, srv in started.values():
        srv.shutdown()


class Engine:
    """One engagement over one lab twin: DB, evidence store, probe, assessor."""

    def __init__(self, data_dir: Path, base: str, target: str | None = None):
        self.app = App(data_dir)
        self.base = base
        self.scope = Scope({"targets": [{"kind": "url", "value": target or base}],
                            "categories": ["web"], "rate_limit_rps": 1000})
        self.eid = f"eng_tech_{int(time.time() * 1e6)}"
        self.app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (self.eid, "techlab", "safe_active", "draft", json.dumps({"targets": []}),
             "{}", "{}", time.time()))

    def assess(self, tech: str) -> dict:
        return TechAssess(self.app.probe, self.eid, self.scope).assess(self.base + PREFIX[tech])

    def evidence_exists(self, ev_id: str) -> bool:
        return self.app.db.one("SELECT id FROM evidence WHERE id=? AND engagement_id=?",
                               (ev_id, self.eid)) is not None

    def events(self, kind: str) -> list[dict]:
        return self.app.db.query(
            "SELECT payload_json FROM events WHERE engagement_id=? AND kind=?", (self.eid, kind))


@pytest.fixture(scope="session")
def results(tmp_path_factory, labs):
    """Assess every stack once per mode (the slow part), shared by the tests."""
    out = {}
    for mode in ("vuln", "hardened"):
        eng = Engine(tmp_path_factory.mktemp(mode), labs[mode])
        out[mode] = (eng, {tech: eng.assess(tech) for tech in TECHS})
    return out


@pytest.fixture
def engine_for(tmp_path, labs):
    def make(mode: str, target: str | None = None) -> Engine:
        return Engine(tmp_path / f"{mode}-{time.time_ns()}", labs[mode], target=target)
    return make
