"""Raw-socket confinement, proven with real sockets and independent hit logs.

A fake scanner (tests/fixtures/raw_tool.py, which ignores every proxy) dials three
fixtures that all live on the host and are all ROUTABLE from the namespace:
  AUTH  = A:pA   authorized
  PORT  = A:pB   same address, unauthorized port
  ADDR  = B:pA   other address, same port, unauthorized address
Hits are counted on TCP *accept* in the fixture, so a blocked connection that merely
looks like success cannot be counted, and a blanket refusal cannot pass: every
negative here has the positive (AUTH reached) next to it, and the mutation tests
show the negatives flip when the in-namespace rule they depend on is removed.
"""
import os
import random
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import libella.netns as netns  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.netns import Confinement, NetnsUnavailable  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools import ToolSpec  # noqa: E402
from libella.tools import runner as runner_mod  # noqa: E402
from libella.tools.runner import ToolRunner  # noqa: E402

PY = "/usr/bin/python3"  # stdlib-only tool; the venv python is not reachable by uid 65534
RAW = Path(__file__).parent / "fixtures" / "raw_tool.py"
EID = "eng_netns"


def _have(*cmds):
    return all(shutil.which(c, path="/usr/sbin:/sbin:/usr/bin:/bin") for c in cmds)


needs_netns = pytest.mark.skipif(
    os.geteuid() != 0 or not _have("ip", "nft", "setpriv") or not os.path.exists(PY),
    reason="network namespaces need root + ip/nft/setpriv")


def _ip(*a, check=True):
    return subprocess.run(["ip", *a], capture_output=True, text=True, check=check).stdout


def leaked() -> list[str]:
    """Our namespaces and veth ends still present (docker's own veths are not ours)."""
    names = [ln.split()[0] for ln in _ip("netns", "list").splitlines() if ln.strip()]
    names += [ln.split(":")[1].strip().split("@")[0] for ln in _ip("-o", "link", "show").splitlines()]
    return sorted(n for n in names if n.startswith(("lbns", "lbh", "lbn")))


class Fixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host, port=0):
        self.hits = []
        outer = self

        class H(socketserver.BaseRequestHandler):
            def setup(self):  # accept-level count: the TCP connection happened
                outer.hits.append(self.client_address[0])

            def handle(self):
                try:
                    self.request.recv(64)
                except OSError:
                    pass

        super().__init__((host, port), H)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def target(self):
        return f"{self.server_address[0]}:{self.server_address[1]}"

    def close(self):
        self.shutdown()
        self.server_close()


@pytest.fixture
def lab():
    """Two extra host-local addresses on lo + fixtures; routable from a veth namespace."""
    r = random.randrange(1, 250)
    a, b = f"10.77.{r}.1", f"10.77.{r}.2"
    for ip in (a, b):
        _ip("addr", "add", f"{ip}/32", "dev", "lo")
    auth = Fixture(a)
    port = Fixture(a)
    addr = Fixture(b, auth.server_address[1])
    try:
        yield type("Lab", (), {"a": a, "b": b, "auth": auth, "port": port, "addr": addr,
                               "ports": [auth.server_address[1]]})
    finally:
        for f in (auth, port, addr):
            f.close()
        for ip in (a, b):
            _ip("addr", "del", f"{ip}/32", "dev", "lo", check=False)


@pytest.fixture(scope="module")
def tool_dir():
    d = tempfile.mkdtemp(prefix="lbtool", dir="/tmp")  # world-traversable, unlike $TMPDIR
    os.chmod(d, 0o755)
    shutil.copy(RAW, d)
    os.chmod(Path(d) / "raw_tool.py", stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _argv(tool_dir, lab, *extra):
    return [PY, f"{tool_dir}/raw_tool.py", lab.auth.target, lab.port.target, lab.addr.target, *extra]


@pytest.fixture
def engine(tmp_path):
    db = DB(tmp_path / "n.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)", (EID, "n", "safe_active", "running", "{}", "{}", "{}", 0.0))
    return db, ev


def _spec(argv, name="nmap", timeout=30):
    return ToolSpec(name=name, description="", category="infra", binary=None, timeout_s=timeout,
                    params={"target": {"type": "string"}, "ports": {"type": "string"}},
                    required=["target"], handler=lambda p, d: list(argv), port_param="ports")


def _scope(lab):
    return Scope({"targets": [{"kind": "ip", "value": lab.a}], "categories": ["infra"],
                  "allowed_ports": lab.ports, "rate_limit_rps": 1000})


def _run(engine, tmp_path, lab, argv, runner=None, **kw):
    runner = runner or ToolRunner(engine[0], engine[1], tmp_path / "runs")
    return runner.run(_spec(argv, **kw), {"target": lab.a, "ports": str(lab.ports[0])}, _scope(lab),
                      EID, None, target=lab.a, category="infra")


def _events(db, kind):
    return [e["payload_json"] for e in db.query(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind=?", (EID, kind))]


def _flush(*fixtures):
    return [len(f.hits) for f in fixtures]


# -- 1+2: permitted AND blocked, through the runner ------------------------------

@needs_netns
def test_raw_tool_reaches_only_the_authorized_address_and_port(engine, tmp_path, lab, tool_dir):
    before = leaked()
    r = _run(engine, tmp_path, lab, _argv(tool_dir, lab))
    assert r["egress"]["level"] == "isolated", r["egress"]
    assert len(lab.auth.hits) >= 1, f"authorized fixture never contacted (blanket refusal?): {r}"
    assert lab.port.hits == [], "unauthorized PORT on the authorized host was reached"
    assert lab.addr.hits == [], "unauthorized ADDRESS (same port) was reached"
    out = r["stdout"]
    assert f"{lab.auth.target} CONNECTED" in out
    assert f"{lab.port.target} FAILED" in out and f"{lab.addr.target} FAILED" in out
    assert leaked() == before
    ev = _events(engine[0], "egress_degradation")
    assert any("egress_isolated" in e and "policy drop" in e for e in ev), ev  # names what was enforced


@needs_netns
def test_tool_cannot_alter_the_filter_it_runs_under(lab, tool_dir):
    with Confinement([lab.a], lab.ports) as c:
        r = c.run([PY, "-c", "import subprocess,sys;sys.exit(subprocess.call(['nft','flush','ruleset']))"])
        assert r.exit_code != 0  # uid 65534, no capabilities
        assert "policy drop" in subprocess.run(
            ["ip", "netns", "exec", c.ns, "nft", "list", "chain", "inet", "guard", "o"],
            capture_output=True, text=True).stdout
        c.run(_argv(tool_dir, lab)[:2] + [lab.addr.target])
    assert lab.addr.hits == []


# -- 4: mutations: the negatives are not vacuous ---------------------------------

@needs_netns
def test_mutation_without_the_allow_rule_the_authorized_connection_fails(lab, tool_dir):
    with Confinement([lab.a], lab.ports) as c:
        ok = c.run(_argv(tool_dir, lab)[:3])
        assert f"{lab.auth.target} CONNECTED" in ok.stdout.decode()
        n = len(lab.auth.hits)
        subprocess.run(["ip", "netns", "exec", c.ns, "nft", "flush", "chain", "inet", "guard", "o"], check=True)
        bad = c.run(_argv(tool_dir, lab)[:3])
        assert f"{lab.auth.target} FAILED" in bad.stdout.decode()
        assert len(lab.auth.hits) == n, "authorized fixture still reached with no allow rule"


@needs_netns
def test_mutation_without_the_filter_the_unauthorized_destinations_are_reached(lab, tool_dir):
    with Confinement([lab.a], lab.ports) as c:
        blocked = c.run([PY, f"{tool_dir}/raw_tool.py", lab.addr.target, lab.port.target])
        assert blocked.exit_code == 1 and lab.addr.hits == [] and lab.port.hits == []
        subprocess.run(["ip", "netns", "exec", c.ns, "nft", "delete", "table", "inet", "guard"], check=True)
        open_ = c.run([PY, f"{tool_dir}/raw_tool.py", lab.addr.target, lab.port.target])
        assert open_.exit_code == 0, open_.stdout
    assert len(lab.addr.hits) >= 1 and len(lab.port.hits) >= 1, \
        "both destinations are routable: only the filter was keeping them out"


# -- 3: nothing is left behind ---------------------------------------------------

@needs_netns
def test_cleanup_on_success_exception_and_timeout(lab, tool_dir):
    before = leaked()
    with Confinement([lab.a], lab.ports):
        assert leaked() != before  # it really created something
    assert leaked() == before
    with pytest.raises(RuntimeError, match="boom"):
        with Confinement([lab.a], lab.ports):
            raise RuntimeError("boom")
    assert leaked() == before
    with Confinement([lab.a], lab.ports) as c:
        t0 = time.time()
        r = c.run([PY, f"{tool_dir}/raw_tool.py", "--loop", lab.auth.target], timeout=1)
        assert r.timed_out and time.time() - t0 < 10
    assert leaked() == before


@needs_netns
def test_runner_timeout_cancel_and_tool_error_leave_nothing(engine, tmp_path, lab, tool_dir, monkeypatch):
    before = leaked()
    loop = _argv(tool_dir, lab, "--loop")
    r = _run(engine, tmp_path, lab, loop, timeout=1)
    assert r["status"] == "timeout" and r["egress"]["level"] == "isolated" and len(lab.auth.hits) >= 1
    assert leaked() == before

    n, res = len(lab.auth.hits), {}
    t = threading.Thread(target=lambda: res.update(_run(engine, tmp_path, lab, loop)))
    t.start()
    for _ in range(300):
        if len(lab.auth.hits) >= n + 2:
            break
        time.sleep(0.02)
    engine[0].execute("UPDATE engagements SET status='cancelled' WHERE id=?", (EID,))
    t.join(20)
    assert not t.is_alive() and res["cancelled"] is True, res
    assert leaked() == before
    seen = len(lab.auth.hits)
    time.sleep(0.5)
    assert len(lab.auth.hits) == seen, "traffic continued after cancel"
    assert lab.port.hits == [] and lab.addr.hits == []

    engine[0].execute("UPDATE engagements SET status='running' WHERE id=?", (EID,))
    monkeypatch.setattr(runner_mod, "_run_capped", lambda *a, **k: (_ for _ in ()).throw(OSError("pipe")))
    with pytest.raises(OSError):
        _run(engine, tmp_path, lab, loop)
    assert leaked() == before


@needs_netns
def test_reaper_removes_what_a_dead_process_left(lab):
    dead = 4194300
    while netns._pid_alive(dead):
        dead -= 1
    ns, h, n = f"lbns{dead}_abc", f"lbh{dead}_abc", f"lbn{dead}_abc"
    _ip("netns", "add", ns)
    _ip("link", "add", h, "type", "veth", "peer", "name", n)
    _ip("link", "set", n, "netns", ns)
    assert ns in leaked() and h in leaked()
    with Confinement([lab.a], lab.ports):  # entering reaps orphans of dead pids
        pass
    assert ns not in leaked() and h not in leaked()
    assert netns.reap_orphans() == []


# -- 5: fail closed --------------------------------------------------------------

@needs_netns
def test_fail_closed_when_isolation_cannot_be_set_up(engine, tmp_path, lab, tool_dir, monkeypatch):
    before = leaked()
    monkeypatch.setattr(netns, "_bin", lambda name: "/bin/false")  # every ip/nft call fails
    r = _run(engine, tmp_path, lab, _argv(tool_dir, lab))
    assert r["ok"] is False and r["egress"]["level"] == "fail_closed", r
    assert r["error"].startswith("egress_isolation_unavailable") and "stdout" not in r
    assert (lab.auth.hits, lab.port.hits, lab.addr.hits) == ([], [], []), "the tool ran anyway"
    rows = engine[0].query("SELECT scope_decision FROM tool_calls WHERE engagement_id=?", (EID,))
    assert any("egress isolation unavailable" in x["scope_decision"] for x in rows), rows
    ev = _events(engine[0], "egress_degradation")
    assert any("egress_fail_closed" in e for e in ev) and not any("egress_isolated" in e for e in ev), ev
    assert leaked() == before


@needs_netns
def test_non_local_and_loopback_targets_fail_closed_never_half_confined(engine, tmp_path, lab, tool_dir):
    for ip in ("127.0.0.1", "203.0.113.7"):  # loopback is another host inside the ns; TEST-NET is remote
        with pytest.raises(NetnsUnavailable):
            Confinement([ip], [80]).__enter__()
    r = ToolRunner(engine[0], engine[1], tmp_path / "runs").run(
        _spec(_argv(tool_dir, lab)), {"target": "203.0.113.7"},
        Scope({"targets": [{"kind": "ip", "value": "203.0.113.7"}], "categories": ["infra"]}),
        EID, None, target="203.0.113.7", category="infra")
    assert r["egress"]["level"] == "fail_closed" and lab.auth.hits == [], r


# -- explicit opt-out ------------------------------------------------------------

@needs_netns
def test_explicit_opt_out_runs_unconfined_and_says_so(engine, tmp_path, lab, tool_dir):
    runner = ToolRunner(engine[0], engine[1], tmp_path / "runs", raw_egress="unconfined")
    r = _run(engine, tmp_path, lab, _argv(tool_dir, lab), runner=runner)
    assert r["egress"]["level"] == "unconfined" and "opt-out" in r["egress"]["residual"]
    assert len(lab.addr.hits) >= 1 and len(lab.port.hits) >= 1, "unconfined means argv is the only boundary"
    assert any("egress_unconfined" in e for e in _events(engine[0], "egress_degradation"))
