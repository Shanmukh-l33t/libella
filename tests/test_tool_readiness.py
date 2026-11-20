"""Multi-level tool readiness: installed -> compatible -> functional -> assessment-ready.

Every level is proven with a real local executable, so the test never needs the
real scanner: a shell script stands in for it. One test exercises real nmap and
httpx against the loopback fixture and skips when the box has neither.
"""
import stat

import pytest

from libella.tools import Registry, ToolSpec
from libella.tools import diagnostics, readiness

MISSING = "libella-no-such-scanner-xyz"


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    # a tool with no declared version probe is unverified by design, so the
    # fixture scanners must declare one
    for name in ("fake-tool", "fake-a", "fake-b", "fixture"):
        monkeypatch.setitem(diagnostics.VERSION_ARGS, name, ["--version"])
    readiness.clear_cache()
    yield
    readiness.clear_cache()


def _script(tmp_path, name: str, body: str) -> str:
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


def _spec(binary: str | None, name: str = "fake-tool") -> ToolSpec:
    return ToolSpec(name=name, description="fixture scanner", category="recon",
                    params={}, required=[], binary=binary)


def _ok_tool(tmp_path, version="9.8.7", name="fake-tool") -> str:
    return _script(tmp_path, name, f'echo "{name} version {version}"')


def test_missing_binary_stops_at_missing(tmp_path):
    row = readiness.check(_spec(MISSING))

    assert row["status"] == "missing"
    assert row["level"] == "missing"
    assert row["degraded"] is False
    assert MISSING in row["detail"]


def test_version_command_failure_stops_at_installed(tmp_path):
    exe = _script(tmp_path, "fake-tool", 'echo "no config" >&2\nexit 3')

    row = readiness.check(_spec(exe))

    assert row["status"] == "installed"
    assert row["level"] == "installed"
    assert row["version"] is None
    assert "exited with code 3" in row["detail"]


def test_version_with_nonzero_exit_is_compatible(tmp_path):
    exe = _script(tmp_path, "fake-tool", 'echo "fake-tool version 9.0.0"\nexit 1')

    row = readiness.check(_spec(exe))

    assert row["status"] == "compatible"
    assert row["version"] == "9.0.0"
    assert row["degraded"] is False


def test_tool_without_a_fixture_check_caps_at_functional(tmp_path):
    exe = _ok_tool(tmp_path)

    row = readiness.check(_spec(exe))

    assert row["status"] == "functional"
    assert row["version"] == "9.8.7"
    assert any("no local fixture check" in text for text in row["limitations"])


def test_version_below_the_declared_minimum_is_degraded(tmp_path, monkeypatch):
    exe = _ok_tool(tmp_path, version="1.0.0")
    monkeypatch.setitem(readiness.MIN_VERSIONS, "fake-tool", "2.0")

    row = readiness.check(_spec(exe))

    assert row["status"] == "degraded"
    assert row["level"] == "functional"
    assert row["degraded"] is True
    assert row["minimum"] == "2.0"
    assert any("below" in text and "2.0" in text for text in row["limitations"])


def test_unrecognized_version_is_not_compatible(tmp_path, monkeypatch):
    exe = _script(tmp_path, "fake-tool", 'echo "fake-tool build unknown"')
    monkeypatch.setitem(readiness.MIN_VERSIONS, "fake-tool", "1.0")

    row = readiness.check(_spec(exe))

    assert row["version"] is None
    assert row["status"] in {"degraded", "installed"}
    assert row["status"] != "assessment_ready"


def test_passing_fixture_check_is_assessment_ready(tmp_path, monkeypatch):
    exe = _ok_tool(tmp_path)
    monkeypatch.setitem(readiness.DEEP, "fake-tool",
                        lambda path: (True, "fixture scan parsed one result", []))

    row = readiness.check(_spec(exe))

    assert row["status"] == "assessment_ready"
    assert row["level"] == "assessment_ready"
    assert row["degraded"] is False
    assert "one result" in row["detail"]


def test_failing_fixture_check_is_degraded_with_the_reason(tmp_path, monkeypatch):
    exe = _ok_tool(tmp_path)
    monkeypatch.setitem(readiness.DEEP, "fake-tool",
                        lambda path: (False, "scan hit nothing", ["the fixture was not reached"]))

    row = readiness.check(_spec(exe))

    assert row["status"] == "degraded"
    assert row["level"] == "functional"
    assert "hit nothing" in row["detail"]
    assert "the fixture was not reached" in row["limitations"]


def test_nuclei_without_a_templates_directory_is_degraded(tmp_path, monkeypatch):
    exe = _script(tmp_path, "nuclei", 'echo "Engine Version: v3.11.1"')
    monkeypatch.setattr(readiness, "_templates_dir", lambda: None)
    monkeypatch.setattr(readiness, "_exec", lambda argv, timeout: (
        '{"template-id":"libella-readiness-fixture","matched-at":"http://127.0.0.1:1/",'
        '"info":{"name":"fixture","severity":"info"}}', "", 0, False))

    row = readiness.check(_spec(exe, name="nuclei"))

    assert row["status"] == "degraded"
    assert any("templates" in text for text in row["limitations"])


def test_zap_without_a_parseable_baseline_never_reaches_assessment_ready(tmp_path, monkeypatch):
    exe = _script(tmp_path, "zap.sh", 'echo "engine 2.15.0"\necho "no report" >&2')
    monkeypatch.setattr(readiness, "_exec", lambda argv, timeout: ("no report", "", 0, False))

    row = readiness.check(_spec(exe, name="zap_baseline"))

    assert row["status"] in {"degraded", "functional"}
    assert row["status"] != "assessment_ready"
    assert any("ZAP" in text for text in row["limitations"])


def test_zap_with_a_parseable_baseline_report_is_assessment_ready(tmp_path, monkeypatch):
    exe = _script(tmp_path, "zap.sh", 'echo "Version: 2.15.0"')
    report = ('<OWASPZAPReport><site name="http://127.0.0.1/"><alerts>'
              '<alertitem><pluginid>10020</pluginid><alert>Missing Anti-clickjacking Header</alert>'
              '<riskcode>1</riskcode><desc>no frame options</desc><uri>http://127.0.0.1/</uri>'
              '<solution>send it</solution></alertitem></alerts></site></OWASPZAPReport>')
    monkeypatch.setattr(readiness, "_exec", lambda argv, timeout: (report, "", 0, False))

    row = readiness.check(_spec(exe, name="zap_baseline"))

    assert row["status"] == "assessment_ready"


def test_browser_without_a_chromium_build_is_degraded(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness, "browser_available", lambda: False)

    row = readiness.check(_spec(None, name="browser"))

    assert row["status"] == "degraded"
    assert any("chromium" in text for text in row["limitations"])


def test_browser_that_renders_the_fixture_is_assessment_ready(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness, "browser_available", lambda: True)
    monkeypatch.setattr(readiness, "_render_probe", lambda base: (True, "rendered the fixture page"))

    row = readiness.check(_spec(None, name="browser"))

    assert row["status"] == "assessment_ready"


def test_cached_row_is_reused_and_force_reruns_the_deep_check(tmp_path, monkeypatch):
    exe = _ok_tool(tmp_path)
    runs = []

    def deep(path):
        runs.append(path)
        return True, "fixture ok", []

    monkeypatch.setitem(readiness.DEEP, "fake-tool", deep)
    spec = _spec(exe)

    first = readiness.check(spec)
    second = readiness.check(spec)
    assert first["checked_at"] == second["checked_at"]
    assert len(runs) == 1

    readiness.check(spec, force=True)
    assert len(runs) == 2


def test_report_covers_every_registered_tool_and_explains_each_level(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness, "browser_available", lambda: False)
    reg = Registry()
    reg.register(_spec(_ok_tool(tmp_path, name="fake-a"), name="fake-a"))
    reg.register(_spec(MISSING, name="fake-b"))

    report = readiness.report(reg)

    tools = report["tools"]
    assert [row["name"] for row in tools[:2]] == ["fake-a", "fake-b"]
    assert [row["status"] for row in tools[:2]] == ["functional", "missing"]
    assert "browser" in [row["name"] for row in tools]  # gated capability, no registry entry
    assert {level["name"] for level in report["levels"]} >= {
        "missing", "installed", "compatible", "functional", "assessment_ready", "degraded"}
    assert all(level["meaning"] for level in report["levels"])


def test_two_tools_sharing_one_binary_get_their_own_rows(tmp_path, monkeypatch):
    # trivy_fs and trivy_image run the same binary but are not the same tool
    monkeypatch.setattr(readiness, "browser_available", lambda: False)
    exe = _ok_tool(tmp_path)
    reg = Registry()
    reg.register(_spec(exe, name="fake-a"))
    reg.register(_spec(exe, name="fake-b"))

    rows = readiness.report(reg)["tools"]

    assert [row["name"] for row in rows[:2]] == ["fake-a", "fake-b"]


def test_readiness_route_requires_auth_caches_and_hides_tool_output(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from libella.api import App, create_api

    app = App(tmp_path / "data")
    monkeypatch.setenv("LIBELLA_FIXTURE_TEST", "synthetic-value")
    # no deep checks here: this test is about the route and its cache, not scanners
    monkeypatch.setattr(readiness, "DEEP", {})
    exe = _script(tmp_path, "fake-tool",
                  'echo "$LIBELLA_FIXTURE_TEST"\necho "fake-tool version 9.8.7"')
    app.registry.register(_spec(exe, name="fixture"))
    with TestClient(create_api(app)) as client:
        assert client.get("/api/tools/readiness").status_code == 401
        auth = {"Authorization": f"Bearer {app.token}"}
        first = client.get("/api/tools/readiness", headers=auth)
        assert first.status_code == 200
        body = first.json()
        row = next(r for r in body["tools"] if r["name"] == "fixture")
        assert row["status"] == "functional"
        assert "fixture" in [r["name"] for r in body["tools"]]
        assert {level["name"] for level in body["levels"]} >= {"assessment_ready", "degraded"}
        assert "synthetic-value" not in first.text
        again = client.get("/api/tools/readiness", headers=auth).json()
        assert again["checked_at"] == body["checked_at"]  # five-minute cache


def test_deep_readiness_route_runs_one_tool_and_404s_unknown_tool(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from libella.api import App, create_api

    app = App(tmp_path / "data")
    monkeypatch.setattr(readiness, "DEEP", {})
    exe = _ok_tool(tmp_path)
    app.registry.register(_spec(exe, name="fixture"))
    path = "/api/tools/fixture/readiness"
    with TestClient(create_api(app)) as client:
        assert client.post(path).status_code == 401
        auth = {"Authorization": f"Bearer {app.token}"}
        assert client.post("/api/tools/unknown/readiness", headers=auth).status_code == 404
        res = client.post(path, headers=auth)
        assert res.status_code == 200
        assert res.json()["name"] == "fixture"
        assert res.json()["status"] == "functional"


def test_real_nmap_and_httpx_reach_assessment_ready_against_the_fixture():
    from libella.tools import resolve_binary

    ready = [name for name in ("nmap", "httpx") if resolve_binary(name)]
    if not ready:
        pytest.skip("neither nmap nor httpx is installed on this box")

    rows = {name: readiness.check(_spec(resolve_binary(name), name=name), force=True)
            for name in ready}

    for name, row in rows.items():
        assert row["status"] == "assessment_ready", (name, row)
