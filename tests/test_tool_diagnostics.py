"""Functional tool readiness: the version command must actually run.

Fixtures are real local executables. Each script records the argv it received
so a test can prove the probe passes the version flag and nothing else (no
target, no engagement params).
"""
import stat

import pytest

from libella.tools import Registry, ToolSpec
from libella.tools import diagnostics

MISSING = "libella-no-such-scanner-xyz"


@pytest.fixture(autouse=True)
def _fresh_cache():
    diagnostics.clear_cache()
    yield
    diagnostics.clear_cache()


def _script(tmp_path, name: str, body: str) -> str:
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


def _spec(binary: str | None, name: str = "fake_scan") -> ToolSpec:
    return ToolSpec(name=name, description="fixture scanner", category="recon",
                    params={}, required=[], binary=binary)


def _ready_script(tmp_path) -> str:
    log, touched = tmp_path / "argv.log", tmp_path / "touched"
    return _script(tmp_path, "fake-scan",
                   f'printf "%s\\n" "$*" >> "{log}"\n'
                   f'[ "$1" = "--version" ] || {{ echo touched >> "{touched}"; exit 2; }}\n'
                   'echo "fake scanner version 9.8.7"')


def test_ready_reports_parsed_version_and_passes_only_the_version_flag(tmp_path):
    exe = _ready_script(tmp_path)

    row = diagnostics.diagnose(_spec(exe))

    assert row["name"] == "fake_scan"
    assert row["status"] == "ready"
    assert row["version"] == "9.8.7"
    assert "9.8.7" in row["detail"]
    # the probe ran the binary, and the only argument was the version flag
    assert (tmp_path / "argv.log").read_text().splitlines() == ["--version"]
    assert not (tmp_path / "touched").exists()


def test_version_after_warning_noise_is_parsed_from_the_labelled_line(tmp_path):
    # nuclei prints a "go1.17~1.26" warning before "Engine Version: v3.11.1"
    exe = _script(tmp_path, "fake-noisy",
                   'echo "WARNING: go1.17~1.26 fallback" >&2\n'
                   'echo "[INF] Fake Engine Version: v3.11.1"')

    row = diagnostics.diagnose(_spec(exe))

    assert row["status"] == "ready"
    assert row["version"] == "3.11.1"


def test_missing_binary_is_reported_as_missing(tmp_path):
    row = diagnostics.diagnose(_spec(MISSING))

    assert row["status"] == "missing"
    assert row["version"] is None
    assert MISSING in row["detail"]


def test_nonzero_exit_is_broken(tmp_path):
    exe = _script(tmp_path, "fake-broken", 'echo "boom: no config" >&2\nexit 3')

    row = diagnostics.diagnose(_spec(exe))

    assert row["status"] == "broken"
    assert row["version"] is None
    assert "3" in row["detail"]


def test_exit_zero_without_a_version_is_broken(tmp_path):
    exe = _script(tmp_path, "fake-mute", 'echo "usage: fake-scan <file>"')

    row = diagnostics.diagnose(_spec(exe))

    assert row["status"] == "broken"
    assert row["version"] is None


def test_timeout_is_broken_not_a_hang(tmp_path, monkeypatch):
    exe = _script(tmp_path, "fake-hang", "exec sleep 30")
    monkeypatch.setattr(diagnostics, "PROBE_TIMEOUT_S", 0.2)

    row = diagnostics.diagnose(_spec(exe))

    assert row["status"] == "broken"
    assert "timed out" in row["detail"]


def test_repeated_calls_are_cached(tmp_path):
    exe = _ready_script(tmp_path)

    diagnostics.diagnose(_spec(exe))
    diagnostics.diagnose(_spec(exe))

    assert len((tmp_path / "argv.log").read_text().splitlines()) == 1

    diagnostics.clear_cache()
    diagnostics.diagnose(_spec(exe))
    assert len((tmp_path / "argv.log").read_text().splitlines()) == 2


def test_registry_diagnostics_returns_one_row_per_registered_tool(tmp_path):
    exe = _ready_script(tmp_path)
    reg = Registry()
    reg.register(_spec(None, name="in_process"))
    reg.register(_spec(exe, name="real"))
    reg.register(_spec(MISSING, name="absent"))

    rows = reg.diagnostics()

    assert [r["name"] for r in rows] == ["in_process", "real", "absent"]
    assert [r["status"] for r in rows] == ["ready", "ready", "missing"]
    assert all(set(r) == {"name", "status", "version", "detail"} for r in rows)
