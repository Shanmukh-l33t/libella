"""Adapter contract tests: closed params, argv built by code, parsers, confinement."""
import json
from pathlib import Path

import pytest

from libella.tools import validate_params
from libella.tools.code_adapters import (GITLEAKS, LOCAL_RULES, SEMGREP, SPECS, TRIVY_FS,
                                         LocalCtx, confine_repo, parse_gitleaks_json,
                                         parse_semgrep_json, parse_trivy_json)

LABS = Path(__file__).resolve().parents[2] / "labs"


@pytest.fixture
def ctx(tmp_path):
    return LocalCtx(str(tmp_path), roots=[str(LABS)])


def _argv(spec, ctx, **params):
    return spec.handler(validate_params(spec, params), ctx)


# --- registry shape ---------------------------------------------------------

def test_specs_are_code_category_and_local():
    assert [s.name for s in SPECS] == ["semgrep", "trivy_fs", "gitleaks"]
    for spec in SPECS:
        assert spec.category == "code"
        assert spec.network_effect is False
        assert spec.target_param == "repo"
        assert spec.binary in ("semgrep", "trivy", "gitleaks")
        assert spec.required == ["repo"]


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_unknown_and_missing_params_rejected(spec):
    with pytest.raises(ValueError):
        validate_params(spec, {"repo": str(LABS / "vulnrepo"), "additional_args": "--evil"})
    with pytest.raises(ValueError):
        validate_params(spec, {})


def test_ruleset_and_scanner_enums_are_closed():
    with pytest.raises(ValueError):
        validate_params(SEMGREP, {"repo": "x", "ruleset": "p/evil"})
    with pytest.raises(ValueError):
        validate_params(TRIVY_FS, {"repo": "x", "scanners": "vuln,secret;rm"})


# --- argv is built by code --------------------------------------------------

def test_semgrep_argv_uses_local_rules_by_default(ctx):
    argv = _argv(SEMGREP, ctx, repo=str(LABS / "vulnrepo"))
    assert argv[0] == "semgrep"
    rules = argv[argv.index("--config") + 1]
    assert rules.endswith("libella-code-rules.yml")
    assert Path(rules).read_text() == LOCAL_RULES
    assert "--json" in argv and argv[-1] == str(LABS / "vulnrepo")


def test_trivy_argv_pins_scanners_and_cache(ctx):
    argv = _argv(TRIVY_FS, ctx, repo=str(LABS / "vulnrepo"))
    assert argv[:2] == ["trivy", "fs"]
    assert argv[argv.index("--scanners") + 1] == "secret,misconfig"
    assert "--cache-dir" in argv and "--format" in argv
    assert argv[-1] == str(LABS / "vulnrepo")


def test_gitleaks_argv_is_redacted_json(ctx):
    argv = _argv(GITLEAKS, ctx, repo=str(LABS / "vulnrepo"))
    assert argv[:3] == ["gitleaks", "dir", str(LABS / "vulnrepo")]
    assert argv[argv.index("--report-format") + 1] == "json"
    assert "--redact" in argv
    assert argv[argv.index("--report-path") + 1].startswith(str(ctx.workdir))


# --- confinement ------------------------------------------------------------

@pytest.mark.parametrize("bad", ["/etc", "/etc/passwd", "../labs/vulnrepo",
                                 "/tmp/../etc", "x;id", "x$(id)", "x`id`", "x\nid"])
def test_confine_repo_rejects_escape_and_metacharacters(bad):
    with pytest.raises(ValueError):
        confine_repo(bad, roots=[str(LABS)])


def test_confine_repo_rejects_missing_and_file_paths(tmp_path):
    with pytest.raises(ValueError):
        confine_repo(str(tmp_path / "nope"), roots=[str(tmp_path)])
    f = tmp_path / "f.txt"
    f.write_text("x")
    with pytest.raises(ValueError):
        confine_repo(str(f), roots=[str(tmp_path)])


def test_confine_repo_accepts_a_plain_inside_path(tmp_path):
    (tmp_path / "repo").mkdir()
    assert confine_repo(str(tmp_path / "repo"), roots=[str(tmp_path)]) \
        == str(tmp_path.resolve() / "repo")


def test_confine_repo_refuses_traversal_even_when_it_lands_inside(tmp_path):
    (tmp_path / "repo").mkdir()
    with pytest.raises(ValueError):
        confine_repo(str(tmp_path / "repo" / ".." / "repo"), roots=[str(tmp_path)])


def test_confine_repo_rejects_symlink_escape(tmp_path):
    outside, inside = tmp_path / "outside", tmp_path / "root"
    outside.mkdir()
    inside.mkdir()
    (inside / "link").symlink_to(outside)
    with pytest.raises(ValueError):
        confine_repo(str(inside / "link"), roots=[str(inside)])


# --- parsers ----------------------------------------------------------------

SEMGREP_OUT = json.dumps({"results": [{
    "check_id": "rules.libella-eval-exec", "path": "/r/app/run.py",
    "start": {"line": 16}, "extra": {"message": "m", "severity": "ERROR",
                                     "metadata": {"cwe": ["CWE-94: Improper Control"]}}}],
    "errors": []})


def test_parse_semgrep_strips_config_prefix_and_normalises_cwe():
    hits = parse_semgrep_json(SEMGREP_OUT)
    assert hits == [{"rule": "libella-eval-exec", "path": "/r/app/run.py", "line": 16,
                     "message": "m", "severity": "ERROR", "cwe": "CWE-94"}]


def test_parse_semgrep_tolerates_garbage():
    assert parse_semgrep_json("not json") == []
    assert parse_semgrep_json("{}") == []


def test_parse_trivy_splits_three_result_kinds():
    out = json.dumps({"Results": [{
        "Target": "requirements.txt",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2020-14343", "PkgName": "PyYAML",
                             "InstalledVersion": "5.3.1", "FixedVersion": "5.4", "Severity": "HIGH"}],
        "Secrets": [{"RuleID": "aws-access-key-id", "StartLine": 6, "Title": "t"}],
        "Misconfigurations": [{"ID": "AVD-X", "CauseMetadata": {"StartLine": 3}}]}]})
    parsed = parse_trivy_json(out)
    assert parsed["vulnerabilities"][0]["cve"] == "CVE-2020-14343"
    assert parsed["secrets"] == [{"rule": "aws-access-key-id", "target": "requirements.txt",
                                 "line": 6, "title": "t", "severity": None}]
    assert parsed["misconfigurations"][0]["id"] == "AVD-X"
    assert parse_trivy_json("")["secrets"] == []


def test_parse_gitleaks_reads_report_list():
    out = json.dumps([{"RuleID": "private-key", "File": "/r/app/signing.py",
                       "StartLine": 7, "Description": "d", "Match": "REDACTED"}])
    assert parse_gitleaks_json(out) == [{"rule": "private-key", "file": "/r/app/signing.py",
                                         "line": 7, "description": "d"}]
    assert parse_gitleaks_json("{}") == []
