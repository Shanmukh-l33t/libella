"""ZAP adapter: report parsing from recorded fixtures, argv shaping, injection
rejection, missing-tool degradation, and a live scan only when ZAP exists."""
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.api import App  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools import validate_params  # noqa: E402
from libella.tools.zap_adapter import (  # noqa: E402
    ZAP, parse_zap_report, zap_available, zap_version,
)

FIX = Path(__file__).with_name("fixtures")
JSON_REPORT = (FIX / "zap_report.json").read_text()
XML_REPORT = (FIX / "zap_report.xml").read_text()


def _key(o):
    return (o["alert"], o["url"], o["param"], o["risk"], o["cwe"], o["plugin_id"])


# ---- parser ----

def test_parse_json_report():
    obs = parse_zap_report(JSON_REPORT)
    assert len(obs) == 4  # three alerts, one of them with two instances
    xss = next(o for o in obs if o["plugin_id"] == "40012")
    assert xss["alert"] == "Cross Site Scripting (Reflected)"
    assert xss["risk"] == "high" and xss["confidence"] == "Medium"
    assert xss["url"] == "http://127.0.0.1:8821/wp/?s=1"
    assert xss["param"] == "s" and xss["method"] == "GET"
    assert xss["cwe"] == "CWE-79"
    assert "<script>" in xss["evidence"]
    assert all(o["source"] == "zap" for o in obs)


def test_parse_xml_report_matches_json():
    assert sorted(map(_key, parse_zap_report(XML_REPORT))) == \
        sorted(map(_key, parse_zap_report(JSON_REPORT)))


def test_parser_tolerates_zap_console_noise():
    noisy = "PASS: New session\nINFO: 127.0.0.1:8821\n" + JSON_REPORT + "\nTotal time: 12s\n"
    assert len(parse_zap_report(noisy)) == 4
    noisy_xml = "INFO: started\n" + XML_REPORT + "\nFINISH"
    assert len(parse_zap_report(noisy_xml)) == 4


def test_missing_instances_still_yields_one_observation():
    report = json.dumps({"site": [{"@name": "http://t.invalid", "alerts": [
        {"alert": "Server Leaks Version Information", "pluginid": "10036", "riskcode": "1"}]}]})
    obs = parse_zap_report(report)
    assert len(obs) == 1 and obs[0]["url"] == "http://t.invalid" and obs[0]["risk"] == "low"


def test_unknown_and_zero_cwe_are_none():
    report = json.dumps({"site": [{"@name": "http://t.invalid", "alerts": [
        {"alert": "A", "pluginid": "1", "riskcode": "0",
         "instances": [{"uri": "http://t.invalid/x", "cweid": "0"}]}]}]})
    obs = parse_zap_report(report)
    assert obs[0]["risk"] == "info" and obs[0]["cwe"] is None


def test_garbage_is_empty_not_an_exception():
    assert parse_zap_report("") == [] and parse_zap_report("not a report") == []
    assert parse_zap_report("<html>nope</html>") == []


# ---- argv ----

def _argv(**params):
    clean = validate_params(ZAP, {"target": "http://127.0.0.1:8821/wp/", **params})
    return ZAP.handler(clean, None)


def test_argv_baseline_is_quick_scan_and_shell_free():
    argv = _argv()
    assert argv[1:3] == ["-cmd", "-silent"]
    assert "-quickurl" in argv and argv[argv.index("-quickurl") + 1] == "http://127.0.0.1:8821/wp/"
    assert argv[argv.index("-quickout") + 1] == "/dev/stdout"
    assert "-config" in argv and "spider.maxDepth=2" in argv
    assert "api.disablekey=true" in argv
    assert "-z" not in argv  # no free-text passthrough into the JVM args
    assert all(isinstance(a, str) for a in argv)


def test_argv_policy_switches_depth():
    assert "spider.maxDepth=5" in _argv(policy="deep")
    assert "spider.maxDepth=2" in _argv(policy="baseline")


@pytest.mark.parametrize("target", [
    "http://127.0.0.1:8821/wp/;id",
    "http://127.0.0.1:8821/wp/?a=1&b=2",
    "http://127.0.0.1:8821/wp/`id`",
    "http://127.0.0.1:8821/wp/|nc 127.0.0.1 1",
])
def test_injection_is_rejected_at_validation(target):
    with pytest.raises(ValueError):
        validate_params(ZAP, {"target": target})


def test_policy_enum_rejects_injection():
    with pytest.raises(ValueError):
        validate_params(ZAP, {"target": "http://127.0.0.1:8821/", "policy": "baseline;id"})


@pytest.mark.parametrize("target", ["--help", "-quickout", "/tmp/x", "ftp://127.0.0.1/x",
                                    "http://127.0.0.1/a b"])
def test_handler_rejects_non_targets(target):
    with pytest.raises(ValueError):
        ZAP.handler({"target": target}, None)


def test_spec_is_wired_to_the_binary_and_target_param():
    assert ZAP.category == "web" and ZAP.target_param == "target" and ZAP.binary
    assert ZAP.schema()["parameters"]["required"] == ["target"]


# ---- runner integration: scope, degradation ----

class Rig:
    def __init__(self, tmp_path):
        self.app = App(tmp_path / "data")
        self.eid = f"eng_zap_{int(time.time() * 1e6)}"
        self.app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (self.eid, "zap", "safe_active", "draft", "{}", "{}", "{}", time.time()))
        self.target = "http://127.0.0.1:8821/wp/"
        self.scope = Scope({"targets": [{"kind": "url", "value": self.target}],
                            "categories": ["web"], "rate_limit_rps": 1000})

    def run(self, scope=None, target=None):
        return self.app.runner.run(ZAP, {"target": target or self.target}, scope or self.scope,
                                   self.eid, None, target or self.target)


def test_missing_tool_degrades_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr("libella.tools.runner.resolve_binary", lambda name: None)
    res = Rig(tmp_path).run()
    assert res["ok"] is False and res["degradation"] == "missing_tool"
    assert "missing_tool" in res["error"]


def test_runner_refuses_out_of_scope_target(tmp_path):
    rig = Rig(tmp_path)
    res = rig.run(target="http://127.0.0.1:9/elsewhere")
    assert res["ok"] is False and res["error"].startswith("out_of_scope")


def test_runner_refuses_out_of_scope_before_binary_check(tmp_path):
    # scope is checked first: an absent binary must not mask an out-of-scope call
    rig = Rig(tmp_path)
    res = rig.run(target="https://not-mine.invalid/")
    assert res["error"].startswith("out_of_scope")
    row = rig.app.db.one("SELECT scope_decision FROM tool_calls WHERE tool=? ORDER BY created_at "
                         "DESC LIMIT 1", (ZAP.name,))
    assert "refused" in row["scope_decision"]


@pytest.mark.skipif(not zap_available(), reason="OWASP ZAP not installed")
def test_live_zap_scan_against_techlab(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("techlab_labctl_zap",
                                                  ROOT / "labs/techlab/labctl.py")
    labctl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(labctl)

    assert zap_version() is not None
    base, srv = labctl.start_lab("vuln")
    try:
        rig = Rig(tmp_path)
        rig.scope = Scope({"targets": [{"kind": "url", "value": base}],
                           "categories": ["web"], "rate_limit_rps": 1000})
        res = rig.run(target=base + "/wp/")
        assert res["ok"] is True, res.get("error")
        assert isinstance(parse_zap_report(res["stdout"]), list)
    finally:
        srv.shutdown()
