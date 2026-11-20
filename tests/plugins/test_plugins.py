"""Plugin manifests: closed contract, registration, scope gate, malicious rejection."""
import copy
import json

import pytest

from libella.plugins import PluginHost, load_plugins, validate_manifest
from plugin_fixtures import TOOL_MANIFEST


def test_valid_manifest_normalizes():
    m = validate_manifest(copy.deepcopy(TOOL_MANIFEST))
    assert m["name"] == "echoer" and m["type"] == "tool"
    assert m["entrypoint"] == ("plugin.py", "run")
    assert m["category"] == "recon" and m["required"] == ["target"]
    assert m["read_only"] is True and m["timeout_s"] == 120


@pytest.mark.parametrize("mutate, message", [
    (lambda m: m.update(type="daemon"), "type must be one of"),
    (lambda m: m.update(name="Bad Name"), "name must match"),
    (lambda m: m.update(entrypoint="../escape.py:run"), "entrypoint must be"),
    (lambda m: m.update(entrypoint="plugin.py:run;rm"), "identifier"),
    (lambda m: m["contract"].update(category="dns"), "category must be one of"),
    (lambda m: m["contract"].update(binary="/bin/sh"), "raw execution control"),
    (lambda m: m.update(shell=True), "raw execution control"),
    (lambda m: m["contract"]["params"].update(command={"type": "string"}),
     "raw execution control"),
    (lambda m: m["contract"]["params"].update(extra={"type": "string", "format": "x"}),
     "unsupported keys"),
    (lambda m: m["contract"].update(required=["nope"]), "required must list"),
    (lambda m: m["contract"].update(timeout_s=0), "timeout_s"),
])
def test_manifest_rejections(mutate, message):
    m = copy.deepcopy(TOOL_MANIFEST)
    mutate(m)
    with pytest.raises(ValueError, match=message):
        validate_manifest(m)


def test_load_plugins_registers_typed_tool(app, plugin_factory):
    host = load_plugins(plugin_factory(TOOL_MANIFEST), app.registry)
    assert host.errors == []
    assert [e["name"] for e in host.loaded] == ["echoer"]
    spec = app.registry.get("plugin_echoer")
    assert spec.category == "recon" and spec.target_param == "target"
    status = host.status()
    assert status["available"][0]["name"] == "plugin_echoer"
    assert status["available"][0]["available"] is True


def test_plugin_tool_executes_through_scope_gate(app, scope, plugin_factory):
    load_plugins(plugin_factory(TOOL_MANIFEST), app.registry)
    spec = app.registry.get("plugin_echoer")
    ok = app.runner.run(spec, {"target": "127.0.0.1", "note": "hello"}, scope,
                        "eng_plug", None, "127.0.0.1")
    assert ok["ok"] is True, ok
    assert json.loads(ok["stdout"])["echoed"]["note"] == "hello"
    row = app.db.one("SELECT scope_decision, artifact_id FROM tool_calls WHERE id=?",
                     (ok["call_id"],))
    assert row["scope_decision"] == "executed: ok" and row["artifact_id"]

    refused = app.runner.run(spec, {"target": "127.0.0.2"}, scope, "eng_plug", None,
                             "127.0.0.2")
    assert refused["ok"] is False and refused["error"].startswith("out_of_scope")
    rows = app.db.query("SELECT tool FROM tool_calls WHERE scope_decision LIKE 'refused%'")
    assert len(rows) == 1 and rows[0]["tool"] == "plugin_echoer"


def test_plugin_cannot_pass_untyped_params(app, scope, plugin_factory):
    load_plugins(plugin_factory(TOOL_MANIFEST), app.registry)
    spec = app.registry.get("plugin_echoer")
    res = app.runner.run(spec, {"target": "127.0.0.1", "extra": "x"}, scope,
                         "eng_plug", None, "127.0.0.1")
    assert res["ok"] is False and res["error"].startswith("invalid_params")


def test_malicious_plugin_is_not_registered(app, plugin_factory):
    bad = copy.deepcopy(TOOL_MANIFEST)
    bad["name"] = "badactor"
    bad["contract"]["binary"] = "/bin/sh"
    root = plugin_factory(bad, slug="evil")
    host = load_plugins(root, app.registry)
    assert host.loaded == []
    assert "raw execution control" in host.errors[0]["error"]
    assert "plugin_badactor" not in app.registry.tools


def test_missing_entrypoint_file_is_an_error(app, plugin_factory):
    root = plugin_factory(TOOL_MANIFEST)
    (root / "plug" / "plugin.py").unlink()
    host = load_plugins(root, app.registry)
    assert host.loaded == [] and "entrypoint file does not exist" in host.errors[0]["error"]


def test_exporter_plugin_registers(app, plugin_factory):
    manifest = {"name": "ticket", "version": "0.1.0", "type": "exporter",
                "contract": {"description": "file findings as tickets", "formats": ["md"]},
                "entrypoint": "plugin.py:export"}
    code = "def export(report):\n    return '# ' + str(report.get('engagement_id'))\n"
    host = load_plugins(plugin_factory(manifest, code, slug="exp"), app.registry)
    assert host.errors == [] and host.status()["exporters"] == ["ticket"]
    assert host.exporters["ticket"]({"engagement_id": "e1"}) == "# e1"


def test_agent_plugin_is_flagged_not_wired(app, plugin_factory):
    manifest = {"name": "specialist", "version": "0.1.0", "type": "agent",
                "contract": {"description": "reserved role plugin"},
                "entrypoint": "plugin.py:run"}
    host = load_plugins(plugin_factory(manifest, slug="agent"), app.registry)
    assert host.loaded[0]["status"] == "unsupported"


def test_reload_replaces_owned_tools_without_duplicates(app, plugin_factory):
    host = load_plugins(plugin_factory(TOOL_MANIFEST), app.registry)
    second = copy.deepcopy(TOOL_MANIFEST)
    second["name"] = "second"
    plugin_factory(second, slug="two")
    host.load()  # no tool re-registered twice -> Registry.register would raise
    assert len(host.status()["available"]) == 2
    assert host.status()["errors"] == []


def test_status_survives_missing_directory(tmp_path, app):
    host = PluginHost(tmp_path / "nowhere", app.registry)
    status = host.load()
    assert status["loaded"] == [] and (tmp_path / "nowhere").is_dir()
