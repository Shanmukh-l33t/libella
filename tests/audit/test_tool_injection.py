"""Tool adapters: no injected parameter may change where a tool connects or
what it reads from disk. All argv is built by code, never by a shell."""
import pytest

from libella.scope import Decision, Scope
from libella.tools import ToolSpec, validate_params
from libella.tools.adapters import (ALL_ADAPTERS, FFUF, HTTPX, NMAP, SUBFINDER,
                                    _ffuf_argv, _nuclei_argv)
from libella.tools.runner import MAX_OUTPUT


@pytest.fixture
def runner(app):
    return app.runner


def _scope(base):
    return Scope({"targets": [{"kind": "url", "value": base}], "categories":
                  ["recon", "web", "api", "infra"], "rate_limit_rps": 1000})


def _ok_decision():
    return Decision(True, "in scope", resolved_ips=["127.0.0.1"], matched_target="t")


# --- the runner must scope the parameter the adapter actually dials ----------

def test_ffuf_url_param_cannot_escape_scope(runner, lab):
    scope = _scope(lab.base)
    r = runner.run(FFUF, {"url": "http://127.0.0.1:1/out-of-scope"}, scope,
                   "eng_audit", None, target=lab.base, category="recon")
    assert r["ok"] is False
    assert "out_of_scope" in r["error"], r


def test_adapter_target_param_is_declared():
    assert FFUF.target_param == "url"
    assert SUBFINDER.target_param == "domain"
    assert HTTPX.target_param == "target"


def test_host_tool_scopes_the_param_it_scans(runner, lab):
    scope = _scope(lab.base)
    r = runner.run(NMAP, {"target": "10.255.255.1"}, scope, "eng_audit", None,
                   target=lab.base, category="infra")
    assert r["ok"] is False and "out_of_scope" in r["error"], r


# --- category mislabelling must not widen authorization ---------------------

def test_runner_refuses_tool_run_under_foreign_category(runner, lab):
    stub = ToolSpec(name="stub", description="", category="web", binary=None, timeout_s=5,
                    params={"target": {"type": "string"}}, required=["target"],
                    handler=lambda p, d: ["true"])
    scope = Scope({"targets": [{"kind": "url", "value": lab.base}], "categories": ["recon"]})
    r = runner.run(stub, {"target": lab.base}, scope, "eng_audit", None,
                   target=lab.base, category="recon")
    assert r["ok"] is False, r
    assert "category" in r["error"]


# --- filesystem parameters --------------------------------------------------

def test_ffuf_wordlist_cannot_read_arbitrary_file():
    with pytest.raises(ValueError):
        _ffuf_argv({"url": "http://127.0.0.1:8080", "wordlist": "/etc/passwd"}, _ok_decision())


def test_ffuf_wordlist_traversal_rejected():
    with pytest.raises(ValueError):
        _ffuf_argv({"url": "http://127.0.0.1:8080",
                    "wordlist": "/usr/share/wordlists/../../etc/shadow"}, _ok_decision())


def test_nuclei_templates_outside_template_root_rejected():
    with pytest.raises(ValueError):
        _nuclei_argv({"target": "http://127.0.0.1:8080", "templates": "/etc"}, _ok_decision())


# --- metacharacters --------------------------------------------------------

@pytest.mark.parametrize("bad", ["a;id", "a|id", "a&id", "$(id)", "`id`", "a\nid", "a>b", "a<b"])
def test_metacharacters_rejected_in_every_string_param(bad):
    with pytest.raises(ValueError):
        validate_params(HTTPX, {"target": bad})


@pytest.mark.parametrize("spec", ALL_ADAPTERS, ids=lambda s: s.name)
def test_every_adapter_param_rejects_shell_metacharacters(spec):
    for name, p in spec.params.items():
        if p.get("type") != "string":
            continue
        params = {name: "x;touch /tmp/libella_pwn"}
        for req in spec.required:
            params.setdefault(req, "http://127.0.0.1:1" if req != "domain" else "localhost")
        with pytest.raises(ValueError):
            validate_params(spec, params)


@pytest.mark.parametrize("bad", ["a;id", "a|id", "a&id", "$(id)", "`id`", "a\nb"])
def test_metacharacters_rejected_in_array_items(bad):
    spec = ToolSpec(name="t", description="", category="recon",
                    params={"hosts": {"type": "array", "items": {"type": "string"}}},
                    required=["hosts"])
    with pytest.raises(ValueError):
        validate_params(spec, {"hosts": [bad]})


def test_unknown_params_are_rejected():
    with pytest.raises(ValueError):
        validate_params(HTTPX, {"target": "http://127.0.0.1", "additional_args": "-oN /tmp/x"})


def test_no_shell_is_used_for_targets_with_metacharacters(runner, lab):
    scope = _scope(lab.base)
    r = runner.run(HTTPX, {"target": "127.0.0.1; touch /tmp/libella_pwn"}, scope,
                   "eng_audit", None, target=lab.base, category="recon")
    assert r["ok"] is False
    import os
    assert not os.path.exists("/tmp/libella_pwn")


# --- output cap is enforced while capturing --------------------------------

def test_tool_output_cap_is_bounded(tmp_path, app, lab):
    noisy = ToolSpec(name="noisy", description="", category="recon", binary="sh",
                     timeout_s=60,
                     params={"target": {"type": "string"}}, required=["target"],
                     handler=lambda p, d: ["sh", "-c", "head -c 20000000 /dev/zero"])
    scope = _scope(lab.base)
    r = app.runner.run(noisy, {"target": "127.0.0.1"}, scope, "eng_audit", None,
                       target="127.0.0.1", category="recon")
    assert r["ok"] is True, r
    assert len(r["stdout"]) == MAX_OUTPUT
    assert r["truncated"] is True
