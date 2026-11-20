"""Scope engine tests: the authorization boundary must fail closed."""
import pytest
from libella.scope import Scope


def spec(**kw):
    base = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
            "categories": ["recon", "web", "api", "infra"]}
    base.update(kw)
    return base


def test_empty_scope_fails_closed():
    with pytest.raises(ValueError):
        Scope({"targets": []})


def test_in_scope_url():
    s = Scope(spec())
    d = s.check_url("http://127.0.0.1:8801/search?q=x")
    assert d.allowed, d.reason


def test_out_of_scope_host():
    s = Scope(spec())
    d = s.check_url("http://127.0.0.1:9999/")
    assert not d.allowed


def test_out_of_scope_external():
    s = Scope(spec())
    d = s.check_url("https://example.com/")
    assert not d.allowed


def test_exclusion_precedence():
    s = Scope(spec(exclusions=[{"kind": "url_prefix", "value": "http://127.0.0.1:8801/admin"}]))
    assert s.check_url("http://127.0.0.1:8801/admin/users").allowed is False
    assert s.check_url("http://127.0.0.1:8801/search").allowed is True


def test_metadata_blocked_even_if_private_allowed():
    s = Scope({"targets": [{"kind": "cidr", "value": "169.254.0.0/16"}],
               "categories": ["web"]})
    # explicitly targeted metadata range is allowed (lab sim), but not implicitly
    s2 = Scope({"targets": [{"kind": "cidr", "value": "10.0.0.0/8"}], "categories": ["web"]})
    d = s2.check_url("http://169.254.169.254/latest/meta-data/")
    assert not d.allowed
    assert "blocked range" in d.reason


def test_scheme_restriction():
    s = Scope(spec())
    assert not s.check_url("file:///etc/passwd").allowed
    assert not s.check_url("gopher://127.0.0.1:8801/").allowed


def test_category_gate():
    s = Scope(spec(categories=["recon"]))
    assert not s.check_url("http://127.0.0.1:8801/", category="web").allowed
    assert s.check_url("http://127.0.0.1:8801/", category="recon").allowed


def test_port_gate():
    s = Scope(spec(allowed_ports=[443]))
    assert not s.check_url("http://127.0.0.1:8801/").allowed


def test_domain_wildcard():
    s = Scope({"targets": [{"kind": "domain", "value": "example.test", "include_subdomains": True}],
               "categories": ["web"]})
    assert s._domain_matches("a.example.test", s.targets[0])
    assert s._domain_matches("example.test", s.targets[0])
    assert not s._domain_matches("evil-example.test", s.targets[0])
    assert not s._domain_matches("example.test.evil.com", s.targets[0])


def test_prompt_block_derives_from_scope():
    s = Scope(spec())
    block = s.prompt_block()
    assert "127.0.0.1:8801" in block
    assert "UNTRUSTED DATA" in block