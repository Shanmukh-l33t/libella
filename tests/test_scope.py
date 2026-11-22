"""Scope engine tests: the authorization boundary must fail closed."""
import json
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
    Scope({"targets": [{"kind": "cidr", "value": "169.254.0.0/16"}],
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


def test_exclusion_respects_path_segment_boundary():
    s = Scope(spec(exclusions=[{"kind": "url_prefix", "value": "http://127.0.0.1:8801/admin"}]))
    assert not s.check_url("http://127.0.0.1:8801/admin/users").allowed
    assert not s.check_url("http://127.0.0.1:8801/admin").allowed
    assert s.check_url("http://127.0.0.1:8801/administrator").allowed


def test_url_target_authorizes_only_its_own_port():
    s = Scope({"targets": [{"kind": "url", "value": "https://127.0.0.1:8443"}],
               "categories": ["infra"]})
    assert s.check_host_port("127.0.0.1", 8443).allowed
    assert not s.check_host_port("127.0.0.1", 22).allowed
    # scheme default port is the URL's own port
    s2 = Scope({"targets": [{"kind": "url", "value": "https://127.0.0.1"}],
                "categories": ["infra"]})
    assert s2.check_host_port("127.0.0.1", 443).allowed
    assert not s2.check_host_port("127.0.0.1", 80).allowed


def test_explicit_ip_target_still_authorizes_other_ports():
    s = Scope({"targets": [{"kind": "ip", "value": "127.0.0.1"}], "categories": ["infra"]})
    assert s.check_host_port("127.0.0.1", 22).allowed


def test_portless_tool_check_is_host_level_not_a_port_claim():
    s = Scope(spec(allowed_ports=[8801]))
    assert s.check_host_port("127.0.0.1", None).allowed
    assert not s.check_host_port("127.0.0.1", 0).allowed  # 0 is a bogus port, not "any"
    assert not s.check_host_port("127.0.0.1", 22).allowed


def test_a_url_target_authorizes_its_own_www_or_apex_alias():
    """A site that 301s apex -> www is the SAME site the operator authorized."""
    sc = Scope({"targets": [{"kind": "url", "value": "https://keyreed.com"}],
                "categories": ["web"]})
    for host in ("keyreed.com", "www.keyreed.com", "WWW.Keyreed.com"):
        d = sc.check_host_port(host, 443, "web")
        assert d.allowed, (host, d.reason)
    # the alias does not widen the authorized port
    assert not sc.check_host_port("www.keyreed.com", 8443, "web").allowed
    assert sc.check_url("https://www.keyreed.com/about").allowed


def test_the_alias_rule_does_not_authorize_another_domain():
    sc = Scope({"targets": [{"kind": "url", "value": "https://keyreed.com"}],
                "categories": ["web"]})
    for name in ("evil.com", "wwwevil.com", "keyreed.com.evil.com", "notkeyreed.com"):
        host = {"wwwevil.com": "wwwevil.example", "notkeyreed.com": "notkeyreed.example"}
        d = sc.check_host_port(host.get(name, name), 443, "web", ips=["203.0.113.10"])
        assert not d.allowed, (name, d.reason)
    # an exclusion still wins over the alias
    sc2 = Scope({"targets": [{"kind": "url", "value": "https://keyreed.com"}],
                 "exclusions": [{"kind": "domain", "value": "www.keyreed.com"}],
                 "categories": ["web"]})
    assert not sc2.check_host_port("www.keyreed.com", 443, "web").allowed


def test_exchange_keeps_the_authorized_hostname_not_the_pinned_ip(tmp_path):
    """The transport dials an IP; the evidence must still name the host it was authorized by."""
    import threading
    import time
    from flask import Flask
    from werkzeug.serving import make_server
    from libella.api import App
    from libella.scope import Scope

    flask = Flask("probe-url")

    @flask.get("/")
    def index():
        return "<html><body>ok</body></html>"

    srv = make_server("127.0.0.1", 0, flask)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        port = srv.server_port
        app = App(tmp_path / "data")
        # the rebinding guard requires the loopback ADDRESS to be authorized too
        scope = {"targets": [{"kind": "url", "value": f"http://localhost:{port}"},
                             {"kind": "ip", "value": "127.0.0.1"}],
                 "categories": ["web"], "rate_limit_rps": 50}
        app.db.execute("INSERT INTO engagements(id,name,profile,status,scope_json,created_at) "
                       "VALUES('e','p','safe_active','draft',?,0)", (json.dumps(scope),))
        r = app.probe.request("e", Scope(scope), f"http://localhost:{port}/", tool="probe_url")
        assert r["ok"] and r["status"] == 200
        assert r["url"] == f"http://localhost:{port}/", r["url"]
        row = app.db.one("SELECT url, peer_ip FROM exchanges WHERE engagement_id='e'")
        assert row["url"].startswith(f"http://localhost:{port}"), row["url"]
        assert row["peer_ip"] is None or row["peer_ip"].startswith("127.0.0.1")
    finally:
        srv.shutdown()
