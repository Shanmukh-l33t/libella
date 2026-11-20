"""Attack the authorization boundary: every case must fail closed."""
import time

import pytest

from libella.scope import Scope


def spec(**kw):
    base = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
            "categories": ["recon", "web", "api", "infra"]}
    base.update(kw)
    return base


# --- URL-prefix targets must bind to an origin, not a string prefix ----------

def test_userinfo_prefix_does_not_authorize_other_origin():
    s = Scope(spec())
    # userinfo chosen so the raw string starts with the authorized target,
    # while the real destination is localhost:9999
    pw = "8801"
    d = s.check_url(f"http://127.0.0.1:{pw}@localhost:9999/")
    assert not d.allowed, d.reason


def test_port_variant_of_url_target_is_out_of_scope():
    s = Scope(spec())
    assert not s.check_url("http://127.0.0.1:88011/").allowed
    assert not s.check_url("http://127.0.0.1:9999/").allowed


def test_url_target_prefix_respects_path_boundary():
    s = Scope(spec(targets=[{"kind": "url", "value": "http://127.0.0.1:8801/app"}]))
    assert s.check_url("http://127.0.0.1:8801/app/x").allowed
    assert not s.check_url("http://127.0.0.1:8801/application").allowed


def test_path_traversal_cannot_smuggle_out_of_prefix():
    s = Scope(spec(targets=[{"kind": "url", "value": "http://127.0.0.1:8801/app"}]))
    assert not s.check_url("http://127.0.0.1:8801/app/../admin").allowed


# --- exclusions -------------------------------------------------------------

def test_exclusion_prefix_case_and_encoding_bypass():
    s = Scope({"targets": [{"kind": "domain", "value": "localhost"}],
               "categories": ["web"],
               "exclusions": [{"kind": "url_prefix", "value": "http://localhost/admin"}]})
    for u in ("http://localhost/admin/x", "HTTP://localhost/admin/x",
              "http://LOCALHOST/admin/x", "http://localhost/%61dmin/x",
              "http://localhost/./admin/x"):
        assert not s.check_url(u).allowed, u
    assert s.check_url("http://localhost/public").allowed


def test_exclusion_does_not_break_in_scope_hosts():
    s = Scope(spec(exclusions=[{"kind": "url_prefix", "value": "http://127.0.0.1:8801/admin"}]))
    assert s.check_url("http://127.0.0.1:8801/administrator").allowed is False  # over-block is safe
    assert s.check_url("http://127.0.0.1:8801/search").allowed


# --- parsing robustness -----------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:99999/",
    "http://127.0.0.1:8801.a/",
    "http://[::1/",
    "http://",
    "http://127.0.0.1:8801\\@evil.test/",
])
def test_malformed_urls_refuse_without_raising(url):
    s = Scope(spec())
    d = s.check_url(url)  # must be a Decision, never an exception
    assert d.allowed is False


def test_scope_rejects_malformed_target_at_construction():
    for targets in ([{"value": "127.0.0.1"}],
                    [{"kind": "urlv2", "value": "http://x"}],
                    [{"kind": "cidr", "value": "not-a-cidr"}],
                    [{"kind": "url"}]):
        with pytest.raises(ValueError):
            Scope({"targets": targets, "categories": ["web"]})


def test_scope_rejects_malformed_exclusion_at_construction():
    with pytest.raises(ValueError):
        Scope({"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
               "exclusions": [{"kind": "url_prefix"}], "categories": ["web"]})


# --- address-space rules ----------------------------------------------------

def test_ipv4_mapped_ipv6_cannot_reach_metadata():
    s = Scope({"targets": [{"kind": "cidr", "value": "::/0"}], "categories": ["web"]})
    d = s.check_url("http://[::ffff:169.254.169.254]/latest/meta-data/")
    assert not d.allowed, d.reason
    assert "blocked range" in d.reason


def test_ipv6_grants_do_not_widen_across_versions():
    s = Scope({"targets": [{"kind": "cidr", "value": "2001:db8::/32"}], "categories": ["web"]})
    assert not s.check_url("http://[fe80::1]/").allowed
    assert s.check_url("http://[2001:db8::1]/").allowed
    # an IPv6-only grant never authorizes the IPv4 metadata range via mapping
    s2 = Scope({"targets": [{"kind": "cidr", "value": "::/0"}], "categories": ["web"]})
    assert not s2.check_url("http://[::ffff:169.254.169.254]/").allowed
    assert not s2.check_url("http://[::ffff:10.0.0.1]/").allowed


def test_decimal_host_alias_is_not_implicitly_in_scope():
    s = Scope(spec())
    # 2130706433 == 127.0.0.1; a url-prefix target does not extend to aliases
    assert not s.check_url("http://2130706433:8801/").allowed


# --- category and port gates ------------------------------------------------

def test_url_target_with_subdomain_host_tool_match_is_not_expanded():
    s = Scope({"targets": [{"kind": "url", "value": "http://app.example.test:8080"}],
               "categories": ["infra"]})
    s._dns_cache["other.app.example.test"] = (time.time(), ["127.0.0.1"])
    assert not s.check_host_port("other.app.example.test", 443).allowed


def test_category_gate_uses_resolved_category():
    s = Scope(spec(categories=["recon"]))
    assert not s.check_url("http://127.0.0.1:8801/", category="web").allowed
    assert s.check_url("http://127.0.0.1:8801/", category="recon").allowed
