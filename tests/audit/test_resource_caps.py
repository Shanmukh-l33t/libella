"""Resource exhaustion: response/tool output caps, redirect loops, crawl bombs."""
import resource

import pytest

from libella.crawl import Crawler
from libella.scope import Scope
from libella.tools import ToolSpec
from libella.tools.http_probe import BODY_CAP, MAX_HOPS


def _rss_mb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def _scope(lab):
    return Scope({"targets": [{"kind": "url", "value": lab.base}],
                  "categories": ["recon", "web", "api", "infra"], "rate_limit_rps": 1000})


def test_huge_response_is_capped_and_not_buffered(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    before = _rss_mb()
    if before > 400:
        pytest.skip("peak RSS already too high to measure")
    r = app.probe.request(eid, _scope(lab), lab.base + "/huge")
    delta = _rss_mb() - before
    assert r["ok"]
    assert len(r["body"]) == BODY_CAP
    assert r["truncated"] is True
    assert delta < 12, f"probe buffered the whole body: +{delta:.0f}MB"


def test_tool_output_is_capped_while_capturing(app, mk_eng, lab):
    from libella.tools.runner import MAX_OUTPUT
    noisy = ToolSpec(name="noisy", description="", category="recon", binary="sh",
                     timeout_s=60, params={"target": {"type": "string"}}, required=["target"],
                     handler=lambda p, d: ["sh", "-c", "head -c 20000000 /dev/zero"])
    before = _rss_mb()
    if before > 400:
        pytest.skip("peak RSS already too high to measure")
    r = app.runner.run(noisy, {"target": "127.0.0.1"}, _scope(lab), "eng_audit", None,
                       target="127.0.0.1", category="recon")
    delta = _rss_mb() - before
    assert r["ok"] and len(r["stdout"]) == MAX_OUTPUT
    assert delta < 12, f"runner buffered full output: +{delta:.0f}MB"


def test_redirect_loop_is_bounded(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    r = app.probe.request(eid, _scope(lab), lab.base + "/redir-loop")
    assert r["ok"]
    assert len(lab.hits) == MAX_HOPS + 1
    assert r["status"] == 302


def test_redirect_out_of_scope_is_refused_before_egress(app, mk_eng, lab, other_lab):
    lab.out_url = other_lab.base + "/never"
    eid = mk_eng(lab.base)
    r = app.probe.request(eid, _scope(lab), lab.base + "/redir-out")
    assert r["ok"] is False and "out_of_scope" in r["error"], r
    assert other_lab.hits == []
    assert lab.hits == ["/redir-out"]


def test_crawl_bomb_is_bounded(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    crawler = Crawler(app.probe, eid, _scope(lab), max_pages=10, max_depth=3)
    result = crawler.crawl(lab.base)
    assert result["crawled"] <= 10
    assert len(result["pages"]) <= 10