"""Audit-2 traffic guards: replay re-issues only what the scope still authorizes.

Attacks: replay a captured request whose origin has since left scope; smuggle a
target through `overrides`. Both must be refused before egress, audited, and
leave no new exchange behind.
"""
import json
import threading

import pytest
from flask import Flask
from werkzeug.serving import make_server

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.scope import Scope
from libella.traffic import replay
from libella.tools.http_probe import HttpProbe


class Sink:
    def __init__(self):
        self.hits: list[str] = []
        sink = self
        app = Flask("audit2-traffic-sink")

        @app.get("/<path:any>")
        def any_path(any):
            sink.hits.append(any)
            return "sink"

        self.srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_port}"


@pytest.fixture
def sink():
    s = Sink()
    yield s
    s.srv.shutdown()


def _captured(tmp_path, url: str):
    """An exchange row + evidence blob as the probe would have written it."""
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    blob = {"request": {"method": "GET", "url": url, "headers": {"Host": "x"}, "body": ""},
            "response": {"status": 200, "headers": {}, "body": "original"}}
    rec = ev.put_json("eng", blob, "http_exchange")
    db.execute("INSERT INTO exchanges(id, engagement_id, evidence_id, method, url, status, "
               "created_at) VALUES('ex1','eng',?, 'GET', ?, 200, 0)", (rec["id"], url))
    return db, ev


def test_replay_of_now_out_of_scope_original_is_refused(tmp_path, sink):
    db, ev = _captured(tmp_path, sink.base + "/inside")
    scope = Scope({"targets": [{"kind": "url", "value": "http://127.0.0.5:1234"}],
                   "categories": ["web"]})
    res = replay(db, ev, HttpProbe(db, ev), scope, "eng", "ex1", {})
    assert res["ok"] is False and res["error"].startswith("out_of_scope"), res
    assert sink.hits == []
    assert db.one("SELECT COUNT(*) n FROM exchanges")["n"] == 1
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='traffic_replay_refused'")["n"] == 1


def test_overrides_cannot_retarget_the_request(tmp_path, sink):
    db, ev = _captured(tmp_path, "http://127.0.0.5:1234/inside")
    scope = Scope({"targets": [{"kind": "url", "value": "http://127.0.0.5:1234"}],
                   "categories": ["web"]})
    # a url override is not a supported field; it must be ignored, not honoured
    res = replay(db, ev, HttpProbe(db, ev), scope, "eng", "ex1",
                 {"url": sink.base + "/pwned", "headers": {"X-Test": "1"}})
    assert sink.hits == [], "override redirected the replay out of scope"
    assert res.get("ok") is False  # 127.0.0.5:1234 is not listening


def test_replay_refuses_malformed_override_headers(tmp_path, sink):
    db, ev = _captured(tmp_path, "http://127.0.0.5:1234/inside")
    scope = Scope({"targets": [{"kind": "url", "value": "http://127.0.0.5:1234"}],
                   "categories": ["web"]})
    res = replay(db, ev, HttpProbe(db, ev), scope, "eng", "ex1", {"headers": {"A": 1}})
    assert res["ok"] is False and "string map" in res["error"]
    assert json.loads(db.one("SELECT tags_json FROM exchanges WHERE id='ex1'")["tags_json"]
                      or "[]") == []
