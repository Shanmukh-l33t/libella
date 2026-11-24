from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from fastapi.testclient import TestClient

from libella.api import App, create_api
from libella.scope import Scope


@pytest.fixture
def lab():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            if self.path == '/hardened':
                self.send_header('Cache-Control', 'private, NO-STORE')
            if self.path == '/misconfigured':
                self.send_header('Cache-Control', 'private, example="x,no-store,y"')
            if self.path == '/challenge':
                self.send_header('cf-mitigated', 'challenge')
            self.end_headers()
            self.wfile.write(b'Fixture: account statement for a synthetic user')

    with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield f'http://127.0.0.1:{server.server_port}'
        finally:
            server.shutdown()
            worker.join()


def requirement(client, eid):
    ledger = client.get(f'/api/engagements/{eid}/coverage/asvs').json()
    return next(r for c in ledger['categories'] for r in c['tests'] if r['id'] == 'V14.3.2')


def test_review_of_captured_responses_survives_restart(tmp_path, lab):
    app = App(tmp_path)
    api = TestClient(create_api(app), headers={'Authorization': f'Bearer {app.token}'})
    scope = {'targets': [{'kind': 'url', 'value': lab}], 'categories': ['web'], 'rate_limit_rps': 20}
    created = api.post('/api/engagements', json={'name': 'cache policy', 'scope': scope, 'profile': 'passive'})
    assert created.status_code < 300, created.text
    eid = created.json()['id']
    review = f'/api/engagements/{eid}/coverage/asvs/V14.3.2'
    api.put(f'/api/engagements/{eid}/standards', json={'asvs': {'level': 2}}).raise_for_status()
    assert requirement(api, eid)['automatic']['status'] != 'partial_evidence'
    for path, outcome in [('challenge', 'inconclusive'), ('misconfigured', 'deviation'), ('hardened', 'conforms')]:
        capture = app.probe.request(eid, Scope(scope), f'{lab}/{path}', category='web')
        assert capture['ok'], capture
        body = {'exchange_id': capture['exchange_id'], 'sensitive': True}
        check = api.post(f'{review}/sample', json=body)
        assert check.status_code == 200, check.text
        assert check.json()['outcome'] == outcome
        assert check.json()['evidence_id'] == capture['evidence_id']
        assert api.post(f'{review}/sample', json={**body, 'sensitive': False}).status_code == 400
    assert api.post(f'{review}/sample', json={'exchange_id': 'ex_unknown', 'sensitive': True}).status_code == 404
    other = api.post('/api/engagements', json={'name': 'other engagement', 'scope': scope,
                     'profile': 'passive'}).raise_for_status().json()['id']
    assert api.post(f'/api/engagements/{other}/coverage/asvs/V14.3.2/sample', json=body).status_code == 404
    api.put(review, json={'status': 'manual', 'note': 'Recheck with release configuration'}).raise_for_status()
    api.put(review, json={'status': 'unknown'}).raise_for_status()
    app.db.close()
    app = App(tmp_path)
    api = TestClient(create_api(app), headers=api.headers)
    row = requirement(api, eid)
    assert row['automatic']['status'] == 'partial_evidence'
    assert row['manual'] is None
    history = api.get(f'{review}/history').json()
    assert [s['outcome'] for s in history['samples']] == ['inconclusive', 'deviation', 'conforms']
    assert [r['status'] for r in history['reviews']] == ['manual', 'unknown']
    report = api.get(f'/api/engagements/{eid}/report?format=json')
    assert report.status_code == 200, report.text
    snapshots = report.json()['standards'][0]['captured_response_checks']
    assert snapshots == history['samples']
    assert all(s['requirement_id'] == 'V14.3.2' for s in snapshots)
