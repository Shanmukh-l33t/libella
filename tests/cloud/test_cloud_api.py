"""POST /api/engagements/{id}/cloud-audit: runs the audit, enforces scope."""


def _engagement(app, client, scope_value):
    r = client.post("/api/engagements", headers=_auth(app), json={
        "name": "cloud api", "scope": {"targets": [{"kind": "cloud", "value": scope_value}],
                                       "categories": ["cloud"]}})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _auth(app):
    return {"Authorization": f"Bearer {app.token}"}


def test_cloud_audit_endpoint_runs_and_persists_findings(app, client, labs, cloud):
    eid = _engagement(app, client, labs["vuln"])
    r = client.post(f"/api/engagements/{eid}/cloud-audit",
                    headers=_auth(app),
                    json={"endpoint": labs["vuln"], "region": "us-east-1",
                          "creds": cloud.creds()})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert len(body["findings"]) == 12
    listed = client.get(f"/api/engagements/{eid}/findings", headers=_auth(app)).json()
    assert len(listed) == 12
    assert {f["cwe"] for f in listed} >= {"CWE-732", "CWE-269", "CWE-284", "CWE-311",
                                          "CWE-778", "CWE-306", "CWE-324"}


def test_cloud_audit_endpoint_refuses_out_of_scope(app, client, labs, cloud):
    eid = _engagement(app, client, "999999999999")
    r = client.post(f"/api/engagements/{eid}/cloud-audit",
                    headers=_auth(app),
                    json={"endpoint": labs["vuln"], "region": "us-east-1",
                          "creds": cloud.creds()})
    assert r.status_code == 403
    assert client.get(f"/api/engagements/{eid}/findings", headers=_auth(app)).json() == []


def test_cloud_audit_requires_credentials(app, client, labs):
    eid = _engagement(app, client, labs["vuln"])
    r = client.post(f"/api/engagements/{eid}/cloud-audit", headers=_auth(app),
                    json={"endpoint": labs["vuln"], "region": "us-east-1"})
    assert r.status_code == 400


def test_cloud_audit_accepts_creds_ref_from_env(app, client, labs, monkeypatch):
    monkeypatch.setenv("LIBELLA_CLOUD_CREDS_LAB", "cloudlab:SI_SECRET_APIKEY_ENV7YQ2M")
    eid = _engagement(app, client, labs["hardened"])
    r = client.post(f"/api/engagements/{eid}/cloud-audit", headers=_auth(app),
                    json={"endpoint": labs["hardened"], "region": "us-east-1",
                          "creds_ref": "lab"})
    assert r.status_code == 200, r.text
    assert r.json()["findings"] == []
