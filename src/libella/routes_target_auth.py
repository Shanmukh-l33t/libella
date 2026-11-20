"""Target credential routes: sealed at rest, never value-returning."""
import json

from fastapi import Depends, HTTPException

from . import target_auth
from .scope import Scope


def register(api, app, auth):
    target_auth.ensure_schema(app.db)

    def _engagement(eid: str) -> dict:
        row = app.db.one("SELECT id, scope_json FROM engagements WHERE id=?", (eid,))
        if row is None:
            raise HTTPException(404, "engagement not found")
        return row

    def _credential(eid: str, cid: str) -> dict:
        row = app.db.one(
            "SELECT * FROM target_credentials WHERE id=? AND engagement_id=?", (cid, eid))
        if row is None:
            raise HTTPException(404, "credential not found")
        return row

    @api.post("/api/engagements/{eid}/credentials", dependencies=[Depends(auth)])
    def create_credential(eid: str, body: dict):
        _engagement(eid)
        try:
            parsed = target_auth.parse(body)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        cid = target_auth.insert(app.db, app.box, eid, parsed)
        app.db.emit(eid, "target_credential_added",
                    {"credential_id": cid, "type": parsed["type"], "name": parsed["name"]})
        return target_auth.public_row(_credential(eid, cid))

    @api.get("/api/engagements/{eid}/credentials", dependencies=[Depends(auth)])
    def list_credentials(eid: str):
        _engagement(eid)
        return [target_auth.public_row(r) for r in app.db.query(
            "SELECT * FROM target_credentials WHERE engagement_id=? ORDER BY created_at", (eid,))]

    @api.delete("/api/engagements/{eid}/credentials/{cid}", dependencies=[Depends(auth)])
    def delete_credential(eid: str, cid: str):
        _credential(eid, cid)
        app.db.execute("DELETE FROM target_credentials WHERE id=? AND engagement_id=?", (cid, eid))
        app.db.emit(eid, "target_credential_removed", {"credential_id": cid})
        return {"deleted": True, "id": cid}

    @api.post("/api/engagements/{eid}/credentials/{cid}/test", dependencies=[Depends(auth)])
    def test_credential(eid: str, cid: str, body: dict | None = None):
        eng = _engagement(eid)
        row = _credential(eid, cid)
        data = body or {}
        url = data.get("url")
        if not isinstance(url, str) or not url.strip():
            raise HTTPException(400, "url is required")
        expect = data.get("expect_substring")
        if expect is not None and (not isinstance(expect, str) or not expect
                                   or len(expect) > target_auth.EXPECT_MAX
                                   or any(ord(c) < 32 for c in expect)):
            raise HTTPException(400, "expect_substring must be 1-200 printable characters")
        scope = Scope(json.loads(eng["scope_json"]))
        try:
            return target_auth.run_test(app, scope, eid, row, url.strip(), expect)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
