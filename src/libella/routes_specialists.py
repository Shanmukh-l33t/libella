"""Registered specialists: read-only lifecycle view for the operator.

Charters are created by the orchestrator's own agents, never through this API: a
route that could register one would be a way around the coordinator.
"""
from fastapi import Depends, HTTPException

from . import specialists


def register(api, app, auth):
    @api.get("/api/engagements/{eid}/specialists", dependencies=[Depends(auth)])
    def list_specialists(eid: str):
        if app.db.one("SELECT id FROM engagements WHERE id=?", (eid,)) is None:
            raise HTTPException(404, "engagement not found")
        return specialists.public_rows(app.db, eid)
