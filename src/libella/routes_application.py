"""Application intelligence API: what the engine understands about the application.

Read-only by design. The model is written by discovery during an assessment, never by a
caller, so an operator can inspect it but cannot assert a fact into it from the outside.
Every node carries its provenance for the same reason the agents need it: a reader must be
able to tell an observed route from an inferred one.
"""
from fastapi import Depends, HTTPException

from .appintel import KINDS, AppIntel


def register(api, app, auth):
    def _intel(eid: str) -> AppIntel:
        row = app.db.one("SELECT id FROM engagements WHERE id=?", (eid,))
        if not row:
            raise HTTPException(404)
        return AppIntel(app.db, eid)

    @api.get("/api/engagements/{eid}/application", dependencies=[Depends(auth)])
    def application(eid: str, kind: str | None = None, min_provenance: str | None = None):
        """The model: shape, nodes by kind, gaps, and the questions the evidence raises."""
        intel = _intel(eid)
        return {
            "shape": intel.summary(),
            "nodes": intel.nodes(kind, min_provenance=min_provenance),
            "edges": intel.edges_all(),
            "gaps": intel.gaps(),
            "candidate_features": _features(intel),
            "kinds": list(KINDS),
        }

    def _features(intel) -> list:
        try:
            from .discovery import Discovery
            return Discovery(app.db, intel.eng, intel).candidate_features()
        except Exception:  # a feature derivation bug must not blank the model
            return []

    @api.get("/api/engagements/{eid}/application/context", dependencies=[Depends(auth)])
    def application_context(eid: str, focus: str | None = None, limit: int = 25):
        """Exactly what an agent sees for a focus, so an operator can audit that view."""
        return _intel(eid).context(focus, limit=limit)
