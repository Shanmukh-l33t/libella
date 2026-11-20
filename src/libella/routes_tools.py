"""Tool readiness routes: level checks backed by local-fixture scans.

The GET is cached for five minutes inside readiness.py; the POST forces one
tool through its deep check now. Deep checks serialize on a module lock, so a
UI click storm cannot start several scanners at once.
"""
from fastapi import Depends, HTTPException

from .tools import readiness


def register(api, app, auth):
    @api.get("/api/tools/readiness", dependencies=[Depends(auth)])
    def tools_readiness():
        return readiness.report(app.registry)

    @api.post("/api/tools/{name}/readiness", dependencies=[Depends(auth)])
    def tool_readiness(name: str):
        # Caller picks a registered tool only; executable and arguments stay server-side.
        try:
            spec = app.registry.get(name)
        except KeyError:
            raise HTTPException(404, "Tool not registered.") from None
        return readiness.check(spec, force=True)
