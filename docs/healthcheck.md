# Health endpoint hardening

## Contract

| Route | Auth | Body |
|-------|------|------|
| `GET /api/health` | none | `{"status": "ok", "version": "<package version>"}` |
| `GET /api/tools` | bearer token | tool inventory (`Registry.available()`) |

`/api/health` is the only unauthenticated JSON route (plus the static UI at `/`).
It answers liveness only: it touches no tool binary and discloses no inventory.

The version comes from `libella.__version__` (the packaged value), never a
literal, so the API cannot drift from `pyproject.toml`.

## Why

Before this change the public probe returned

```json
{"status": "ok", "version": "0.1.0", "tools": [ ... 9 entries ... ]}
```

Two problems:

1. **Cost on an unauthenticated path.** Every anonymous request ran
   `Registry.available()`, which calls `resolve_binary()` for each registered
   tool — a `stat`/`access` pair on `/usr/local/bin/<tool>` (and
   `$LIBELLA_TOOL_PATH`) plus a `shutil.which()` PATH walk. The work scales with
   the size of the registry and the host PATH, and any process that can reach
   the port could force it in a loop.
2. **Inventory disclosure.** The response listed every tool name, description,
   category, parameter schema and install state — a map of what the box can do
   and what it is missing, handed to an unauthenticated caller.

## Consumers

Anonymous `GET /api/health` is still used by the login screen (reachability and
version), so the route stays public and cheap. Everything that needs the
inventory now calls the authenticated `/api/tools`: the Tool center
(`web/src/pages/Tools.tsx`), the Engagements dashboard and the Command Center.
`Settings.tsx` already used `/api/tools`. The Tool center additionally reads
`version` from `/api/health`.

## Measurement

`benchmarks/bench_health.py` (in-process `TestClient`, 200 requests, same
sandbox, 9 registered tools, no network):

| Endpoint | baseline median / p95 | after median / p95 | payload |
|----------|----------------------|--------------------|---------|
| `GET /api/health` | 1.58 ms / 1.84 ms | 1.24 ms / 1.50 ms | 3709 B → 33 B |
| `GET /api/tools` (token) | 1.78 ms / 2.16 ms | 1.75 ms / 2.19 ms | 3667 B |

The saving is small here because the registry holds 9 tools and most binaries
are absent locally; on a host with a full scanner install and a long PATH the
removed probe path is the dominant cost, and the payload difference is fixed.

## Test

`tests/audit/test_api_security.py::test_health_leaks_no_inventory_and_probes_nothing`
monkeypatches `libella.tools.resolve_binary` to raise, then asserts the public
probe still answers 200 with exactly `{status, version}`. Any future
re-introduction of tool probing or inventory on the anonymous path fails the
test.

## Note

`web/src/components/TokenScreen.tsx` (owned elsewhere) renders
`${health.tools?.length ?? 0} tools`; with `tools` gone it shows "0 tools".
One-line fix when that file is next touched: drop the tool count and show
`Backend ${health.version}` only.