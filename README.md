# Libella

Autonomous penetration-testing workbench. Evidence-first, scope-enforced, multi-agent.

Libella plans, executes, verifies, and reports authorized security assessments.
It is not a chatbot that runs security commands, and not a scanner wrapper.
Every finding must survive independent replay verification before it is
called validated. Every network action is checked against an enforceable
engagement authorization object before it executes.

> For systems you own or are explicitly authorized to test. Libella enforces
> scope in code, but authorization is your responsibility. See SECURITY.md.

## What makes it different

- **Scope is code, not prompt.** Targets, exclusions, ports, categories, time
  window, rate and budget limits live in an engagement authorization object.
  The tool execution layer resolves DNS and checks every target (including
  redirect hops and post-connect peer IPs) before execution. Refusals are
  audited. Prompts derive from the scope object; they never replace it.
- **Verified means reproduced now.** Candidate findings carry a replayable
  proof request and a verbatim evidence quote. An independent verifier
  re-issues the request and compares the fresh response. No replay, no
  promotion. Scanner banners and version strings are observations, never
  automatic findings.
- **Tamper-evident evidence.** Content-addressed blobs with an append-only
  hash chain. Integrity is re-checked on every read; chain breaks fail closed.
- **Typed tools, no shell.** Adapters build argv from validated, typed
  parameters. There is no free-text argument that reaches a command line and
  no generic shell tool exposed to the model.
- **Deterministic core, optional LLM planning.** The full assessment pipeline
  runs without any model (reproducible, benchmarkable, offline). An LLM
  planner can add investigation intents through a compile gate that re-checks
  scope and rejects invalid proposals.
- **One container, one file of state.** SQLite + evidence directory. No
  Postgres, no Temporal, no queue service. `docker compose up` and go.

## Verified results (real execution, not claims)

PairLab benchmark (labs/pairlab): a vulnerable/hardened twin app with 13
seeded vulnerability classes and machine-readable ground truth.

| Mode | Seeded vulns detected + independently validated | False positives | Duration |
|---|---|---|---|
| Vulnerable twin | 13 / 13 | 0 | ~156s (with nuclei) / ~8s (deterministic only) |
| Hardened twin | 0 (correct) | 0 | ~154s / ~7s |

Evidence hash chains intact across all runs. Reproduce:

```bash
python labs/pairlab/app.py                      # vuln  :8801
LAB_MODE=hardened LAB_PORT=8802 python labs/pairlab/app.py
python labs/pairlab/verify_ground_truth.py      # lab self-check
python benchmarks/run_pairlab.py --mode both
```

See CAPABILITIES.md for the full tested/planned matrix and benchmark details.

## Quickstart (Docker)

```bash
git clone https://github.com/Shanmukh-l33t/libella && cd libella
export LIBELLA_TOKEN=*** rand -hex 24)
docker compose up -d --build
# UI + API at http://127.0.0.1:8787 (loopback-only by default)
```

Open the UI, enter the token, create an engagement against a lab target
(e.g. OWASP Juice Shop on 127.0.0.1:3001), start it, watch live operations,
inspect findings and evidence, export the report.

## Quickstart (development)

```bash
# backend (Python 3.12+)
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m libella.main --port 8787 --data-dir ./data
# token is printed at startup

# frontend (Node 22+)
cd web && npm ci && npm run build   # built UI served by backend at /
# or: npm run dev                   # Vite dev server proxies /api to :8787

# tests
python -m pytest tests/ -q
```

Optional scanner toolchain (the platform degrades loudly without them):
nmap, nuclei (+ templates), ProjectDiscovery httpx, subfinder, ffuf.
Availability is probed at startup and shown in Settings.

## Configure a model (optional, for LLM planning)

Settings > LLM provider: any OpenAI-compatible endpoint (base URL, API key,
model). Per-role model selection and fallback are supported. Token and cost
accounting is recorded per engagement. Deterministic mode needs no model.

## Architecture

Single Python process (FastAPI) + embedded SQLite (WAL) + content-addressed
evidence store + static React UI. Supervisor planner emits leased worker
intents (fencing tokens, expiry sweep, bounded retries). Workers execute
typed tool adapters and deterministic checks. An independent verifier
replays proof requests. Reports render deterministically from typed state
(Markdown, JSON, SARIF) with secret redaction.

Read ARCHITECTURE.md for the decision record and THREAT_MODEL.md for the
security model and known limits.

## Safety model (summary)

- Fail-closed scope: empty scope is rejected at creation.
- Metadata/link-local ranges blocked unless explicitly targeted.
- Per-engagement rate, concurrency, duration, and cost budgets.
- Profiles: passive, safe_active, advanced_validation (explicit opt-in).
- Emergency stop: cancel propagates to intents and subprocesses.
- Localhost-only bind by default; token auth on every API route.
- Credentials redacted from logs, evidence views, and reports.
- Target content is untrusted data; it cannot mutate canonical state.

## Project status

Working and benchmarked: engagement lifecycle, scope enforcement, recon,
crawling, deterministic web/API checks, nuclei/nmap/httpx/subfinder/ffuf
adapters, independent verification, retest, hash-chained evidence, reporting,
live UI, LLM planning mode. See CAPABILITIES.md for what is tested vs planned.

## License

Apache-2.0. See LICENSE and NOTICE. Security tool binaries (nmap, nuclei,
sqlmap-adjacent, etc.) carry their own licenses; Libella invokes them as
subprocesses and does not link them.

## Contributing / Security

CONTRIBUTING.md for development workflow. SECURITY.md for the disclosure
policy and the authorization requirements.