# Contributing to Libella

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cd web && npm ci && cd ..
python -m pytest tests/ -q          # must pass
ruff check src/ tests/ benchmarks/  # must pass
```

Run the labs locally for integration work:

```bash
python labs/pairlab/app.py                          # vuln :8801
LAB_MODE=hardened LAB_PORT=8802 python labs/pairlab/app.py
python benchmarks/run_pairlab.py --mode both
```

## Rules

- Evidence-first: a feature that produces findings must bind them to captured
  evidence and pass independent verification. No mock data in the product.
- Scope enforcement lives in code (scope.py / runner.py / http_probe.py),
  never only in prompts. New egress paths must go through the scope check.
- New tools: typed ToolSpec adapter, argv built by code, structured parser,
  availability probe, integration test. No shell strings, no additional_args.
- Every bug fix gets a regression test first.
- Keep the deterministic pipeline working without any LLM configured.
- Do not commit assessment data, credentials, or evidence (see .gitignore).

## Pull requests

1. Branch from main.
2. Tests + lint green; benchmark gate unchanged (13/13 vuln, 0 FP hardened).
3. Describe the change, the verification you ran, and any capability-matrix
   updates (CAPABILITIES.md).
4. UI changes: include a screenshot and confirm no console errors.

## Reporting security issues

See SECURITY.md. Do not open public issues for exploitable defects.

## Code style

Python: ruff, 100 col, type hints on public functions. TypeScript: strict,
functional components, hooks. Comments explain why, not what.