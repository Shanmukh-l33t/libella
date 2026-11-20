# Libella Threat Model

## Assets protected

1. Target systems (availability, integrity, confidentiality).
2. Engagement data and evidence (integrity, confidentiality).
3. Operator credentials and API tokens.
4. The host running Libella.
5. Other engagements on the same instance (isolation).

## Adversaries considered

- A malicious or compromised target serving prompt-injection content.
- A model that hallucinates findings or proposes out-of-scope actions.
- An unauthenticated network peer reaching the API.
- A local user tampering with evidence files.
- A buggy or hostile tool binary producing malformed output.

## Trust boundaries and controls

| Boundary | Control | Enforcement point |
|---|---|---|
| Engagement scope | Authorization object: targets, exclusions, ports, categories, window, budgets; fail-closed on empty | scope.py, checked in tools/runner.py and tools/http_probe.py before every egress action |
| DNS rebinding / redirect escape | Pre-resolve + per-hop redirect re-check + post-connect peer IP verification | http_probe.py |
| Metadata / link-local access | Always-blocked ranges unless explicitly targeted | scope.py ALWAYS_BLOCKED |
| LLM -> canonical state | Typed deltas through compile gate (role, scope, objective validation); model never writes DB directly | orchestrator.py _plan_llm |
| Tool arguments | JSON-schema-like typed validation, closed enums/patterns, forbidden shell metacharacters, argv list (no shell) | tools/__init__.py validate_params, runner.py |
| Finding truth | Verbatim quote must exist in a captured exchange; validated state requires independent replay reproduction | findings.py, verifier.py |
| Evidence integrity | Content-addressed sha256 blobs, append-only hash chain, re-hash on read, fail-closed | evidence.py |
| API access | Bearer token (constant-time compare), loopback-only default bind | api.py auth |
| Secrets | Redaction pass over reports/evidence views; credentials never echoed in API responses | report.py redact, api.py sanitization |
| Resource abuse | Per-engagement rate limiter, output caps, crawl bounds, subprocess timeouts, duration/cost budgets, max plan rounds | http_probe.py, runner.py, crawl.py, orchestrator.py |
| Cancellation | Engagement cancel stops leases and marks intents stopped; subprocess timeouts bound stragglers | orchestrator.py |

## Prompt injection posture

Target responses, scanner output, and crawled content are framed as untrusted
data in every prompt. Structurally, they can only become observations bound
to captured evidence; they cannot expand scope, promote findings, or write
state. The compile gate re-validates any model-proposed intent against the
scope object regardless of what the target content said.

## What we do NOT claim

- No kernel-level egress jail yet: subprocess tools that re-resolve DNS have
  a residual TOCTOU window. Roadmap: per-engagement network namespace with
  resolved-IP allowlist.
- No encryption at rest for evidence blobs; rely on filesystem/volume
  encryption. Settings-held credentials (API token, LLM key) ARE encrypted
  (Fernet, key file 0600); back up the key with the data dir.
- No multi-tenant isolation hardening; one instance per trust domain.
- Verification reproduces the recorded proof request; it does not prove
  exploitability beyond the demonstrated impact (e.g. a reflected XSS proof
  shows unescaped reflection, not a full session-theft chain).

## Verification of this model

The controls above are exercised by tests/ (unit + audit regression) and by
the PairLab benchmark (positive and negative controls). See AUDIT.md for
defects found and fixed during adversarial review.