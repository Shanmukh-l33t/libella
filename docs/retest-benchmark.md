# Retest benchmark result

Run on the integrated `defensive-readiness` branch against the local PairLab twin on `127.0.0.1:8803` (owned lab, no external target). Command: `benchmarks/run_retest_cycle.py 1` then `2`, swapping the lab from vulnerable to hardened between phases.

Finding: `Debug endpoint exposes configuration/secrets` (`/debug`).

| Phase | Lab mode | Verdict | Detail | Finding state after |
|---|---|---|---|---|
| 1 | vulnerable | `persists` | verbatim quote present in replay body | `retested_persists` |
| 2 | hardened | `inconclusive` | status class changed 200 -> 404: quote absent from replay body | `retested_persists` |

## Interpretation

Phase 1 reproduces the original proof, so the finding correctly stays present.

Phase 2 removes the route (200 becomes 404). The current retest rule earns `fixed` only when the proof quote is absent **and** the response status class matches the original proof. A removed route changes the status class, so the verdict is `inconclusive`, not `fixed`. This is the conservative behavior introduced in PR #2: a changed response alone is not proof of remediation.

This is honest but limited. The master directive (section 8) asks for corroborating signals so an intentional route removal can be recognized as remediation: the original condition is no longer reachable through any supported route, legitimate functionality still works, and the protected behavior is independently observed. That richer retest logic is not implemented yet. Until it is, a remediation that deletes a route reads as `inconclusive` and a human confirms the fix.

## Compatibility

Proof specs created before PR #2 have no recorded `proof_status`. Retesting those findings returns `inconclusive` (fail-closed) because the baseline status class is unknown. No automatic migration backfills a status that was never captured.
