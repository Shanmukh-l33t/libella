# Validation workspace

`/validation` is a read-only review surface for candidate and verified findings. It answers, per finding: how was this detected, was impact demonstrated, what did independent verification decide, and what remains uncertain.

## What it shows

- Engagement picker with counts: Not verified, Verified, Closed.
- Status labels mapped from the finding lifecycle and the last recorded verdict: Suspected, Validation pending, Verified, Retested fixed, Still present, Not reproduced, Inconclusive, Did not reproduce, Blocked by policy, Verification failed.
- A four-cell case strip per finding: Detection, Impact, Verification decision, Limitations.
- A keyboard-operable technical panel with evidence object ids and the request that produced each.

## What it never claims

- `Verified` means the finding state is `validated`, `reported` or `retested_persists` — an independent replay reproduced the recorded proof. It is never set from a tool exit code.
- Impact text is the check's prediction, labelled "Predicted, not demonstrated" or "Not demonstrated". A verified finding is not automatically a demonstrated impact; exploitability prediction is shown as "Not assessed" until a separate, evidence-backed assessment exists.
- Missing fields read "No impact statement recorded." or "Not assessed"; nothing is invented.

## Controls

The workspace issues only GET requests (`/api/engagements/{id}/findings`, `/api/findings/{id}`). Verify, retest and lifecycle actions remain on the finding detail page, where they were before.

## Verification

- `benchmarks/check_validation_ui.py <data-dir> <out-dir>` drives the built UI in Chromium against a copy of a real completed engagement: labels render, no non-GET request is issued, no "Impact demonstrated" text appears, 390 px has no horizontal overflow, and no console errors occur.
- Fixture-based smoke (all ten labels, keyboard expansion, mobile) was run during development; the repeatable check above is the committed one.
