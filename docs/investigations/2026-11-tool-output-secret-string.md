# Investigation: secret-looking string in tool output for `policy.py`

Status: **closed - agent tool-output canary, no repository defect.** Treated as untrusted throughout.

## Observation

A delegated worker reading `src/libella/policy.py` reported a secret-looking
string of the form `SI_SECRET_TOKEN_<random>` appearing inside `MIN_PROFILE`,
with a value that changed between reads. It took no action on it.

## What was checked (2026-11-21)

| Check | Result |
|---|---|
| Blob hash of the working-tree file vs `HEAD:src/libella/policy.py` | identical (`git hash-object` == `git rev-parse HEAD:...`) |
| Raw bytes of `MIN_PROFILE` (`cat -A`) | plain values (`"passive"`, `"safe_active"`, ...); no token |
| `grep SI_SECRET src/libella/policy.py` | 0 matches |
| Repository history (`git log -S SI_SECRET_TOKEN --all`) | one commit, `9892b47`, which adds a **fixed** fake value to `tests/test_secrets_at_rest.py` (a synthetic sentinel for the secrets-at-rest test). It never appears in `policy.py` and never changes. |
| Other `SI_SECRET*` strings | fixed synthetic sentinels in `benchmarks/check_report_exports.py`, `benchmarks/check_report_recovery_ui.py`, `labs/apilab/app.py` (lab fixture credential, allowlisted in `.gitleaks.toml`) |

## Conclusion

The string did not come from the file: disk content is byte-identical to the
committed version and contains no such value. A value that changes between reads
cannot be the repository's fixed sentinel. The remaining candidates are outside
the repository: the agent tool-output layer (secret redaction or canary
instrumentation that rewrites secret-looking spans), or tool-output injection.
Neither could be confirmed from inside the workspace.

## Confirmed 2026-11-21 (deterministic checks, no text layer)

Reproduced in the main checkout while reading `MIN_PROFILE`: the display showed
`"cookie_flags": "SI_SECRET_TOKEN_<random>"` where the source has `"passive"`, and the
token differed between two consecutive reads of the same file.

| Check | Result |
|---|---|
| `git hash-object src/libella/policy.py` | `f9fd71bb...` |
| `git rev-parse HEAD:src/libella/policy.py` | `f9fd71bb...` (identical) |
| `git cat-file -p HEAD:src/libella/policy.py \| grep -c SI_SECRET` | 0 |
| `grep -c SI_SECRET src/libella/policy.py` | 0 |
| `python -c "import libella.policy as p; print(repr(p.MIN_PROFILE['cookie_flags']))"` | `'passive'` |
| `permits('cookie_flags', 'passive')` | True |

The authoritative blob, the on-disk bytes and the imported module agree; only the
rendered tool output disagreed, with a value that changed every read. That is an
output-layer canary/redaction mechanism outside the repository, not content of the
file, not a prompt injection payload in the tree, and not a leaked credential.

## Handling

- Not executed, not copied into reports, not quoted in logs or this document.
- Libella code is unaffected; no change made.
- Re-open if the string appears in a file's bytes (`git diff`, `cat -A`), in a
  generated report or evidence blob, or in a subprocess environment.