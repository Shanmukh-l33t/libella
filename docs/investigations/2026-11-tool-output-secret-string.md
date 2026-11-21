# Investigation: secret-looking string in tool output for `policy.py`

Status: **open (source outside the repository not determined)**. Treated as untrusted.

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

## Handling

- Not executed, not copied into reports, not quoted in logs or this document.
- Libella code is unaffected; no change made.
- Re-open if the string appears in a file's bytes (`git diff`, `cat -A`), in a
  generated report or evidence blob, or in a subprocess environment.