# Offline CI gate (`libella-gate`)

Reads report JSON that Libella already rendered and answers one question: did
this assessment get worse, and can we actually tell? It never runs a scanner,
opens a socket, or re-verifies evidence.

## Usage

```bash
PYTHONPATH=/home/computebox/libella-gate/src \
/home/computebox/project-pentest/libella/.venv/bin/python -m libella.gate \
  --baseline path/to/previous/report.json \
  --current  path/to/current/report.json \
  --policy   auto \
  --junit    gate-junit.xml
```

Installed as a console script after `pip install -e .`: `libella-gate --current ...`.
`--baseline` is optional. Without it, every verified high/critical finding in the
current report counts as new, so a first run fails closed instead of silently
passing. `--policy` is optional (default `auto`).

Exit codes:

| code | meaning |
|------|---------|
| 0 | every requirement for the resolved policy satisfied, no new verified high/critical |
| 1 | gate violation (new risk and/or a requirement not satisfied) |
| 2 | input or output error (unreadable/malformed report, bad `--policy`, unwritable JUnit path) |

Exit 2 is never used for findings. CI should treat it as a broken gate, not a
verified result.

## Policy: which requirements apply

The gate evaluates an assessment against a **policy**, and resolves it itself:

| `--policy` | resolved requirement set |
|------------|--------------------------|
| `auto` (default) | from `engagement.profile`. `passive`, `production_safe` → `passive`; `safe_active`, `advanced_validation` → `active`; anything else or absent → `strict` |
| `passive` | requires a declared read-only profile. `policy_restriction` skips are expected limitations, not failures |
| `active` | requires a declared active profile. `policy_restriction` is a coverage failure |
| `strict` | previous behaviour: every recorded limitation fails |

The gate computes the verdict; it ignores any verdict field inside `report.json`.
Explicit `passive` and `active` policies reject mismatched profiles, even when no
skips are recorded. `strict` rejects every recorded limitation.

`--policy auto` trusts the declared profile. Pin an explicit policy in CI and
consume reports from a trusted producer. No policy establishes what actually ran
or proves complete methodology coverage from a redacted report alone.

## Requirement categories

The gate reports six distinct categories, each item `ok`, `limitation`,
`failed`, `missing`, or `unknown`. Only `ok` and `limitation` satisfy a
requirement; `limitation` is an expected, recorded reduction of scope and is
never a pass claim.

| category | items | fails when |
|----------|-------|------------|
| `execution` | `engagement-status` | status is `failed`/`cancelled`/`budget_exhausted`; anything but `done` is `unknown` |
| `coverage` | `intents` | zero intents (`missing`), any blocked (`failed`), fewer done than total (`unknown`) |
| `policy` | `profile`, `degradations` | non-`policy_restriction` degradations under `passive`; any degradation under `active`/`strict`; `agent_run_failed` always |
| `limitations` | `policy-limitations`, `active-validation` | never — listed so a PASS cannot be misread as full coverage |
| `incomplete` | `findings-totals` | `summary.findings_total`/`summary.confirmed` disagree with the listed findings |
| `regression` | `baseline-findings` | a baseline finding is absent from the current report |

New verified high/critical findings are reported separately as
`[vulnerability]` lines (`result["violations"]`), not as a requirement.

## What fails the gate

A finding is *verified* only when its report state is `validated`, `reported`,
or `retested_persists` — the same definition the report uses for "confirmed".
`suspected`, `observed`, `remediated`, `retested_fixed`, and `ruled_out` are not.

- **New verified high/critical**: current finding at `high`/`critical` whose
  normalized identity is either absent from the baseline or present there only
  as unverified or below `high`. A severity escalation from medium to high
  therefore fails; a pre-existing, already-verified high does not.
- **Coverage never passes unless proven** (see the category table). In
  particular:
  - `degradations` under `passive`: expected `policy_restriction` entries are
    listed as limitations; every other code (e.g. `tls_unreachable`,
    `agent_run_failed`, `verify_failed`) still fails the gate.
  - `degradations` under `active`: a `policy_restriction` means work this
    profile permits was refused, so it is unexpected and fails.
  - `baseline-findings`: a baseline finding absent from the current report is
    `missing`, not "fixed". Libella keeps fixed findings in the report as
    `retested_fixed`; disappearance means the evidence set changed.
- **Malformed input**: invalid JSON, missing mandatory sections/fields, unknown
  severity/state enum, non-string `engagement.profile`, unknown `--policy`.
  This is a gate error (exit 2), not a finding.

Finding identity is normalized `(title, endpoint, cwe)` from the redacted
report — `dedup_key` is not exported. A title rewrite is treated as a new
finding (fail-closed, but noisy).

## What a PASS means per policy

- `passive`: the declared read-only requirements were met and every policy skip
  is listed. It is **not** an active penetration test; the output states the
  profile and that the gate does not establish active validation coverage.
- `active`: the run finished its planned intents with no degradations at all and
  no new verified high/critical finding.
- `strict`: as `active`, plus no recorded limitation of any kind.

## Output

```
libella-gate: PASS
  policy: passive (declared profile 'passive')
  requirements: 7 satisfied (2 as recorded limitations), 0 not satisfied
  [ok] policy/profile: declared profile 'passive': read-only (passive) requirements
  [ok] execution/engagement-status
  [ok] coverage/intents
  [limitation] limitations/policy-limitations: 2 check(s) skipped by the read-only profile (expected): policy_restriction x2
  [ok] policy/degradations
  [limitation] limitations/active-validation: declared profile 'passive': this gate does not establish active validation coverage or represent an active penetration test
  [ok] incomplete/findings-totals
```

Every requirement is printed with its category, status and reason — satisfied
ones included — so the CI log states exactly why the gate passed or failed.

## Deriving what the report lacks

`report.json` exports `degradations` as `{code, detail}` only: the `unit` that
was skipped is inside `detail`, not a field. The gate therefore classifies by
`code` and treats a degraded unit as evidence of coverage loss only where the
policy says that unit was permitted. No schema change was made to `report.py`.

## JUnit output

One `<testsuite name="libella-gate">` with a testcase per requirement and per
violating finding; failures carry the sanitized title/endpoint, never raw
control characters. Limitations are emitted as `<skipped message="limitation: ...">`
so they appear in CI without failing the job. Input errors produce a single
testcase with `<error>`. The file is written with escaped text and control
characters replaced, so consumer parsers (Jenkins, GitLab, `xmllint`, Python's
Expat) can read it even when a redacted finding title contains markup.

## Proving it locally

```bash
cd /home/computebox/libella-gate
PYTHONPATH=$PWD/src /home/computebox/project-pentest/libella/.venv/bin/python \
  -m pytest tests/test_gate.py -q
```

`test_end_to_end_persisted_assessment_reports` and
`test_end_to_end_passive_assessment_passes_without_claiming_active_coverage`
write real SQLite engagements and evidence stores through `render_report`, run
the CLI as a subprocess, and parse the emitted JUnit XML.

## Limitations

- Report states are trusted as written; redaction removes the evidence needed
  to re-verify, and the gate deliberately performs no replay.
- The declared `engagement.profile` is trusted for `--policy auto`. Use
  `--policy active` or `--policy strict` when the pipeline must not accept a
  report that merely claims to be passive.
- JSON reports only; SARIF/PDF are renderings, not inputs.
- The gate compares visibility, not truth: a report that omits coverage fields
  fails as malformed, but a report can still lie about its own `done` status.
  It is not a signature or integrity check.
- A degradation is not proof that the work was attempted: `agent_run_failed`
  and every non-policy code fail under every policy, but a report that records
  no degradation at all still passes — absence of evidence is not evidence.
- Baseline scope drift looks like missing findings and blocks. Keep baseline
  and current scopes comparable.
- JUnit XML is the minimal shape (`tests`, `failures`, `errors`); no timestamps,
  hostname, or per-suite timing.