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
  --junit    gate-junit.xml
```

Installed as a console script after `pip install -e .`: `libella-gate --current ...`.
`--baseline` is optional. Without it, every verified high/critical finding in the
current report counts as new, so a first run fails closed instead of silently
passing.

Exit codes:

| code | meaning |
|------|---------|
| 0 | no new verified high/critical findings and all coverage checks passed |
| 1 | gate violation (new risk and/or incomplete coverage) |
| 2 | input or output error (unreadable/malformed report, unwritable JUnit path) |

Exit 2 is never used for findings. CI should treat it as a broken gate, not a
verified result.

## What fails the gate

A finding is *verified* only when its report state is `validated`, `reported`,
or `retested_persists` — the same definition the report uses for "confirmed".
`suspected`, `observed`, `remediated`, `retested_fixed`, and `ruled_out` are not.

- **New verified high/critical**: current finding at `high`/`critical` whose
  normalized identity is either absent from the baseline or present there only
  as unverified or below `high`. A severity escalation from medium to high
  therefore fails; a pre-existing, already-verified high does not.
- **Coverage never passes unless proven**:
  - `engagement-status`: must be `done`. `failed`, `cancelled`, and
    `budget_exhausted` are `failed`; anything else is `unknown`.
  - `intents`: zero tracked intents is `missing`; any blocked intent is
    `failed`; fewer done than total is `unknown`.
  - `degradations`: any recorded limitation is `unknown` (the report itself
    says a blocked scan must not read as all clear).
  - `findings-totals`: `summary.findings_total` and `summary.confirmed` must
    match the listed findings.
  - `baseline-findings`: a baseline finding absent from the current report is
    `missing`, not "fixed". Libella keeps fixed findings in the report as
    `retested_fixed`; disappearance means the evidence set changed.
- **Malformed input**: invalid JSON, missing mandatory sections/fields, unknown
  severity/state enum. This is a gate error (exit 2), not a finding.

Finding identity is normalized `(title, endpoint, cwe)` from the redacted
report — `dedup_key` is not exported. A title rewrite is treated as a new
finding (fail-closed, but noisy).

## JUnit output

One `<testsuite name="libella-gate">` with a testcase per coverage check and per
violating finding; failures carry the sanitized title/endpoint, never raw
control characters. Input errors produce a single testcase with `<error>`.
The file is written with escaped text and control characters replaced, so
consumer parsers (Jenkins, GitLab, `xmllint`, Python's Expat) can read it even
when a redacted finding title contains markup.

## Proving it locally

```bash
cd /home/computebox/libella-gate
PYTHONPATH=$PWD/src /home/computebox/project-pentest/libella/.venv/bin/python \
  -m pytest tests/test_gate.py -q
```

`test_end_to_end_persisted_assessment_reports` writes real SQLite engagements
and evidence stores through `render_report`, runs the CLI as a subprocess, and
parses the emitted JUnit XML.

## Limitations

- Report states are trusted as written; redaction removes the evidence needed
  to re-verify, and the gate deliberately performs no replay.
- JSON reports only; SARIF/PDF are renderings, not inputs.
- The gate compares visibility, not truth: a report that omits coverage fields
  fails as malformed, but a report can still lie about its own `done` status.
  It is not a signature or integrity check.
- Any degradation fails the gate. A clean assessment that recorded a harmless
  degradation will need a clean re-run; this is intentional fail-closed
  behaviour, not a bug to excuse in policy.
- Baseline scope drift looks like missing findings and blocks. Keep baseline
  and current scopes comparable.
- JUnit XML is the minimal shape (`tests`, `failures`, `errors`); no timestamps,
  hostname, or per-suite timing.