# Report integrity and privacy

The client-facing report is the only thing most engagements ever deliver, so it carries
two promises: every claim in it comes from captured evidence, and no credential captured
during the assessment leaves the process inside it.

## Invariant

`libella.report.redact()` is the single redaction pass. Every report surface goes through
it: `report.md` (whole document), `report.json` and `report.sarif` (per field via
`_safe()`), the PDF (`report_pdf._text()`), the `report` evidence blob, and the
`/api/evidence/{id}` / `/api/exchanges/{id}` views. A shape that survives `redact()` leaks
in all of them, so the pass is the place to fix — never a per-format patch.

Redaction is deliberately lossy and idempotent: it runs twice on the Markdown (once per
field, once over the assembled document) and again in the PDF, so every pattern must be
stable under re-application (asserted in `tests/report/test_report_redaction_shapes.py`).

## Defect fixed: quoted and scheme-prefixed credentials

The pass keyed on *labels followed by a separator* (`password=`, `Cookie:`, `Bearer `).
Two commonplace shapes have a character between the label and the separator and were
therefore never matched:

| Captured shape | Before |
|---|---|
| `{"password": "..."}`, `{"db_password": "..."}`, `{"api_key":"..."}` | rendered verbatim |
| `{"Authorization": "Basic <base64>"}` | rendered verbatim |
| `Authorization: Basic <base64>` (text) | scheme word consumed, **base64 credential left in place** |

The first two are ordinary API request/response bodies quoted into a finding description,
so secrets reached `report.md`, `report.json`, `report.sarif`, the stored report evidence
and the PDF. The third is the same header the tooling already masks structurally via
`redact_headers()`, defeated as soon as it appears in prose, a log line or an LLM summary.

Fix, in `REDACT_PATTERNS`:

- an `Authorization`/`Proxy-Authorization` header pattern that consumes the whole value,
  including Basic/Digest/Negotiate scheme credentials;
- one quoted `key: value` pattern covering the full credential label set plus affixes
  (`db_password`, `client_secret`, `access_key_id`), preserving the value's quote so the
  surrounding JSON still parses. It replaces the narrower double-quote cookie-only rule.

Second, smaller gap closed at the same time: `report.json` and the report evidence blob
were the only surfaces that did not redact engagement `name`/`status_detail` or
`degradations[].code/detail`. Those strings come from exception text (`str(e)`) and can
echo a request body; they now go through `_safe()` like every other field.

## What the tests hold

`tests/report/test_report_redaction_shapes.py` exercises the full persistence/export path
on synthetic data — DB rows → `render_report()` (md/json/sarif + evidence blob) →
`render_pdf()` — and asserts no secret appears in any of the five outputs, that the JSON
still parses, that `[REDACTED]` markers are present, and that the evidence chain verifies.
Eight of its cases fail on the previous implementation.

## Known limits (not fixed here)

- A credential with no label at all (`http://user:pass@host`, a bare base64 blob) is not
  redacted; there is nothing to key on. Treat such values as "do not capture" upstream.
- `scope` values are exported as recorded. MD/PDF pass them through `redact()` too, so the
  behaviour is at least uniform; but a target URL containing userinfo is not specifically
  masked.
- Only `report.json` is stored as an evidence blob. `report.md`/`report.sarif`/`report.pdf`
  are rewritten from DB state on every export, so a hand-edited copy is not detectable by
  hash the way the JSON is.