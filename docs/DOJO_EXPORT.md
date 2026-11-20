# DefectDojo export (Generic Findings Import)

`GET /api/engagements/{id}/report?format=dojo` returns the normalized, redacted report as
DefectDojo's **Generic Findings Import** JSON, and the Report tab has a **DefectDojo** button.
Nothing is written outside Libella's data dir and nothing is sent anywhere: the browser
downloads the file, the operator imports it.

## Format mapping

| Libella (`report.json`) | DefectDojo item |
|---|---|
| `findings[].title` | `title` |
| `severity` critical/high/medium/low/info | `Critical`/`High`/`Medium`/`Low`/`Info` |
| `cwe` `CWE-89` | `cwe: 89` (integer, omitted when unparseable) |
| `endpoint` | `endpoints: [url]`, only when it is an absolute `scheme://` URL |
| description + impact + remediation + evidence ids + verification | `description` |
| engagement `started_at` | `date` (date-only, stable) |
| finding state / verifications | see truth table below |

Top-level `name`, `type`, `description` describe the test; the test description carries the
engagement status and every coverage limitation, so an incomplete assessment cannot import
as "all clear".

## Identity and truth

- `unique_id_from_tool = libella:<engagement id>:<finding id>` — unique inside one export
  and stable across re-exports of unchanged state (the whole document is byte-identical).
- `verified` is `true` **only** when the finding's last independent replay verdict is
  `reproduced`. A lifecycle state alone never sets it.
- `active: false` + `is_mitigated: true` for `retested_fixed`; `active: false` + `false_p:
  true` for `ruled_out`; everything else is `active: true`. DefectDojo has no field for
  "observed but unverified", so that distinction lives in `description`.

## Verification: what was actually proven

Two separate levels, do not conflate them.

1. **Parser acceptance — proven in CI.** `tests/report/test_dojo_export.py` runs the payload
   through DefectDojo 3.5.202's own `dojo/tools/generic/json_parser.py`, vendored unmodified
   in `tests/fixtures/defectdojo/` and executed with stubbed `dojo`/`django` modules. This
   proves the field whitelist, required fields, severities, CWE ints, endpoints and unique
   ids pass the parser. It does **not** prove a database import.
2. **Real API import — proven once, manually.** A disposable DefectDojo 3.5.202 stack
   (`docker compose up` from the tagged repo, local only, synthetic data) returned `201` from
   `POST /api/v2/import-scan/` (`scan_type=Generic Findings Import`,
   `auto_create_context=true`). Reading `/api/v2/findings/?test_id=…` back showed the four
   synthetic findings with their severities, `cwe: 89`, endpoints, `date`, and
   `unique_id_from_tool` intact. Nothing is committed that requires this stack; it is not a
   regression test.

Findings from that run (worth knowing before trusting an import):

- **The request flags override per-finding truth.** With `active=true&verified=false` in the
  import request, every finding imported as unverified — including the one whose item said
  `verified: true`. Passing `verified=false` when a test has mixed evidence silently demotes
  every verified finding, and omitting the flags with older clients that default them to
  `true` does the opposite. `dojo/importers/default_importer.py` only keeps the item values
  when the flags are absent (`None`).
- **`unique_id_from_tool` is stored but not used by default dedupe.** A second import of the
  same file created four new findings. DefectDojo's shipped dedupe is hash-only; enable a
  unique-id-based dedupe algorithm on the product if re-imports must merge.
- Titles are title-cased by DefectDojo on import; that is cosmetic.

## Import recipe

```bash
curl -sS -X POST https://<defectdojo>/api/v2/import-scan/ \
  -H "Authorization: Token $DD_TOKEN" \
  -F scan_type="Generic Findings Import" \
  -F auto_create_context=true \
  -F product_type_name="Libella" -F product_name="Acme" \
  -F engagement_name="Acme external" \
  -F file=@libella-eng_abc-defectdojo.json
# omit `active` and `verified`: supplying them forces one value onto every finding
```

## Browser transport integration (auth worker)

The export link intentionally does **not** put the API token in a URL; query-string tokens
end up in history, referrers and proxy logs. `downloadReport()` in `web/src/api.ts` performs
an authenticated `fetch` with the `Authorization` header and saves the response as a blob.

That function is the single seam for the in-progress transport change: when the browser
worker replaces the header token with a session cookie (or any other scheme), change only
`downloadReport()` — add `credentials: "same-origin"` and drop the header — and the route,
the button and the format stay as they are. The route sits behind the existing `auth`
dependency, so it follows whatever the transport validates; the UI helper simply never
puts the token in the URL.