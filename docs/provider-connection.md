# AI provider connection check

Open **Settings → AI provider**. Set the API base URL, enter the exact model ID, and enter a key if needed. Use **Test connection** before saving. Blank base URL means OpenAI; blank model ID means `gpt-4o-mini`. The check sends one short Chat Completions request and may incur a small charge. It doesn’t save settings, send assessment data, or launch an assessment.

The result includes a plain-language status and request latency. It confirms that the endpoint returned text, not that a model supports structured outputs, tool calls, or all runtime parameters. Libella doesn’t log or return the diagnostic prompt response or provider error body. A provider rejection is not a Libella session failure.

## Custom providers

Set `LIBELLA_PROVIDER_TEST_URLS` on the Libella backend to a comma-separated list of trusted exact API base URLs. For example, a locally hosted compatible server could use `http://127.0.0.1:11434/v1`. The addresses are relative to the Libella backend, not to the web browser. Only literal loopback IP addresses may use HTTP; all other endpoints require HTTPS. The check validates TLS, doesn’t follow redirects, and won’t send a saved key to another base URL. Saving a different endpoint without supplying a replacement removes the old saved key.

The allowlist constrains the diagnostic route only. It is not a network sandbox or an egress policy for existing assessment workers. Administrators should authorize only providers they control or trust. Native provider protocols, provider pricing and model discovery are not implemented by this check.

## Verification

- `tests/test_provider_diagnostic.py` exercises the authenticated route against a disposable loopback HTTP server, including key rejection, model access, quota and rate limits, redirects, malformed responses, response size, unsaved drafts, and credential isolation on endpoint change.
- `benchmarks/check_provider_ui.py` loads the built UI in Chromium, tests a rejection and a valid fixture key, checks that the draft wasn’t persisted, saves it, and captures desktop/mobile screenshots. It uses no live provider credentials and runs no assessments. Run from the repo root after building `web/dist` and installing Playwright Chromium: `PYTHONPATH=src python benchmarks/check_provider_ui.py /absolute/path/to/artifacts`.
