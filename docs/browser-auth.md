# Browser authentication

How the web UI proves it may talk to a local Libella API. This document covers the
credential's path through the browser only; encryption of the token at rest is
handled separately (`SecretBox`, see `SECURITY.md`).

## What the token is

One long-lived bearer secret per data directory, read from the `settings` table
(`api_token`) or from `LIBELLA_TOKEN` on first run. It is the operator's whole
authority over the local API, so it is treated as a credential, not a session id.

The backend never prints it at startup. Recover it deliberately, from a terminal:

```bash
LIBELLA_TOKEN=... python -m libella.main            # choose your own
libella --show-token --data-dir ~/.libella/data     # read the stored one
```

`--show-token` is a local, terminal-only operation; nothing on the HTTP surface
reveals the token.

## Where it lives in the browser

In a module-scope variable in `web/src/api.ts` — memory only, for the lifetime of
the tab. It is not written to `localStorage`, `sessionStorage`, IndexedDB, a cookie,
or a URL. Consequences, by design:

- a page reload (including an SPA deep-link refresh) asks for the token again;
- closing or duplicating the tab starts from the connect screen;
- the sign-out button clears the variable and drops the UI back to that screen;
- XSS in the app cannot lift a persisted credential out of storage, and a leaked
  URL or screenshot cannot carry it either.

`GET /api/health` stays public; every other route rejects a request without a valid
credential with `401`.

Pre-hardening builds wrote the token to `localStorage` under `libella.token`.
`web/src/api.ts` removes that key when the module loads, so an upgraded checkout
does not leave a stale credential behind in the browser profile.

## The three call paths

| Caller | Credential | Why |
| --- | --- | --- |
| Normal API calls (`fetch` in `web/src/api.ts`) | `Authorization: Bearer <token>` | Header, never logged or cached in URLs |
| Report download (Markdown / SARIF / PDF) | `Authorization: Bearer <token>` on a `fetch`, saved via a blob URL | A plain link or `window.open` would need the token in the URL |
| Live event stream (SSE) | `?ticket=<one-shot ticket>` on `GET .../stream` | `EventSource` cannot set headers, and the stream reconnects |

### Tickets

`POST /api/ticket` (bearer required, body `{"engagement_id": "<eid>"}`) returns
`{"ticket": "...", "expires_in": 60}`. A ticket

- is 192 bits from `secrets.token_urlsafe`, unrelated to the token;
- is bound to one engagement's exact stream, `/api/engagements/<eid>/stream`; it
  authorizes no other route and no other engagement, so a URL caught in a log or
  `Referer` cannot be pointed at the rest of the API;
- is consumed on first use — including a mismatched, forged or expired one — so it
  cannot be replayed, even by a concurrent duplicate;
- expires 60 seconds after issue, timed on `time.monotonic` so a wall-clock jump
  neither extends nor revokes it early; expired entries are pruned on each issue;
- cannot mint another ticket (that route is `POST` and needs the bearer token);
- is capped at 64 outstanding; issuing a 65th evicts the oldest, so a client stuck
  in a reconnect loop cannot grow the in-process store without bound.

The store is an in-process dict guarded by a `threading.Lock`, so concurrent
requests cannot interleave a consume with an issue.

### Bearer parsing

The `Authorization` header is parsed strictly: the scheme must be exactly `Bearer`,
followed by one space and the token. A bare token with no scheme, `bearer`, another
scheme, or extra whitespace is refused with `401`.

`useStream` mints a fresh ticket before every connect and every reconnect, so a
ticket appears in an access log or `Referer` at most once and is worthless by the
time anyone reads it. Query strings are still the weakest channel, which is why the
long-lived token never uses one: `?token=` is rejected with `401`.

Downloads moved off `?token=` for the same reason; `downloadReport()` fetches with
the header and hands the browser a `blob:` URL, which also avoids popup blockers
that fire after an `await`.

## Verified by

- `tests/audit/test_api_security.py::test_sse_requires_a_single_use_ticket` —
  `?token=` is refused, a ticket works exactly once, an expired or forged ticket
  is refused, and `POST /api/ticket` needs the bearer token and an engagement id.
- `tests/audit/test_api_security.py::test_ticket_is_bound_to_one_stream` — a ticket
  for one engagement opens neither another engagement's stream nor any other GET.
- `tests/audit/test_api_security.py::test_ticket_expires` and
  `::test_outstanding_tickets_are_capped` — monotonic TTL and the 64-ticket bound.
- `tests/audit/test_api_security.py::test_bearer_scheme_must_match_exactly` — a bare
  token and variants of the scheme are refused.
- `tests/audit/test_api_security.py::test_every_route_requires_a_token` — the new
  ticket route is covered by the route sweep.
- `tests/audit/test_api_security.py::test_report_download_accepts_bearer_header` —
  the download path the UI now uses.

## Not covered here

- Token generation and at-rest encryption (`SecretBox`, key file permissions).
- CSRF: there are no cookies, so cross-site requests cannot borrow credentials.
- TLS: the API binds to loopback by default; terminate TLS in front of it if it
  ever listens on anything else.