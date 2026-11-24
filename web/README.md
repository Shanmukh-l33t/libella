# Libella web

React 18 + Vite 7 + TypeScript + Tailwind 3 frontend for the Libella API.
Use Node 22.12 or newer on the Node 22 release line used by CI and Docker.

## Develop

```bash
npm ci
npm run dev          # http://127.0.0.1:5173, proxies /api -> http://127.0.0.1:8787
```

Start the backend with `LIBELLA_TOKEN` set, or read the stored token from the data
directory with `libella --show-token --data-dir <dir>` in a terminal, then paste it
into the connect screen. The token lives in memory for that tab only — it is never
written to `localStorage`/`sessionStorage` — so a reload asks for it again.

## Build

```bash
npm run build        # writes dist/ and a 404.html copy for SPA deep links
```

The backend serves `web/dist` at `/` when it exists. Refreshing a client route
such as `/engagements/:id` serves the SPA with HTTP 200. Missing API routes and
assets still return 404.

SSE uses `EventSource`, which cannot set headers: the client mints a single-use,
60-second ticket bound to that engagement's stream (`POST /api/ticket` with
`{"engagement_id": "<eid>"}`) and passes it as `?ticket=`. The long-lived
token is never put in a URL. Report downloads go through `fetch` with the bearer
header and save the blob locally.