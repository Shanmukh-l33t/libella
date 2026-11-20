# Libella web

React 18 + Vite 5 + TypeScript + Tailwind 3 frontend for the Libella API.

## Develop

```bash
npm install
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

The backend serves `web/dist` at `/` when it exists. `dist/404.html` lets Starlette's
`StaticFiles(html=True)` render the SPA for `/engagements/:id` and `/findings/:id`
refreshes (the response status stays 404, which browsers ignore for rendering).

SSE uses `EventSource`, which cannot set headers: the client mints a single-use,
60-second ticket from `POST /api/ticket` and passes it as `?ticket=`. The long-lived
token is never put in a URL. Report downloads go through `fetch` with the bearer
header and save the blob locally.