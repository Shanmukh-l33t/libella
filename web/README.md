# Libella web

React 18 + Vite 5 + TypeScript + Tailwind 3 frontend for the Libella API.

## Develop

```bash
npm install
npm run dev          # http://127.0.0.1:5173, proxies /api -> http://127.0.0.1:8787
```

Start the backend (`python -m libella.main`) and paste the token it prints into the
connect screen. The token is stored in `localStorage` and sent as a bearer token.

## Build

```bash
npm run build        # writes dist/ and a 404.html copy for SPA deep links
```

The backend serves `web/dist` at `/` when it exists. `dist/404.html` lets Starlette's
`StaticFiles(html=True)` render the SPA for `/engagements/:id` and `/findings/:id`
refreshes (the response status stays 404, which browsers ignore for rendering).

SSE uses `EventSource` with `?token=`, a persisted `since` cursor and backoff reconnect.