# Egress enforcement

Scope checked before launch is not a boundary. A redirect, a subresource, a popup
or the tool itself can dial somewhere else after the check passed, so the
platform now makes **one decision at dial time** and pins what it decided.

## The decision

`libella.egress.Egress.decide(host, port, scheme, ips=None)` →
`EgressDecision(allowed, reason, host, port, scheme, ip, ips)`.

It combines, in this order:

1. **The engagement may touch the target at all** — `assessment_window.stored_stop_refusal`
   (paused, cancelled, or the authorized window closed).
2. **The Scope** — `Scope.check_url` / `check_host_port` with the resolved IPs
   passed in (`ips=`), so the name *and* the address are checked against targets,
   exclusions, `allowed_ports` and the always-blocked ranges (metadata, link-local,
   multicast, reserved).
3. **The resolved address** — the host is resolved **once**, and that list is what
   the Scope decides on. `ip` in the result is the address the connection must be
   opened to, so a DNS answer that changes afterwards cannot move the traffic.
4. **Rebinding guard** — a *name* that resolves onto loopback/private space is
   refused unless an `ip`/`cidr` target authorizes that address (`Scope.ip_in_targets`).
   An engagement that names a hostname has not authorized `127.0.0.1`, `10.0.0.0/8`
   or `169.254.169.254` behind it.

Every denial is audited as `egress_denied` (`host`, `url`, `ip`, `port`, `scheme`,
`reason`, `tool`) and, once per host, as the `scope_refusal` the UI and reports
already read.

## Every path obeys it

| Path | Enforcement | Where |
|---|---|---|
| HTTP client, every redirect hop | `PinnedTransport` rewrites the socket destination to the decided IP; `Host` header and TLS SNI stay the authorized name | `tools/http_probe.py`, `egress.PinnedTransport` |
| Body of a slow response | a pause/cancel/window close mid-body aborts the read | `http_probe._read_capped` |
| Browser: navigation, redirect, subresource, XHR/fetch, popup | one **context-level** `route("**/*")`; page-level routes do not cover popups | `egress.open_browser_context` |
| Browser: the whole context | `open_browser_context` puts the context behind an `EgressProxy` (`proxy={"server": ..., "bypass": "<-loopback>"}`), so every dial — including loopback targets — is a proxy decision, and the proxy dials `decision.ip` | `egress.open_browser_context` |
| Browser: websockets | `context.route_web_socket` gates the upgrade by URL, and Chromium tunnels `ws`/`wss` through that proxy with CONNECT, so the upgrade is decided AND pinned at the same event. `EgressProxy.server.seen` records every decision | same |
| Browser: service workers, downloads | `service_workers="block"`, `accept_downloads=False` (cannot be routed around) | same |
| Browser: third-party hosts a page references | aborted, counted per host, reported as `egress_blocked_third_party` in `degraded` and in `result["egress"]` | `browser_crawl._result` |
| Scanner subprocesses | per-run HTTP/CONNECT proxy (`EgressProxy`) forced in by env `HTTP(S)_PROXY`/`ALL_PROXY` (with `NO_PROXY` emptied) and each tool's own flag (`nuclei -proxy`, `httpx -http-proxy`, `ffuf -x`); the proxy applies `decide()` to every request and CONNECT | `tools/runner.py`, `egress.EgressProxy` |

Credentials and cookies never reach a non-authorized origin because the request
is aborted before it is dispatched, and each browser context is per authorization.

A websocket is authorized as the http(s) origin it upgrades from:
`scope.normalize_scheme` maps `ws`→`http` and `wss`→`https` for the decision, and
`parse_origin`/`check_url` apply it so port, path, exclusion and resolved-address
rules are identical to the page's. The transport is untouched — this only changes
which destination the policy compares. A CONNECT tunnel carries host:port and no
scheme, so the proxy decides it as `https` and falls back to `http`; either way it
connects to `decision.ip`, never to a name the browser resolves again.

## Confinement level per tool (recorded, never assumed)

`runner.run()` returns `result["egress"] = {level, proxy, residual, denied_requests, blocked_hosts}`:

- `proxy` — HTTP tools: nuclei, httpx, ffuf, and any future tool that honours the
  proxy environment. Every request is decided at dial time by the proxy.
- `unconfined` — tools that only speak raw sockets (`nmap`). They stay confined by
  argv (resolved IP, `authorized_ports`) and the run is marked with an
  `egress_degradation` event carrying code `egress_unconfined` and the exact residual.
- `third_party` — passive tools (`subfinder`, `network_effect=False`) that dial
  third-party sources by design. Marked `egress_third_party`; engagement scope
  cannot be applied to destinations the operator never authorized.

## Residual risks

- **Unproxied subprocess traffic.** A `proxy`-level tool that ignores its proxy
  environment/flag (raw sockets, UDP, DNS) is not blocked by the platform: the
  proxy only sees what the tool sends it. `nmap` is the explicit example and is
  marked unconfined. Closing this needs a network namespace with a route to the
  proxy, which needs `CAP_NET_ADMIN` on the host side (root) — checked on this
  host (`unshare -rn` works, but a fresh namespace has no route to the target or
  the proxy, so applying it to a tool that must reach the target makes it useless).
- **Websocket pinning (browser path) is closed.** The upgrade is decided by
  `route_web_socket` and again by the context proxy's CONNECT, which dials the
  pinned address; `tests/test_egress_enforcement.py` proves an authorized upgrade
  completing on its fixture and zero hits on a reachable unauthorized one. This
  does NOT extend to a raw-socket client outside the browser: anything that dials
  `socket.create_connection` directly is still argv- or proxy-confined only.
- **TLS through the proxy** is tunneled (CONNECT), so the proxy decides the
  destination host/port but does not see the path.
- Other egress paths outside this change still check scope before they dial and
  should be moved onto `Egress`: `tls_audit.py` (raw TLS dial), `traffic.py`
  (replay), `tools/browser_fetch.fetch` (no policy; `browser_crawl.fetch_scoped`
  is the gated replacement, and `http_probe.browser_request` now uses it).

## Tests

`tests/test_egress_enforcement.py` — real sockets only, assertions on the fixture
servers' hit logs: authorized host+port contacted; unauthorized port refused;
redirect to another host and to an unauthorized port refused; DNS change between
check and connect pinned (one resolution, first address only); rebinding to
metadata and to a private address refused; pause mid-body stops the stream;
browser page with third-party script/img/fetch/websocket/download/popup contacts
the third-party server **zero** times; popup to another origin refused; scanner
subprocess goes through the proxy for an authorized target and reaches nothing
for an unauthorized one; raw tool marked unconfined; cancel mid-run stops traffic.

Websockets are covered in both directions with the positive twin required: an
in-scope `ws` upgrade completes on its fixture and echoes a frame (`msg:hi`), the
proxy records the CONNECT decision that dialed `127.0.0.1`, an unauthorized
`127.0.0.2` websocket server that IS listening records zero hits, and a websocket
to an unauthorized port on the authorized host is refused while the authorized one
in the same context still connects. `tests/test_scope.py` covers the scheme
normalization itself: `ws` is decided as `http`, `wss` as `https`, default ports
follow, and port, path, exclusion, category, metadata and userinfo rules still
apply to a websocket URL.

Every negative here is paired with a positive in the same test, because "zero
hits" is also what a blanket refusal produces — the vacuous result this suite
previously had.