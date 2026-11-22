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
| Browser: websockets | `context.route_web_socket`, upgrade refused unless allowed | same |
| Browser: service workers, downloads | `service_workers="block"`, `accept_downloads=False` (cannot be routed around) | same |
| Browser: third-party hosts a page references | aborted, counted per host, reported as `egress_blocked_third_party` in `degraded` and in `result["egress"]` | `browser_crawl._result` |
| Scanner subprocesses | per-run HTTP/CONNECT proxy (`EgressProxy`) forced in by env `HTTP(S)_PROXY`/`ALL_PROXY` (with `NO_PROXY` emptied) and each tool's own flag (`nuclei -proxy`, `httpx -http-proxy`, `ffuf -x`); the proxy applies `decide()` to every request and CONNECT | `tools/runner.py`, `egress.EgressProxy` |

Credentials and cookies never reach a non-authorized origin because the request
is aborted before it is dispatched, and each browser context is per authorization.

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
- **Websocket pinning.** `route_web_socket` decides on the URL, but
  `connect_to_server()` dials by name; the upgrade cannot be pinned to one IP.
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