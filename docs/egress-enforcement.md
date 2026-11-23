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
- `isolated` — tools that only speak raw sockets (`nmap`, `RAW_TOOLS`). They run in a
  disposable network namespace (`libella.netns.Confinement`) as uid 65534 with no
  capabilities. The nftables filter is INSIDE the namespace (`policy drop`, accept only
  the authorized IPv4 addresses x tcp ports, plus established/related), so the tool
  cannot alter it. The level is reported only after the filter was applied and read
  back, and the command ran through `ip netns exec`. `egress_degradation` carries code
  `egress_isolated` and `enforced` = the exact ruleset.
- `fail_closed` — isolation could not be set up (not root, `ip`/`nft`/`setpriv`
  missing, target not host-local or loopback, no free /30, filter not verified). The
  tool is **not run**, the call is audited as refused, and `egress_degradation` carries
  `egress_fail_closed`. Nothing is claimed as confined.
- `unconfined` — only on the explicit opt-out `ToolRunner(raw_egress="unconfined")` /
  `LIBELLA_RAW_EGRESS=unconfined`: argv (resolved IP, `authorized_ports`) is the only
  boundary. Marked `egress_unconfined` with the residual on every run.
- `third_party` — passive tools (`subfinder`, `network_effect=False`) that dial
  third-party sources by design. Marked `egress_third_party`; engagement scope
  cannot be applied to destinations the operator never authorized.

## Residual risks

- **Raw-socket tools: design chosen and why.** Measured on this host:
  (a) "namespace holds only a policy proxy" would block nmap outright (it cannot use an
  HTTP proxy for scanning), so it is not usable for scanners; (b) forwarding does not
  work reliably here: with `ip_forward=1`, a scoped masquerade table and an accept in a
  separate forward chain, a namespace connection to 8.8.8.8:53 (which the host itself
  reaches) timed out, because docker's `FORWARD` `policy drop` is in another owner's
  table and an accept elsewhere does not override a drop. Making it work means editing
  `DOCKER-USER`, which Libella must not do. So the namespace has **no forwarding**: its
  only route is the host end of the veth and it reaches addresses **the host terminates**
  (lab/host-local targets, measured: eth0's own address connects). The in-namespace
  filter then admits only the authorized `ip:port`s. A target the host does not terminate
  (any remote address) or a loopback target fails closed instead of being scanned blind
  (a remote target would otherwise look `filtered`, indistinguishable from a real
  firewall). Remote scanning needs either the explicit opt-out or an operator-provided
  forward path, which is follow-up work.
- **netns residuals.** TCP only (nmap `-sT`; as uid 65534 it cannot send raw SYNs, and
  the filter would drop UDP/ICMP/IPv6 anyway). The tool can still talk to every service
  on the authorized addresses within the authorized ports. The tool shares the host's
  kernel, so a kernel privilege-escalation bug defeats any namespace. The /30 is chosen
  at random from 10.254.0.0/16 and skipped if a route overlaps; two overlapping
  non-route uses of that range (e.g. an address on another interface without a route)
  are not detected. A hard-killed Libella leaves its `lbns<pid>_*`/`lbh<pid>_*` objects
  until the next confined run, which reaps those whose pid is dead (`reap_orphans`).
  Root is required (`CAP_NET_ADMIN`). The engagement-level opt-in lives on the runner
  (`raw_egress` / env), not in the Scope model (that file is not part of this change).
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

`tests/test_netns_confinement.py` — real sockets, a fake raw scanner
(`tests/fixtures/raw_tool.py`) and accept-level hit logs on three host-local fixtures that
are all routable from the namespace: authorized `A:pA` is reached (hits >= 1), `A:pB`
(unauthorized port) and `B:pA` (unauthorized address) get zero hits. Mutations: flush the
allow rule and the authorized connection fails; delete the filter and both unauthorized
destinations are reached, so the negatives are not vacuous. No `lbns*`/`lbh*`/`lbn*` object
survives success, exception, timeout, cancel or a failing tool; the reaper clears a dead
pid's leftovers; with `ip`/`nft` failing (or a loopback/remote target) the tool is refused
and never runs; the explicit opt-out is reported `unconfined`.
