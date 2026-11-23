"""One egress decision, applied at dial time on every path a connection leaves by.

A scope check before launch is not a boundary: a redirect, a subresource, a
popup or the tool itself can dial somewhere else after the check passed. So the
policy is evaluated where the socket is opened, and what it decides is pinned:
the address the policy authorized is the address connected to, so a DNS answer
that changes between check and connect cannot move the traffic.

Enforcement levels, strongest first (a weaker level is recorded, never assumed):
  http     HttpProbe dials the pinned IP through PinnedTransport (redirect hops
           are separate decisions, each with its own pin).
  browser  every request of every page in the context -- navigation, redirect,
           subresource, XHR, websocket, popup -- goes through `gate()`; service
           workers are off and downloads are refused, so no request can bypass
           the route handler.
  scanner  a per-run HTTP/CONNECT proxy is forced into the tool (proxy env vars
           plus the tool's own proxy flag) and applies `decide()` to every
           request. Tools that only speak raw sockets (nmap) cannot be proxied:
           they stay argv-confined and are marked `egress_unconfined` with the
           exact residual in the result and an `egress_degradation` event.
"""
import http.client
import ipaddress
import socket
import threading
from collections import Counter
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import httpx

from .assessment_window import stored_stop_refusal
from .scope import normalize_scheme

PROXY_CAP = 8 * 1024 * 1024  # a proxied response body is capped, not buffered whole
SOCKET_TIMEOUT = 20


def _resolve(host: str) -> list[str]:
    """Resolve once, at decision time. Tests replace this to move DNS."""
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        return []


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved)


@dataclass
class EgressDecision:
    allowed: bool
    reason: str
    host: str = ""
    port: int = 0
    scheme: str = "http"
    ip: str | None = None       # the address to dial: what the policy authorized
    ips: list[str] = field(default_factory=list)


class Egress:
    """The single decision function every path calls before it connects.

    (host, resolved IP, port, scheme, engagement) -> allow/deny with reason.
    Denials are audited as `egress_denied` and counted per host, so a page that
    referenced third-party hosts can report how many were not contacted.
    """

    def __init__(self, db, scope, engagement_id: str, tool: str = "egress",
                 category: str = "web"):
        self.db = db
        self.scope = scope
        self.engagement_id = engagement_id
        self.tool = tool
        self.category = category
        self.denied: Counter = Counter()   # host -> denied requests
        self._audited: set[str] = set()

    # -- decisions ---------------------------------------------------------
    def deny(self, host: str, port, scheme: str, reason: str, ip: str | None = None,
             tool: str | None = None, url: str | None = None) -> EgressDecision:
        self.denied[host] += 1
        self.db.emit(self.engagement_id, "egress_denied",
                     {"host": host, "url": url or host, "ip": ip, "port": port,
                      "scheme": scheme, "reason": reason, "tool": tool or self.tool})
        # existing consumers (UI, reports) read scope_refusal; one row per host
        # keeps their volume unchanged while egress_denied carries every denial
        if host not in self._audited:
            self._audited.add(host)
            self.db.emit(self.engagement_id, "scope_refusal",
                         {"url": url or host, "reason": reason, "tool": tool or self.tool})
        return EgressDecision(False, reason, host=host, port=int(port or 0),
                              scheme=scheme, ip=ip)

    def decide(self, host: str, port: int | None = None, scheme: str = "http",
               ips: list[str] | None = None, category: str | None = None,
               tool: str | None = None, url: str | None = None) -> EgressDecision:
        """May this connection be opened to host:port over scheme?

        `url` is the request path the caller is about to send: path-scoped
        targets and url_prefix exclusions are decided on it, not on the origin.
        """
        stop = stored_stop_refusal(self.db, self.engagement_id)
        if stop:
            return self.deny(host, port, scheme, stop, tool=tool, url=url)
        host = (host or "").lower().rstrip(".")
        if not host:
            return self.deny(host, port, scheme, "no host", tool=tool)
        if scheme in ("ws", "wss"):
            scheme = normalize_scheme(scheme)  # a ws dial is an http(s) destination
        if scheme not in ("http", "https"):
            return self.deny(host, port, scheme, f"scheme '{scheme}' not permitted", tool=tool)
        port = int(port or (443 if scheme == "https" else 80))
        ips = list(ips) if ips is not None else _resolve(host)
        if not ips:
            return self.deny(host, port, scheme, f"DNS resolution failed for {host}", tool=tool)
        literal = _is_literal(host)
        authority = host if literal and ":" not in host else (f"[{host}]" if ":" in host else host)
        decision = self.scope.check_url(url or f"{scheme}://{authority}:{port}/",
                                       category or self.category, ips=ips)
        if not decision.allowed:
            return self.deny(host, port, scheme, decision.reason, tool=tool, url=url)
        private = [ip for ip in ips if _is_private(ip)]
        if private and not literal and not self.scope.ip_in_targets(ips):
            # a name authorized as a name, resolving onto loopback/private space,
            # is a rebinding or an SSRF pivot -- not the target the operator named
            return self.deny(host, port, scheme,
                             f"{host} resolves to {private[0]} (private/loopback) and no "
                             "ip/cidr target authorizes it", ip=private[0], tool=tool, url=url)
        return EgressDecision(True, "in scope", host=host, port=port, scheme=scheme,
                              ip=ips[0], ips=ips)

    def decide_url(self, url: str, category: str | None = None,
                   tool: str | None = None) -> EgressDecision:
        try:
            p = urlparse(url)
            host, port = p.hostname or "", p.port
        except ValueError as e:
            return self.deny(str(url), None, "", f"unparseable url: {e}", tool=tool)
        return self.decide(host, port, (p.scheme or "http").lower(),
                           category=category, tool=tool, url=url)

    def gate(self, url: str, tool: str | None = None,
             category: str = "web") -> EgressDecision:
        """Browser-side check for one request, whatever its type."""
        p = urlparse(url)
        if p.scheme not in ("http", "https", "ws", "wss"):
            return self.deny(p.hostname or url, p.port, p.scheme,
                             f"scheme '{p.scheme}' not permitted", tool=tool, url=url)
        return self.decide_url(url, category=category, tool=tool)

    def summary(self) -> dict:
        """What was refused and never contacted -- for the run's report."""
        return {"denied_requests": sum(self.denied.values()),
                "blocked_hosts": sorted(self.denied)}


class PinnedTransport(httpx.HTTPTransport):
    """Dial the pinned IP; URL path, Host header and TLS SNI keep the name."""

    def __init__(self, host: str, ip: str, **kw):
        super().__init__(**kw)
        self._host, self._ip = host.lower(), ip

    def handle_request(self, request):
        if request.url.host.lower() == self._host and self._ip != self._host:
            request.headers.setdefault("Host", request.url.netloc.decode("ascii"))
            request.extensions = {**request.extensions, "sni_hostname": self._host}
            request.url = request.url.copy_with(host=self._ip)
        return super().handle_request(request)


# -- browser -----------------------------------------------------------------

def _route_handler(egress: Egress, on_request=None):
    def handle(route):
        req = route.request
        if urlparse(req.url).scheme not in ("http", "https", "ws", "wss"):
            return route.continue_()  # data:/blob:/about: never leave the browser
        if not egress.gate(req.url).allowed:
            return route.abort("blockedbyclient")
        if on_request is not None:
            on_request(req)
        return route.continue_()
    return handle


def _websocket_handler(egress: Egress):
    def handle(ws):
        if not egress.gate(ws.url).allowed:
            return ws.close(code=1008, reason="egress policy")
        return ws.connect_to_server()
    return handle


def open_browser_context(browser, egress: Egress, on_request=None, **opts):
    """A context where every request of every page is policy-checked.

    Context-level routes cover popups and pages a target opens itself, which a
    page-level route does not. Service workers would let a page fetch outside
    the route handler, so they are blocked; downloads are refused, so a link a
    page pushes never reaches a non-authorized origin or the disk.

    The context also dials THROUGH the egress proxy, so a websocket upgrade --
    which `route_web_socket` can only judge by URL -- is decided and connected at
    the proxy: Chromium tunnels `ws`/`wss` with CONNECT, and the proxy dials the
    address it decided, not a name the browser resolves again. `bypass`
    `<-loopback>` keeps loopback targets in that path too.
    """
    proxy = EgressProxy(egress)
    ctx = browser.new_context(ignore_https_errors=True, service_workers="block",
                              accept_downloads=False,
                              proxy={"server": proxy.url, "bypass": "<-loopback>"},
                              **{k: v for k, v in opts.items()
                                 if k not in ("service_workers", "accept_downloads", "proxy")})
    ctx.libella_egress_proxy = proxy  # the dialer this context uses; tests read it
    ctx.on("close", lambda *_: proxy.close())
    ctx.route("**/*", _route_handler(egress, on_request))
    if hasattr(ctx, "route_web_socket"):
        # a second gate on the upgrade itself: refuse it before the browser opens
        # the tunnel the proxy would then have to judge
        ctx.route_web_socket("**/*", _websocket_handler(egress))
    return ctx


# -- scanner subprocesses ----------------------------------------------------

class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # never leave tool traffic in the platform log
        pass

    def _deny(self, d: EgressDecision):
        body = f"libella egress denied: {d.reason}".encode()
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(":")
        # A CONNECT tunnel names host:port, not a scheme: Chromium uses it for wss
        # AND for plain ws. Decide as https, fall back to http, so a destination
        # authorized for either scheme is reachable while the host/port/ip rules
        # stay the same for both.
        d = self.server.egress.decide(host.strip("[]"), int(port or 443), "https")
        if not d.allowed:
            alt = self.server.egress.decide(host.strip("[]"), int(port or 443), "http")
            if alt.allowed:
                d = alt
        self.server.seen.append(("CONNECT", f"{host}:{port}", d.allowed, d.ip))
        if not d.allowed:
            return self._deny(d)
        try:
            upstream = socket.create_connection((d.ip, d.port), timeout=SOCKET_TIMEOUT)
        except OSError as e:
            return self._fail(f"upstream connect failed: {e}")
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.close_connection = True
        _relay(self.connection, upstream)

    def _proxy_http(self):
        u = urlparse(self.path)
        if u.scheme not in ("http", "https") or not u.hostname:
            return self._fail("proxy request must be an absolute http(s) url")
        d = self.server.egress.decide(u.hostname, u.port, u.scheme)
        self.server.seen.append((self.command, self.path, d.allowed, d.ip))
        if not d.allowed:
            return self._deny(d)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("proxy-connection", "connection", "keep-alive",
                                        "content-length", "host")}
        headers["Host"] = u.netloc  # the authorized name, dialed at the pinned ip
        headers["Via"] = "1.1 libella-egress"
        conn = http.client.HTTPConnection(d.ip, d.port, timeout=SOCKET_TIMEOUT)
        path = u.path or "/"
        if u.query:
            path += f"?{u.query}"
        try:
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(PROXY_CAP)
        except (OSError, http.client.HTTPException) as e:
            return self._fail(f"upstream request failed: {e}")
        finally:
            conn.close()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "keep-alive",
                                 "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _proxy_http

    def _fail(self, reason: str):
        body = reason.encode()
        self.send_response(502)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def _pump(src, dst):
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _relay(client, upstream):
    up = threading.Thread(target=_pump, args=(upstream, client), daemon=True)
    up.start()
    _pump(client, upstream)
    up.join(SOCKET_TIMEOUT)
    upstream.close()


class EgressProxy:
    """The only way out for a confined scanner: policy is applied per request."""

    def __init__(self, egress: Egress):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
        self.server.daemon_threads = True
        self.server.egress = egress
        # every decision this proxy took, in order: (method, target, allowed, dialed ip)
        self.server.seen = []
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def proxy_env(base: dict, proxy_url: str) -> dict:
    """Every proxy variable a tool might read; NO_PROXY is emptied on purpose.

    A tool that inherits a NO_PROXY=localhost default would dial the target
    directly and leave the policy behind.
    """
    return {**base, "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
            "http_proxy": proxy_url, "https_proxy": proxy_url,
            "ALL_PROXY": proxy_url, "NO_PROXY": "", "no_proxy": ""}
