"""Application discovery: turn real traffic and code into application intelligence.

The point of this module is to replace NAME LISTS with EVIDENCE. A fixed list of likely
paths (`/fetch`, `/api/orders`) only finds what someone already thought of; measured on
PairLab it cost the engine two of sixteen seeds, and on Juice Shop it produced a false
positive. So every fact recorded here states where it came from:

    traffic      a request the application itself made (browser network log, crawl)
    response     a response body that carries an object and its owner field
    bundle       a JavaScript bundle's own route and endpoint strings
    openapi      the application's published description
    source       authorised source inspection

`ingest_traffic` is the workhorse: given the runtime API requests the browser engine
already captures, it derives routes, endpoints, parameters, resources and owner fields, and
links them. Nothing is invented: a parameter exists because a request carried one, a
resource because a response returned a record, an owner because a record named one.

`candidate_features` is the other half: it names functionality that SHOULD exist given the
vocabulary of the app's own observed traffic (an import feature implies a destination
parameter) so an agent can test a hypothesis instead of guessing a path.
"""
import json
import re
from urllib.parse import parse_qsl, urlparse

from . import appintel
from .appintel import AppIntel

# Auth-shaped paths an app links to but never renders as normal content.
AUTH_HINT = re.compile(r"(?i)/(login|signin|sign-in|logout|register|signup|password|reset|"
                       r"forgot|auth|session|token|verify|activate)")

# Field names a served record uses to say who owns it. The list is a starting vocabulary,
# not the mechanism: whatever single-valued scalar field a record carries is recorded, and
# a field whose value differs per identity becomes an owner candidate through observation.
OWNER_HINTS = ("user_id", "owner_id", "customer_id", "account_id", "tenant_id", "uid",
               "ownerid", "userid", "created_by", "member_id", "org_id", "company_id")

# A destination parameter is one whose VALUE is a place: a URL, a path, a file, a host.
# The list is a name vocabulary, but the mechanism is broader: a value that parses as an
# absolute URL marks its parameter regardless of what it is called, which is why `where`
# or `q` carrying `http://...` raises the fetch question and a bare word does not.
DESTINATION_NAMES = ("url", "uri", "target", "src", "source", "dest", "destination",
                     "next", "redirect", "redirect_uri", "return", "returnurl", "callback",
                     "file", "path", "image", "webhook", "endpoint", "link", "host",
                     "where", "from", "to", "site", "page_url", "address")


def _looks_like_place(value: str) -> bool:
    """Does this parameter VALUE name somewhere a server could be asked to fetch?

    An absolute URL, a scheme-relative URL or a traversal path qualifies. A bare filename
    does NOT: `name=readme.txt` is a file selector, and treating it as a remote reference
    raised an SSRF question against a parameter that takes a local file (measured on
    PairLab, where it produced a hypothesis for `name`).
    """
    v = (value or "").strip()
    if re.match(r"^(https?:)?//", v, re.I) or v.startswith("../"):
        return True
    return bool(re.match(r"^/[a-z0-9_]", v, re.I)) and "." not in v.split("/")[-1]


def _norm_path(url: str) -> str:
    """Path with query stripped and numeric ids replaced, so /orders/101 and /102 are one route."""
    path = urlparse(url).path or "/"
    return re.sub(r"/\d+(?=/|$)", "/{id}", path)


def _record_of(body: str) -> dict | None:
    """The single record inside a JSON response, unwrapping one named envelope."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if isinstance(data, list):
        return data[0] if data and isinstance(data[0], dict) else None
    if not isinstance(data, dict):
        return None
    if "id" in data:
        return data
    for value in data.values():
        if isinstance(value, dict) and "id" in value:
            return value
        if isinstance(value, list) and value and isinstance(value[0], dict) and "id" in value[0]:
            return value[0]
    return None


def _owner_field(record: dict) -> tuple[str, object] | None:
    """(field, value) naming the record's owner, by vocabulary first, then by shape."""
    if not isinstance(record, dict):
        return None
    for name in OWNER_HINTS:
        if name in record and isinstance(record[name], (str, int)) and record[name] != "":
            return name, record[name]
    # nothing matched the vocabulary: any field whose name reads as an owner
    for name, value in record.items():
        low = name.lower()
        if isinstance(value, (str, int)) and value != "" and (
                low.endswith("_id") or low.endswith("id") and low != "id"
                or low.startswith("owner") or low.endswith("_by")):
            if low != "id":
                return name, value
    return None


class Discovery:
    """Records application intelligence from evidence produced elsewhere."""

    def __init__(self, db, engagement_id: str, intel: AppIntel | None = None):
        self.db = db
        self.eng = engagement_id
        self.intel = intel or AppIntel(db, engagement_id)

    # ------------------------------------------------------------------ traffic
    def ingest_traffic(self, api_requests: list[dict], *, evidence_id: str | None = None,
                       provenance: str = appintel.OBSERVED) -> dict:
        """Record routes, endpoints, parameters and auth-shaped features from real requests.

        `api_requests` is the crawler's own list: {method, url, page}. Each entry becomes
        an endpoint with its parameters, linked to the route it belongs to and to the page
        whose action triggered it, which is the edge that later answers "what feature does
        this belong to".
        """
        routes, endpoints, params, auth = set(), set(), set(), set()
        for req in api_requests or []:
            url = req.get("url") or ""
            if not url:
                continue
            method = (req.get("method") or "GET").upper()
            route = _norm_path(url)
            route_id = self.intel.add(appintel.ROUTE, route, route,
                                      {"method": method}, provenance=provenance,
                                      evidence_id=evidence_id)
            if AUTH_HINT.search(route):
                auth.add(route)
                self.intel.add(appintel.SENSITIVE_OP, f"auth:{route}", route,
                               {"kind": "authentication"}, provenance=provenance,
                               evidence_id=evidence_id)
            ep_key = f"{method} {url.split('?')[0]}"
            ep_id = self.intel.add(appintel.ENDPOINT, ep_key, url.split("?")[0],
                                   {"method": method, "raw": url}, provenance=provenance,
                                   evidence_id=evidence_id)
            self.intel.link(route_id, ep_id, "has_endpoint", provenance, evidence_id=evidence_id)
            for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
                params.add(name)
                shaped = name.lower() in DESTINATION_NAMES or _looks_like_place(value)
                p_id = self.intel.add(appintel.PARAM, name, name,
                                      {"seen_value": value[:80],
                                       "destination_shaped": shaped,
                                       "because": ("name" if name.lower() in DESTINATION_NAMES
                                                   else "value" if _looks_like_place(value)
                                                   else None)},
                                      provenance=provenance, evidence_id=evidence_id)
                self.intel.link(ep_id, p_id, "accepts", provenance, evidence_id=evidence_id)
                if shaped:
                    self.intel.add(appintel.SENSITIVE_OP, f"remote_reference:{ep_key}",
                                   f"remote reference via '{name}'",
                                   {"param": name}, provenance=appintel.INFERRED,
                                   evidence_id=evidence_id)
            routes.add(route)
            endpoints.add(ep_key)
        return {"routes": len(routes), "endpoints": len(endpoints),
                "params": len(params), "auth_features": len(auth)}

    def ingest_response(self, url: str, body: str, *, method: str = "GET",
                        evidence_id: str | None = None) -> dict:
        """Record the resource model a response reveals: object, id field, owner field.

        This is what makes IDOR testable WITHOUT guessing: the resource and its owner come
        from the record the application served, so a later test compares identities against
        a relationship the app itself published.
        """
        record = _record_of(body)
        if not record:
            return {"resource": None}
        # the resource is named by the LAST LITERAL segment: on /api/orders/{id} that is
        # "orders", not the normalised placeholder, or every collection would collide into
        # one resource called "{id}" and its ownership candidates would be meaningless
        literal = urlparse(url).path.rstrip("/").split("/")
        res_key = next((seg for seg in reversed(literal) if seg and not seg.isdigit()), "") \
            or urlparse(url).path.strip("/") or "root"
        res_id = self.intel.add(appintel.RESOURCE, res_key, res_key,
                                {"id_field": "id", "sample_id": record.get("id")},
                                provenance=appintel.OBSERVED, evidence_id=evidence_id)
        # The endpoint that served this record is itself evidence: record it and link it,
        # rather than only linking when a crawl happened to register the same URL. Without
        # this edge the resource has no serving endpoint and the authorization hypothesis
        # is blocked forever, which reads as "nothing to test" instead of a missing link.
        ep_key = f"{method.upper()} {url.split('?')[0]}"
        ep_id = self.intel.add(appintel.ENDPOINT, ep_key, url.split("?")[0],
                               {"method": method.upper(), "from": "response"},
                               provenance=appintel.OBSERVED, evidence_id=evidence_id)
        self.intel.link(ep_id, res_id, "serves", appintel.OBSERVED, evidence_id=evidence_id)
        owner = _owner_field(record)
        if owner:
            name, value = owner
            o_id = self.intel.add(appintel.OWNER, name, name, {"sample_value": value},
                                  provenance=appintel.OBSERVED, evidence_id=evidence_id)
            self.intel.link(res_id, o_id, "owned_by", appintel.OBSERVED, evidence_id=evidence_id)
            return {"resource": res_key, "owner_field": name, "owner_value": value}
        return {"resource": res_key, "owner_field": None}

    # ------------------------------------------------------------------- bundles
    def ingest_bundle(self, text: str, *, source_ref: str) -> dict:
        """Route and endpoint strings a JavaScript bundle states about itself.

        Modern applications expose most functionality through client code rather than
        HTML links, so a crawl sees a single page and an API client sees everything. The
        strings are recorded as `source` provenance: they are the app's own declaration,
        not a guess, but they are a claim about code rather than an observed request.
        """
        paths = set()
        for pattern in (r"""["'`](/(?:api|rest|v\d|graphql|admin|internal)[^"'`\s]*)["'`]""",
                        r"""(?:url|path|endpoint)\s*[:=]\s*["'`](/[^"'`\s]+)["'`]"""):
            for m in re.finditer(pattern, text):
                paths.add(m.group(1).split("?")[0])
        for route in sorted(paths)[:400]:
            self.intel.add(appintel.ROUTE, _norm_path(route), route,
                           {"from": "bundle"}, provenance=appintel.SOURCE,
                           source_ref=source_ref, confidence=0.7)
        if paths:
            self.db.emit(self.eng, "app_bundle_routes",
                         {"source_ref": source_ref, "routes": len(paths)})
        return {"routes": len(paths)}

    # ------------------------------------------------------------------- openapi
    def ingest_openapi(self, spec: dict, *, base: str, source_ref: str) -> dict:
        """The application's own published description: routes, operations, parameters."""
        count = 0
        for route, ops in (spec.get("paths") or {}).items():
            if not isinstance(ops, dict):
                continue
            route_id = self.intel.add(appintel.ROUTE, _norm_path(route), route,
                                      {"from": "openapi"}, provenance=appintel.SPEC,
                                      source_ref=source_ref)
            for method, op in ops.items():
                if str(method).lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                ep = self.intel.add(appintel.ENDPOINT,
                                    f"{method.upper()} {route}", route,
                                    {"method": method.upper(), "from": "openapi"},
                                    provenance=appintel.SPEC, source_ref=source_ref)
                self.intel.link(route_id, ep, "has_endpoint", appintel.SPEC)
                for p in (op or {}).get("parameters") or []:
                    name = p.get("name") if isinstance(p, dict) else None
                    if not name:
                        continue
                    schema = (p.get("schema") or {}) if isinstance(p, dict) else {}
                    dest = str(schema.get("format", "")).lower() in ("uri", "url") \
                        or name.lower() in DESTINATION_NAMES
                    pid = self.intel.add(appintel.PARAM, name, name,
                                         {"from": "openapi", "destination_shaped": dest},
                                         provenance=appintel.SPEC, source_ref=source_ref)
                    self.intel.link(ep, pid, "accepts", appintel.SPEC)
                    count += 1
        return {"endpoints": count}

    # -------------------------------------------------------------- hypotheses
    def candidate_features(self) -> list[dict]:
        """Functionality worth investigating, derived from what the app already showed.

        Not a path list: each candidate names a SECURITY QUESTION and the evidence that
        raised it, so an agent can decide whether to test it and how. A destination-shaped
        parameter on an observed endpoint is a server-side fetch question; an owner field
        on a served resource is an authorization question; an auth-shaped route is a session
        question.
        """
        out: list[dict] = []
        for op in self.intel.nodes(appintel.SENSITIVE_OP):
            if op["key"].startswith("remote_reference:"):
                out.append({
                    "feature": "server-side fetch",
                    "property": "the server must not fetch arbitrary caller-supplied URLs",
                    "raised_by": op["key"], "provenance": op["provenance"],
                    "test": "point the parameter at a destination the app is not entitled to "
                            "reach and show whether it is fetched",
                })
            elif op["key"].startswith("auth:"):
                out.append({
                    "feature": "authentication",
                    "property": "session state must change predictably across login/logout",
                    "raised_by": op["key"], "provenance": op["provenance"],
                    "test": "capture the session lifecycle and replay it after logout",
                })
        for res in self.intel.nodes(appintel.RESOURCE):
            owners = [e for e in self.intel.edges(res["id"]) if e["kind"] == "owned_by"]
            if owners:
                out.append({
                    "feature": f"{res['key']} ownership",
                    "property": "a record may only be read by its owner (or an admin)",
                    "raised_by": f"resource {res['key']} owns {owners[0]['other']['label']}",
                    "provenance": owners[0]["provenance"],
                    "test": "read the record as a second identity and compare the served "
                            "owner with the requester",
                })
        return out
