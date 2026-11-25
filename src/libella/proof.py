"""Typed proof contracts: what a finding of each class must be able to SHOW.

A check producing an observation is not the observation proving the weakness. The
verifier used to equate the two: it replayed the recorded quote and called that
confirmation, so an IDOR whose "proof" was a public profile page and an SSRF whose
marker was the empty string both reached 'validated' through a genuine replay.

A candidate therefore carries a `proof` contract describing the test it ran, and the
differential that makes the observation meaningful:

    assertion        the security claim, in the check's own terms
    identity         {name, value}: who the request was made as (authorization)
    owner_field      body field naming the record's owner, and the value it held
    owner_value
    marker           the controlled value that must appear only when the weakness holds
    benign_request   the negative control: same endpoint, no payload/marker/foreign id
    document         canonical resource identity ('': and '/' are ONE document)
    controls, cookie, missing   header/cookie specifics

`missing()` names what a contract still lacks; the verifier refuses to promote a
finding with any gap, and NOTHING is defaulted: an absent prerequisite is a refusal,
because a guessed value is how a finding gets "verified" for something never tested.
"""
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

AUTHORIZATION = "authorization"
SSRF = "ssrf"
INJECTION = "injection"
SQL_ERROR = "sql_error"
BLIND_COMMAND = "blind_command"
HEADERS = "headers"
SESSION = "session"
GENERIC = "generic"

CWE_CLASS = {
    "CWE-639": AUTHORIZATION, "CWE-862": AUTHORIZATION, "CWE-863": AUTHORIZATION,
    "CWE-284": AUTHORIZATION, "CWE-566": AUTHORIZATION, "CWE-425": AUTHORIZATION,
    "CWE-918": SSRF, "CWE-1385": SSRF,
    "CWE-79": INJECTION, "CWE-94": INJECTION, "CWE-1336": INJECTION, "CWE-22": INJECTION,
    "CWE-611": INJECTION, "CWE-601": INJECTION,
    # The signal alone can appear without injection: a server may raise a database error
    # for any malformed input, and a delay can be load. These two need a benign control;
    # every other class in INJECTION proves itself when its quote comes back verbatim
    # (a reflected payload, an evaluated expression, /etc/passwd, a redirect target).
    "CWE-89": SQL_ERROR, "CWE-78": BLIND_COMMAND,
    "CWE-943": SQL_ERROR,
    "CWE-693": HEADERS,
    "CWE-614": SESSION, "CWE-1004": SESSION, "CWE-1275": SESSION,
    # CWE-613 (a logout or an expired token that still works) is not a cookie-flag claim:
    # SESSION would demand cookie+missing flags and read Set-Cookie on the replay, which
    # a replayed protected page never carries. It stays GENERIC: the audit already holds
    # the anonymous control (protected URL refused without the credential) before it
    # submits, and the replay shows the stale credential is still honoured.
}


def kind_for(cwe: str | None) -> str:
    return CWE_CLASS.get((cwe or "").upper(), GENERIC)


def _text(v) -> str:
    return v.strip() if isinstance(v, str) else ""


def _request(value) -> dict:
    return value if isinstance(value, dict) else {}


def missing(kind: str, contract: dict | None, proof_request: dict | None = None,
            assertion: str = "") -> list[str]:
    """Prerequisites this contract does not satisfy. Empty means it may be verified.

    `assertion` is the finding's own statement of what was tested (its title), so a check
    that never filled a contract is judged on what it claimed, not on an empty string.
    """
    if kind == GENERIC:
        # No typed contract exists for this class, so there is nothing to demand beyond the
        # reproduced observation. Saying so is the point: an untyped class is not evidence
        # that its prerequisites were checked.
        return []
    c = contract if isinstance(contract, dict) else {}
    gaps = [] if (_text(c.get("assertion")) or _text(assertion)) else ["assertion"]
    pr = _request(proof_request)
    if not _text(pr.get("url")):
        gaps.append("proof_request.url")
    if kind == AUTHORIZATION:
        identity = _request(c.get("identity"))
        if not _text(identity.get("name")):
            gaps.append("identity.name")
        if identity.get("value") in (None, ""):
            gaps.append("identity.value")
        # Two authorization models, and a finding must say which one it tested:
        # ownership (another user's object) or privilege (a role the caller lacks).
        if _text(c.get("privilege")):
            pass
        elif _text(c.get("owner_field")):
            if c.get("owner_value") in (None, ""):
                gaps.append("owner_value")
        else:
            gaps += ["owner_field", "privilege"]
        headers = {str(k).lower() for k in (pr.get("headers") or {})}
        if not ({"cookie", "authorization"} & headers):
            gaps.append("credential")
        if not _text(_request(c.get("benign_request")).get("url")):
            gaps.append("benign_request.url")
    elif kind == SSRF:
        if not _text(c.get("marker")):
            gaps.append("marker")
        if not _text(_request(c.get("benign_request")).get("url")):
            gaps.append("benign_request.url")
    elif kind in (SQL_ERROR, BLIND_COMMAND) or c.get("signal") in ("union_marker",
                                                                   "boolean_differential"):
        # an error signature, a delay or an extracted row can appear without injection:
        # demand the benign control
        if not _text(_request(c.get("benign_request")).get("url")):
            gaps.append("benign_request.url")
        if not _text(c.get("signal")):
            gaps.append("signal")
    elif kind == HEADERS:
        if not _text(c.get("document")):
            gaps.append("document")
        if not list(c.get("controls") or ()):
            gaps.append("controls")
    elif kind == SESSION:
        if not _text(c.get("cookie")):
            gaps.append("cookie")
        if not list(c.get("missing") or ()):
            gaps.append("missing")
    return gaps


def canonical_document(url: str | None) -> str:
    """One document, one identity: '' and '/' are the same resource."""
    u = _text(url or "")
    if not u:
        return ""
    base, _, query = u.partition("?")
    return (base.rstrip("/") or base) + (("?" + query) if query else "")


def with_param(url: str, param: str, value: str) -> str:
    """Same URL with one query parameter replaced (the negative control's URL)."""
    parts = urlparse(url)
    query = [(k, value if k == param else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if param not in {k for k, _ in query}:
        query.append((param, value))
    return urlunparse(parts._replace(query=urlencode(query)))
