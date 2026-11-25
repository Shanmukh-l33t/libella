"""One bounded chat completion to confirm operator-supplied provider settings."""
import asyncio
import ipaddress
import json
import os
import time
from urllib.parse import urlsplit

import httpx

DEFAULT_URL = "https://api.openai.com/v1"
# The other first-class protocol. An operator may legitimately test a Claude endpoint, so
# it is allowlisted by default rather than requiring an environment entry.
ANTHROPIC_URL = "https://api.anthropic.com/v1"
MAX_REPLY = 64 * 1024

MESSAGES = {
    "connected": "The selected model returned the JSON object agents need, so agent turns can run.",
    "text_only": "The model replied, but not with parseable JSON. Chat works; agents need structured output, so they may fail on this endpoint.",
    "invalid_url": "Use an HTTPS base URL without credentials, a query, or a fragment. Plain HTTP is allowed only for a loopback IP.",
    "endpoint_not_allowed": "Ask the server administrator to add this exact base URL to LIBELLA_PROVIDER_TEST_URLS.",
    "key_required": "Enter a provider API key. A saved key is only reused with its original base URL.",
    "invalid_credentials": "The provider rejected the credentials. Check the key or replace it if it expired.",
    "access_denied": "The provider denied access. Check the key’s project, permissions, and model access.",
    "model_unavailable": "The provider reports that this model does not exist or is not accessible to this key.",
    "insufficient_quota": "The provider reported a billing or quota problem. Check available credits and limits.",
    "rate_limited": "The provider rate-limited the request. Wait before trying again.",
    "provider_unavailable": "The provider returned a server error. Check its status before trying again.",
    "redirect_refused": "The provider redirected the request. Enter the final API base URL instead.",
    "protocol_mismatch": "No compatible text completion was returned. Check the base URL and model; some models do not support this small test.",
    "response_too_large": "The provider returned more data than the connection test accepts.",
    "request_rejected": "The provider rejected the request. Check the base URL, exact model ID, and Chat Completions support.",
    "timeout": "The provider did not finish in 10 seconds. Check service health and connectivity.",
    "connection_failed": "Could not reach the provider. Check DNS, TLS certificates, and whether the service is running.",
    "busy": "Another provider test is running. Wait for it to finish.",
}


# one prompt for both protocols: the reply proves the endpoint can do what an agent needs
PROBE_PROMPT = 'Reply with exactly this JSON object and nothing else: {"ok": true}'


def _is_json_object(text: str) -> bool:
    """True when the reply carries a JSON object, tolerating a fenced code block."""
    body = text.strip()
    if body.startswith("```"):
        body = body.split("```")[1] if body.count("```") >= 2 else body
        body = body.split("\n", 1)[-1] if body.lower().startswith(("json", "javascript")) else body
    try:
        return isinstance(json.loads(body.strip()), dict)
    except (ValueError, RecursionError):
        return False


def normalize_base(value: str) -> str:
    """Canonical provider base URL; ValueError unless HTTPS or literal-loopback HTTP."""
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 or c in "\\?#" for c in value):
        raise ValueError
    p = urlsplit(value)
    if not p.hostname or p.port == 0 or p.username is not None or p.password is not None:
        raise ValueError
    if p.scheme != "https" and not (p.scheme == "http" and ipaddress.ip_address(p.hostname).is_loopback):
        raise ValueError
    try:
        return str(httpx.URL(value.rstrip("/")))
    except httpx.InvalidURL:
        raise ValueError from None


def same_base(a: str | None, b: str | None) -> bool:
    a, b = a or DEFAULT_URL, b or DEFAULT_URL
    try:
        return normalize_base(a) == normalize_base(b)
    except ValueError:
        return a.rstrip("/") == b.rstrip("/")


def diagnostic_result(status: str, started: float | None = None) -> dict:
    return {"status": status, "message": MESSAGES[status],
            "latency_ms": round((time.monotonic() - started) * 1000) if started is not None else None}


async def test_connection(saved: dict, draft: dict) -> dict:
    try:
        base = normalize_base(draft.get("base_url", saved.get("base_url")) or DEFAULT_URL)
    except ValueError:
        return diagnostic_result("invalid_url")
    allowed = {DEFAULT_URL, ANTHROPIC_URL}
    for value in os.environ.get("LIBELLA_PROVIDER_TEST_URLS", "").split(","):
        if value.strip():
            try:
                allowed.add(normalize_base(value.strip()))
            except ValueError:
                continue
    if base not in allowed:
        return diagnostic_result("endpoint_not_allowed")

    key = draft.get("api_key") or ""
    key = key.strip()
    if not key and same_base(base, saved.get("base_url")):
        key = saved.get("api_key") or ""
    if base == DEFAULT_URL and not key:
        return diagnostic_result("key_required")
    if not isinstance(key, str) or not key.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in key):
        return diagnostic_result("invalid_credentials")

    style = (draft.get("api_style") or saved.get("api_style") or "").strip().lower()
    default_model = "claude-3-5-haiku-latest" if base == ANTHROPIC_URL else "gpt-4o-mini"
    model = draft.get("default_model", saved.get("default_model")) or default_model
    started = time.monotonic()
    try:
        async with asyncio.timeout(10):
            if style in ("anthropic", "messages") or (not style and base == ANTHROPIC_URL):
                status = await _complete_anthropic(base, key, model)
            else:
                status = await _complete(base, key, model)
    except (TimeoutError, httpx.TimeoutException):
        status = "timeout"
    except (httpx.HTTPError, ValueError):
        status = "connection_failed"
    return diagnostic_result(status, started)


async def list_models(saved: dict, draft: dict) -> dict:
    """Models the endpoint advertises, so an operator picks one instead of typing it.

    Same allowlist and TLS rules as the connection test: this sends the operator's key, so it
    must not be usable against an arbitrary host. Both protocols expose a models listing
    (OpenAI `GET /models`, Anthropic `GET /models`), and the reply shapes differ only in the
    field that carries the id, so one parser covers both.
    """
    try:
        base = normalize_base(draft.get("base_url", saved.get("base_url")) or DEFAULT_URL)
    except ValueError:
        return {"status": "invalid_url", "message": MESSAGES["invalid_url"], "models": []}
    allowed = {DEFAULT_URL, ANTHROPIC_URL}
    for value in os.environ.get("LIBELLA_PROVIDER_TEST_URLS", "").split(","):
        if value.strip():
            try:
                allowed.add(normalize_base(value.strip()))
            except ValueError:
                continue
    if base not in allowed:
        return {"status": "endpoint_not_allowed", "message": MESSAGES["endpoint_not_allowed"],
                "models": []}
    key = (draft.get("api_key") or "").strip()
    if not key and same_base(base, saved.get("base_url")):
        key = saved.get("api_key") or ""
    if not key:
        return {"status": "key_required", "message": MESSAGES["key_required"], "models": []}
    style = (draft.get("api_style") or saved.get("api_style") or "").strip().lower()
    anthropic = style in ("anthropic", "messages") or (not style and base == ANTHROPIC_URL)
    headers = {"Accept-Encoding": "identity"}
    if anthropic:
        headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
    else:
        headers["Authorization"] = f"Bearer {key}"
    started = time.monotonic()
    try:
        async with asyncio.timeout(10):
            async with httpx.AsyncClient(timeout=10, trust_env=False,
                                         follow_redirects=False) as client:
                async with client.stream("GET", f"{base}/models", headers=headers) as response:
                    if response.status_code in (401, 403):
                        return {"status": "invalid_credentials",
                                "message": MESSAGES["invalid_credentials"], "models": []}
                    if response.status_code >= 500:
                        return {"status": "provider_unavailable",
                                "message": MESSAGES["provider_unavailable"], "models": []}
                    if response.status_code != 200:
                        return {"status": "request_rejected",
                                "message": MESSAGES["request_rejected"], "models": []}
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(raw) + len(chunk) > MAX_REPLY:
                            return {"status": "response_too_large",
                                    "message": MESSAGES["response_too_large"], "models": []}
                        raw.extend(chunk)
    except (TimeoutError, httpx.TimeoutException):
        return {"status": "timeout", "message": MESSAGES["timeout"], "models": []}
    except (httpx.HTTPError, ValueError):
        return {"status": "connection_failed", "message": MESSAGES["connection_failed"],
                "models": []}
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        return {"status": "protocol_mismatch", "message": MESSAGES["protocol_mismatch"],
                "models": []}
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {"status": "protocol_mismatch", "message": MESSAGES["protocol_mismatch"],
                "models": []}
    models = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        # OpenAI: {"id": "gpt-4o"}; Anthropic: {"id": "claude-3-5-haiku", "display_name": ...}
        mid = row.get("id") or row.get("name")
        if isinstance(mid, str) and mid.strip():
            models.append({"id": mid.strip(), "label": row.get("display_name") or mid.strip()})
    models.sort(key=lambda m: m["id"])
    return {"status": "connected", "message": f"{len(models)} model(s) available",
            "models": models, "base_url": base,
            "latency_ms": round((time.monotonic() - started) * 1000)}


async def _complete_anthropic(base: str, key: str, model: str) -> str:
    """One Messages API round trip. The wire format differs from Chat Completions.

    Testing a Claude endpoint with the OpenAI shape would report `request_rejected` for a
    perfectly good key and model, which reads as an operator error when it is ours.
    """
    if not key:
        return "key_required"
    headers = {"anthropic-version": "2023-06-01", "content-type": "application/json",
               "x-api-key": key}
    body = {"model": model, "max_tokens": 64,
            "messages": [{"role": "user", "content": PROBE_PROMPT}]}
    async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as client:
        async with client.stream("POST", f"{base}/messages", headers=headers, json=body) as response:
            status = response.status_code
            if 300 <= status < 400:
                return "redirect_refused"
            if status == 401:
                return "invalid_credentials"
            if status == 403:
                return "access_denied"
            if status >= 500:
                return "provider_unavailable"
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                if len(raw) + len(chunk) > MAX_REPLY:
                    return "response_too_large"
                raw.extend(chunk)
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        payload = None
    error = payload.get("error") if isinstance(payload, dict) else None
    code = (error or {}).get("type") if isinstance(error, dict) else None
    if code == "rate_limit_error":
        return "rate_limited"
    if code == "not_found_error":
        return "model_unavailable"
    if status == 429:
        return "rate_limited"
    if status != 200:
        return "request_rejected"
    blocks = payload.get("content") if isinstance(payload, dict) else None
    if isinstance(blocks, list):
        text = "".join(b.get("text", "") for b in blocks
                       if isinstance(b, dict) and b.get("type") == "text")
        if text.strip():
            return "connected" if _is_json_object(text) else "text_only"
    return "protocol_mismatch"


async def _complete(base: str, key: str, model: str) -> str:
    headers = {"Accept-Encoding": "identity"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    limit_field = "max_completion_tokens" if base == DEFAULT_URL else "max_tokens"
    body = {"model": model, "messages": [{"role": "user", "content": PROBE_PROMPT}], limit_field: 64}
    async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as client:
        async with client.stream("POST", f"{base}/chat/completions", headers=headers, json=body) as response:
            status = response.status_code
            if 300 <= status < 400:
                return "redirect_refused"
            if status == 401:
                return "invalid_credentials"
            if status == 403:
                return "access_denied"
            if status >= 500:
                return "provider_unavailable"
            raw = bytearray()
            # shortcut: cap applies to decoded bytes, so one compressed chunk can briefly
            # expand in memory; acceptable for admin-allowlisted endpoints only.
            async for chunk in response.aiter_bytes():
                if len(raw) + len(chunk) > MAX_REPLY:
                    return "response_too_large"
                raw.extend(chunk)
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        payload = None
    error = payload.get("error") if isinstance(payload, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    if code in ("insufficient_quota", "billing_hard_limit_reached"):
        return "insufficient_quota"
    if code in ("model_not_found", "invalid_model"):
        return "model_unavailable"
    if status == 429:
        return "rate_limited"
    if status != 200:
        return "request_rejected"
    if not isinstance(payload, dict):
        return "protocol_mismatch"
    try:
        choice = payload["choices"][0]
        message = choice["message"]
        content = message.get("content")
        if (not message.get("refusal") and choice.get("finish_reason") != "content_filter"
                and isinstance(content, str) and content.strip()):
            # A text reply is not enough: every agent turn parses a JSON object, so a model
            # that cannot produce one must not be reported as fully working.
            return "connected" if _is_json_object(content) else "text_only"
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    return "protocol_mismatch"
