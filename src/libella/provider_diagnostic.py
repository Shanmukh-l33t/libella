"""One bounded chat completion to confirm operator-supplied provider settings."""
import asyncio
import ipaddress
import json
import os
import time
from urllib.parse import urlsplit

import httpx

DEFAULT_URL = "https://api.openai.com/v1"
MAX_REPLY = 64 * 1024

MESSAGES = {
    "connected": "The selected model returned a text response. Structured output and tool support were not tested.",
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
    allowed = {DEFAULT_URL}
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

    model = draft.get("default_model", saved.get("default_model")) or "gpt-4o-mini"
    started = time.monotonic()
    try:
        async with asyncio.timeout(10):
            status = await _complete(base, key, model)
    except (TimeoutError, httpx.TimeoutException):
        status = "timeout"
    except (httpx.HTTPError, ValueError):
        status = "connection_failed"
    return diagnostic_result(status, started)


async def _complete(base: str, key: str, model: str) -> str:
    headers = {"Accept-Encoding": "identity"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    limit_field = "max_completion_tokens" if base == DEFAULT_URL else "max_tokens"
    body = {"model": model, "messages": [{"role": "user", "content": "Reply with OK."}], limit_field: 64}
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
            return "connected"
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    return "protocol_mismatch"
