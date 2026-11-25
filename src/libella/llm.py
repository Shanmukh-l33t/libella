"""LLM abstraction: OpenAI-compatible endpoints, per-role models, fallback,
structured outputs, token/cost accounting. The LLM proposes typed deltas;
deterministic code owns state writes and policy.
"""
import json
import time
from urllib.parse import urlsplit

import httpx

from .budget import BudgetLedger
from .db import DB, new_id

# USD per 1M tokens (input, output). Estimates; configurable via settings.
DEFAULT_PRICING = {
    "gpt-4o": (2.5, 10.0), "gpt-4o-mini": (0.15, 0.6),
    "gpt-4.1": (2.0, 8.0), "gpt-4.1-mini": (0.4, 1.6),
    "claude-sonnet-4-5": (3.0, 15.0), "claude-haiku-4-5": (1.0, 5.0),
    "deepseek-chat": (0.27, 1.1), "default": (1.0, 3.0),
}
# A reservation must not under-estimate: 3 chars/token is below prose (~4) and
# JSON/code (~2.5) alike, and the call has no max_tokens, so assume a full reply.
CHARS_PER_TOKEN = 3
MAX_OUTPUT_TOKENS = 1024


class LLMError(Exception):
    pass


class BudgetExceeded(LLMError):
    """The engagement ceiling refused the reservation: no call was made."""


class LLM:
    def __init__(self, db: DB, config: dict):
        """config: {base_url, api_key, models: {role: model}, fallback: [models],
        pricing: {model: [in, out]}, timeout_s}"""
        self.db = db
        self.config = config or {}
        self.base_url = (config.get("base_url") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = config.get("api_key") or ""
        self.models = config.get("models", {})
        self.default_model = config.get("default_model") or "gpt-4o-mini"
        self.fallback = config.get("fallback", [])
        self.pricing = {**DEFAULT_PRICING, **config.get("pricing", {})}
        self.timeout = config.get("timeout_s", 120)
        self.ledger = BudgetLedger(db) if db is not None else None

    def model_for(self, role: str) -> str:
        return self.models.get(role, self.default_model)

    def _price(self, model: str) -> tuple[float, float]:
        # longest match wins, so "gpt-4o-mini" is not priced as "gpt-4o"
        keys = [k for k in self.pricing if k != "default" and k in model]
        return tuple(self.pricing[max(keys, key=len)] if keys else self.pricing["default"])

    def estimate(self, system: str, user: str, model: str | None = None,
                 max_output_tokens: int = MAX_OUTPUT_TOKENS) -> float:
        """Conservative USD estimate for one call: the amount to reserve before it."""
        pin, pout = self._price(model or self.default_model)
        prompt_tokens = (len(system) + len(user)) / CHARS_PER_TOKEN + 64
        return (prompt_tokens * pin + max_output_tokens * pout) / 1_000_000

    def _max_usd(self, engagement_id: str) -> float:
        row = self.db.one("SELECT budgets_json FROM engagements WHERE id=?", (engagement_id,))
        try:
            return float(json.loads((row or {}).get("budgets_json") or "{}").get("max_usd", 10.0))
        except (TypeError, ValueError):
            return 10.0  # corrupt ceilings never widen

    def complete(self, role: str, system: str, user: str, engagement_id: str | None = None,
                 json_schema: dict | None = None, temperature: float = 0.1) -> dict:
        """One structured completion. Returns {content, parsed, usage}.
        Retries once on malformed JSON with a repair prompt; falls back across models."""
        models = [self.model_for(role)] + [m for m in self.fallback if m != self.model_for(role)]
        last_err = None
        for model in models:
            try:
                return self._call(model, role, system, user, engagement_id, json_schema, temperature)
            except BudgetExceeded:
                raise  # another model cannot help: the ceiling is the engagement's
            except LLMError as e:
                last_err = e
                continue
        raise LLMError(f"all models failed: {last_err}")

    def _call(self, model, role, system, user, engagement_id, json_schema, temperature) -> dict:
        """One provider call: headroom is reserved before it and settled after it.

        A refusal raises BudgetExceeded before any HTTP request is made; every
        failure path releases the reservation, so a dead provider costs nothing.
        """
        reservation = None
        if engagement_id is not None and self.ledger is not None:
            amount = self.estimate(system, user, model)
            reservation = self.ledger.reserve(engagement_id, None, amount,
                                              self._max_usd(engagement_id))
            if reservation is None:
                raise BudgetExceeded(
                    f"engagement budget refused a model call: reserving ~{amount:.4f} USD on top of "
                    f"{self.ledger.committed(engagement_id):.4f} USD committed would pass the "
                    f"{self._max_usd(engagement_id):.4f} USD ceiling")
        try:
            return self._provider_call(model, role, system, user, engagement_id, json_schema,
                                       temperature, reservation)
        except BaseException:
            if reservation is not None and self.ledger is not None:
                self.ledger.settle(reservation, 0.0)  # no usage known: give the headroom back
            raise

    def protocol(self) -> str:
        """Which wire protocol this endpoint speaks: "anthropic" or "openai".

        An operator may point Libella at either kind of API, so the choice must be explicit
        rather than guessed from the URL: a compatible proxy can expose Claude models behind
        an OpenAI-shaped path and vice versa. `api_style` in the settings wins; otherwise a
        host of api.anthropic.com implies the Messages API.
        """
        style = (self.config.get("api_style") or "").strip().lower()
        if style in ("anthropic", "messages"):
            return "anthropic"
        if style in ("openai", "chat"):
            return "openai"
        host = urlsplit(self.base_url).hostname or ""
        return "anthropic" if "anthropic" in host else "openai"

    def _provider_call(self, model, role, system, user, engagement_id, json_schema, temperature,
                       reservation) -> dict:
        if self.protocol() == "anthropic":
            return self._anthropic_call(model, role, system, user, engagement_id, json_schema,
                                        temperature, reservation)
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        body = {"model": model, "messages": messages, "temperature": temperature}
        if json_schema:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            with httpx.Client(timeout=self.timeout, trust_env=False) as client:
                resp = client.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
        except httpx.HTTPError as e:
            raise LLMError(f"transport: {e}") from e
        if resp.status_code == 429 or resp.status_code >= 500:
            raise LLMError(f"provider {resp.status_code}: {resp.text[:200]}")
        if resp.status_code != 200:
            raise LLMError(f"provider {resp.status_code}: {resp.text[:300]}")
        try:
            data = resp.json()
            choice = data["choices"][0]
            msg = choice["message"]
            content = msg.get("content") or ""
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
            raise LLMError("provider returned an unexpected response shape") from e
        if choice.get("finish_reason") == "content_filter" or msg.get("refusal"):
            raise LLMError("provider refusal")
        usage = data.get("usage") or {}
        it, ot = usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
        pin, pout = self._price(model)
        cost = (it * pin + ot * pout) / 1_000_000
        self.db.execute(
            "INSERT INTO llm_usage(id, engagement_id, role, model, input_tokens, output_tokens, cost_usd, created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (new_id("lu"), engagement_id, role, model, it, ot, round(cost, 6), time.time()),
        )
        if reservation is not None and self.ledger is not None:
            # settle to what the provider says it used; llm_usage above stays the
            # reporting record, the ledger is what the ceiling is enforced on
            self.ledger.settle(reservation, cost)
        parsed = None
        if json_schema:
            parsed = self._parse_json(content)
            if parsed is None:
                # one bounded repair attempt
                repair = ("Your previous reply was not valid JSON. Reply again with ONLY a valid "
                          "JSON object matching the requested schema. Previous reply:\n" + content[:2000])
                body["messages"] = messages + [{"role": "assistant", "content": content},
                                               {"role": "user", "content": repair}]
                try:
                    with httpx.Client(timeout=self.timeout, trust_env=False) as client:
                        resp2 = client.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
                    if resp2.status_code == 200:
                        c2 = resp2.json().get("choices", [{}])[0].get("message", {}).get("content", "")
                        parsed = self._parse_json(c2)
                        content = c2 or content
                except httpx.HTTPError:
                    pass
            if parsed is None:
                raise LLMError("malformed structured output after repair")
        return {"content": content, "parsed": parsed,
                "usage": {"input_tokens": it, "output_tokens": ot, "cost_usd": round(cost, 6),
                          "model": model}}

    def _anthropic_call(self, model, role, system, user, engagement_id, json_schema,
                        temperature, reservation) -> dict:
        """One Messages API call. Same accounting and refusal semantics as the OpenAI path.

        The two APIs differ in the parts an agent actually depends on: the auth header, the
        system prompt being a top-level field rather than a message, `max_tokens` being
        REQUIRED, and usage being `input_tokens`/`output_tokens`. Getting any of these wrong
        fails every agent turn with a provider 400, so they are translated explicitly.
        """
        body = {"model": model, "max_tokens": int(self.config.get("max_tokens") or 4096),
                "temperature": temperature,
                "system": system,
                "messages": [{"role": "user", "content": user}]}
        if json_schema:
            # a JSON-object nudge, not a schema: the Messages API has no response_format
            body["system"] = system + "\nReply with ONE JSON object and nothing else."
        headers = {"anthropic-version": "2023-06-01", "content-type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        try:
            with httpx.Client(timeout=self.timeout, trust_env=False) as client:
                resp = client.post(f"{self.base_url}/messages", json=body, headers=headers)
        except httpx.HTTPError as e:
            raise LLMError(f"transport: {e}") from e
        if resp.status_code == 429 or resp.status_code >= 500:
            raise LLMError(f"provider {resp.status_code}: {resp.text[:200]}")
        if resp.status_code != 200:
            raise LLMError(f"provider {resp.status_code}: {resp.text[:300]}")
        try:
            data = resp.json()
            blocks = data.get("content") or []
            content = "".join(b.get("text", "") for b in blocks
                              if isinstance(b, dict) and b.get("type") == "text")
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise LLMError("provider returned an unexpected response shape") from e
        if data.get("stop_reason") == "refusal":
            raise LLMError("provider refusal")
        usage = data.get("usage") or {}
        it = usage.get("input_tokens", 0)
        ot = usage.get("output_tokens", 0)
        pin, pout = self._price(model)
        cost = (it * pin + ot * pout) / 1_000_000
        self.db.execute(
            "INSERT INTO llm_usage(id, engagement_id, role, model, input_tokens, output_tokens, "
            "cost_usd, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (new_id("lu"), engagement_id, role, model, it, ot, round(cost, 6), time.time()),
        )
        if reservation is not None and self.ledger is not None:
            self.ledger.settle(reservation, cost)
        parsed = self._parse_json(content) if json_schema else None
        if json_schema and parsed is None:
            raise LLMError("malformed structured output")
        return {"content": content, "parsed": parsed,
                "usage": {"input_tokens": it, "output_tokens": ot,
                          "cost_usd": round(cost, 6), "model": model}}

    @staticmethod
    def _parse_json(content: str):
        content = content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(content[start:end + 1])
                except json.JSONDecodeError:
                    return None
        return None

    def spend(self, engagement_id: str) -> dict:
        row = self.db.one(
            "SELECT COALESCE(SUM(input_tokens),0) it, COALESCE(SUM(output_tokens),0) ot, "
            "COALESCE(SUM(cost_usd),0) cost FROM llm_usage WHERE engagement_id=?",
            (engagement_id,))
        return {"input_tokens": row["it"], "output_tokens": row["ot"], "cost_usd": round(row["cost"], 4)}
