"""LLM abstraction: OpenAI-compatible endpoints, per-role models, fallback,
structured outputs, token/cost accounting. The LLM proposes typed deltas;
deterministic code owns state writes and policy.
"""
import json
import time

import httpx

from .db import DB, new_id

# USD per 1M tokens (input, output). Estimates; configurable via settings.
DEFAULT_PRICING = {
    "gpt-4o": (2.5, 10.0), "gpt-4o-mini": (0.15, 0.6),
    "gpt-4.1": (2.0, 8.0), "gpt-4.1-mini": (0.4, 1.6),
    "claude-sonnet-4-5": (3.0, 15.0), "claude-haiku-4-5": (1.0, 5.0),
    "deepseek-chat": (0.27, 1.1), "default": (1.0, 3.0),
}


class LLMError(Exception):
    pass


class LLM:
    def __init__(self, db: DB, config: dict):
        """config: {base_url, api_key, models: {role: model}, fallback: [models],
        pricing: {model: [in, out]}, timeout_s}"""
        self.db = db
        self.base_url = (config.get("base_url") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = config.get("api_key") or ""
        self.models = config.get("models", {})
        self.default_model = config.get("default_model") or "gpt-4o-mini"
        self.fallback = config.get("fallback", [])
        self.pricing = {**DEFAULT_PRICING, **config.get("pricing", {})}
        self.timeout = config.get("timeout_s", 120)

    def model_for(self, role: str) -> str:
        return self.models.get(role, self.default_model)

    def _price(self, model: str) -> tuple[float, float]:
        # longest match wins, so "gpt-4o-mini" is not priced as "gpt-4o"
        keys = [k for k in self.pricing if k != "default" and k in model]
        return tuple(self.pricing[max(keys, key=len)] if keys else self.pricing["default"])

    def complete(self, role: str, system: str, user: str, engagement_id: str | None = None,
                 json_schema: dict | None = None, temperature: float = 0.1) -> dict:
        """One structured completion. Returns {content, parsed, usage}.
        Retries once on malformed JSON with a repair prompt; falls back across models."""
        models = [self.model_for(role)] + [m for m in self.fallback if m != self.model_for(role)]
        last_err = None
        for model in models:
            try:
                return self._call(model, role, system, user, engagement_id, json_schema, temperature)
            except LLMError as e:
                last_err = e
                continue
        raise LLMError(f"all models failed: {last_err}")

    def _call(self, model, role, system, user, engagement_id, json_schema, temperature) -> dict:
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
