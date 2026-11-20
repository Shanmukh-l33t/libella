"""Typed tool contracts + registry. No free-text argument reaches a shell."""
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolSpec:
    name: str
    description: str
    category: str  # recon | web | api | infra | code
    params: dict  # json-schema properties
    required: list[str]
    read_only: bool = True
    network_effect: bool = True  # touches the target
    destructive: bool = False
    binary: str | None = None  # external binary, if any
    handler: Callable | None = None
    timeout_s: int = 120
    target_param: str = "target"  # the param the adapter actually dials/scans

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "read_only": self.read_only,
            "destructive": self.destructive,
            "parameters": {
                "type": "object",
                "properties": self.params,
                "required": self.required,
                "additionalProperties": False,
            },
        }


def resolve_binary(name: str) -> str | None:
    """Prefer /usr/local/bin (platform-installed scanners) over ambient PATH,
    which may contain unrelated tools with the same name (e.g. python httpx)."""
    import os
    import shutil
    explicit = os.environ.get("LIBELLA_TOOL_PATH")
    if explicit:
        p = os.path.join(explicit, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    p = f"/usr/local/bin/{name}"
    if os.path.isfile(p) and os.access(p, os.X_OK):
        return p
    return shutil.which(name)


class Registry:
    def __init__(self):
        self.tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec):
        if spec.name in self.tools:
            raise ValueError(f"duplicate tool {spec.name}")
        self.tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        if name not in self.tools:
            raise KeyError(f"unknown tool {name}")
        return self.tools[name]

    def available(self) -> list[dict]:
        out = []
        for t in self.tools.values():
            ok = t.binary is None or resolve_binary(t.binary) is not None
            out.append({**t.schema(), "available": ok})
        return out

    def for_category(self, category: str) -> list[ToolSpec]:
        return [t for t in self.tools.values() if t.category == category]


def validate_params(spec: ToolSpec, params: dict) -> dict:
    """Deterministic parameter validation. Reject unknown/missing/mistyped."""
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    unknown = set(params) - set(spec.params)
    if unknown:
        raise ValueError(f"unknown parameters: {sorted(unknown)}")
    missing = [r for r in spec.required if r not in params]
    if missing:
        raise ValueError(f"missing required parameters: {missing}")
    clean = {}
    for k, v in params.items():
        p = spec.params[k]
        t = p.get("type")
        if t == "string":
            if not isinstance(v, str):
                raise ValueError(f"{k} must be a string")
            if "enum" in p and v not in p["enum"]:
                raise ValueError(f"{k} must be one of {p['enum']}")
            if "pattern" in p:
                import re as _re
                if not _re.fullmatch(p["pattern"], v):
                    raise ValueError(f"{k} does not match required pattern")
            if "maxLength" in p and len(v) > p["maxLength"]:
                raise ValueError(f"{k} exceeds maxLength {p['maxLength']}")
            # no shell metacharacters in any string that could reach argv
            if any(c in v for c in (";", "|", "&", "$", "`", "\n", "\r", ">", "<")):
                raise ValueError(f"{k} contains forbidden characters")
        elif t == "integer":
            if not isinstance(v, int) or isinstance(v, bool):
                raise ValueError(f"{k} must be an integer")
            if "minimum" in p and v < p["minimum"]:
                raise ValueError(f"{k} below minimum {p['minimum']}")
            if "maximum" in p and v > p["maximum"]:
                raise ValueError(f"{k} above maximum {p['maximum']}")
        elif t == "number":
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                raise ValueError(f"{k} must be a number")
        elif t == "boolean":
            if not isinstance(v, bool):
                raise ValueError(f"{k} must be a boolean")
        elif t == "array":
            if not isinstance(v, list):
                raise ValueError(f"{k} must be an array")
            it = p.get("items", {})
            for item in v:
                if it.get("type") == "string" and not isinstance(item, str):
                    raise ValueError(f"{k} items must be strings")
                if it.get("type") == "integer" and (not isinstance(item, int) or isinstance(item, bool)):
                    raise ValueError(f"{k} items must be integers")
                if isinstance(item, str) and any(c in item for c in (";", "|", "&", "$", "`", "\n", "\r", ">", "<")):
                    raise ValueError(f"{k} item contains forbidden characters")
        elif t == "object":
            if not isinstance(v, dict):
                raise ValueError(f"{k} must be an object")
        clean[k] = v
    return clean