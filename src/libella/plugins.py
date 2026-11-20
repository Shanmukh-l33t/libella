"""Plugin framework: manifests, typed tool plugins, exporter plugins.

A plugin is a directory holding ``manifest.json`` plus a python module::

    {"name": "whoisx", "version": "1.0.0", "type": "tool",
     "contract": {"category": "recon", "description": "...",
                  "params": {"target": {"type": "string"}}, "required": ["target"]},
     "entrypoint": "plugin.py:run"}

Tool plugins become ordinary ToolSpecs, so they run through ToolRunner and get
the same scope gate, argv validation, output cap and audit row as built-ins.
The plugin body executes in a separate ``python -I`` process with only the
typed parameters on argv: a manifest can never choose the executable, an argv
element or a shell.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

from .scope import CATEGORIES
from .tools import Registry, ToolSpec

MANIFEST_KEYS = {"name", "version", "type", "contract", "entrypoint"}
TOOL_CONTRACT_KEYS = {
    "description", "category", "params", "required", "read_only",
    "network_effect", "destructive", "timeout_s", "target_param",
}
EXPORTER_CONTRACT_KEYS = {"description", "formats"}
# Any of these in a manifest is an attempt to pick the process or its argv.
FORBIDDEN_KEYS = {"command", "cmd", "shell", "argv", "args", "binary", "handler",
                  "exec", "code", "script", "additional_args", "executable"}
PARAM_TYPES = {"string", "integer", "number", "boolean", "array", "object"}
PARAM_KEYS = {"type", "enum", "minimum", "maximum", "maxLength", "pattern",
              "items", "description"}
PLUGIN_TYPES = {"tool", "exporter", "agent"}
NAME_RE = re.compile(r"[a-z][a-z0-9_]{2,40}")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")

# Launched with -I (isolated: no PYTHONPATH/user-site hijack) and the module
# path + params as argv. Constant string: nothing from a manifest reaches it.
_BOOTSTRAP = (
    "import importlib.util,json,sys\n"
    "path,func,raw=sys.argv[1:4]\n"
    "spec=importlib.util.spec_from_file_location('libella_plugin',path)\n"
    "mod=importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(mod)\n"
    "sys.stdout.write(json.dumps(getattr(mod,func)(json.loads(raw)),default=str))\n"
)


class PluginError(ValueError):
    pass


def _closed(obj, allowed: set[str], where: str):
    if not isinstance(obj, dict):
        raise PluginError(f"{where} must be an object")
    unknown = set(obj) - allowed
    if unknown & FORBIDDEN_KEYS:
        raise PluginError(f"{where} requests raw execution control: {sorted(unknown & FORBIDDEN_KEYS)}")
    if unknown:
        raise PluginError(f"{where} has unsupported keys: {sorted(unknown)}")


def _entrypoint(value) -> tuple[str, str]:
    if not isinstance(value, str) or value.count(":") != 1:
        raise PluginError("entrypoint must be 'file.py:function'")
    rel, func = value.split(":")
    path = Path(rel)
    if path.suffix != ".py" or path.is_absolute() or ".." in path.parts:
        raise PluginError("entrypoint must be a relative .py path inside the plugin")
    if not IDENT_RE.fullmatch(func):
        raise PluginError("entrypoint function must be an identifier")
    return rel, func


def validate_manifest(manifest: dict) -> dict:
    """Normalize + validate. Raises PluginError; no I/O, no imports."""
    _closed(manifest, MANIFEST_KEYS, "manifest")
    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise PluginError("name must match [a-z][a-z0-9_]{2,40}")
    version = manifest.get("version")
    if not isinstance(version, str) or not version.strip():
        raise PluginError("version must be a non-empty string")
    kind = manifest.get("type")
    if kind not in PLUGIN_TYPES:
        raise PluginError(f"type must be one of {sorted(PLUGIN_TYPES)}")
    rel, func = _entrypoint(manifest.get("entrypoint"))
    contract = manifest.get("contract")
    allowed = TOOL_CONTRACT_KEYS if kind == "tool" else EXPORTER_CONTRACT_KEYS
    _closed(contract, allowed, "contract")
    if not isinstance(contract.get("description"), str) or not contract["description"].strip():
        raise PluginError("contract.description required")
    out = {"name": name, "version": version, "type": kind, "entrypoint": (rel, func),
           "description": contract["description"][:500]}
    if kind == "tool":
        out.update(_tool_contract(contract))
    return out


def _tool_contract(contract: dict) -> dict:
    category = contract.get("category")
    if category not in CATEGORIES:
        raise PluginError(f"category must be one of {sorted(CATEGORIES)}")
    params = contract.get("params") or {}
    if not isinstance(params, dict):
        raise PluginError("contract.params must be an object")
    for key, schema in params.items():
        if not IDENT_RE.fullmatch(str(key)):
            raise PluginError(f"invalid parameter name {key!r}")
        if key in FORBIDDEN_KEYS:
            raise PluginError(f"parameter {key!r} requests raw execution control")
        _closed(schema, PARAM_KEYS, f"param {key}")
        if schema.get("type") not in PARAM_TYPES:
            raise PluginError(f"param {key} type must be one of {sorted(PARAM_TYPES)}")
    required = contract.get("required") or []
    if not isinstance(required, list) or not set(required) <= set(params):
        raise PluginError("required must list declared parameters")
    target_param = contract.get("target_param", "target")
    if not isinstance(target_param, str) or (target_param != "target" and target_param not in params):
        raise PluginError("target_param must name a declared parameter")
    timeout = contract.get("timeout_s", 120)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 600:
        raise PluginError("timeout_s must be an int in 1..600")
    return {
        "category": category,
        "params": params,
        "required": required,
        "read_only": contract.get("read_only", True) is True,
        "network_effect": contract.get("network_effect", True) is True,
        "destructive": contract.get("destructive", False) is True,
        "timeout_s": timeout,
        "target_param": target_param,
    }


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(f"libella_plugin_{name}", path)
    if spec is None or spec.loader is None:
        raise PluginError(f"cannot load plugin module {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _plugin_handler(module_path: Path, func: str):
    def handler(params: dict, decision) -> list[str]:
        return [sys.executable, "-I", "-c", _BOOTSTRAP, str(module_path), func,
                json.dumps(params, default=str)]
    return handler


class PluginHost:
    """Discovers plugins under ``directory``, one subdirectory per plugin."""

    def __init__(self, directory: str | Path, registry: Registry):
        self.directory = Path(directory)
        self.registry = registry
        self.exporters: dict[str, object] = {}
        self.loaded: list[dict] = []
        self.errors: list[dict] = []
        self._owned: set[str] = set()

    def load(self) -> dict:
        for name in list(self._owned):  # reload re-registers what this host owns
            self.registry.tools.pop(name, None)
        self._owned.clear()
        self.exporters.clear()
        self.loaded.clear()
        self.errors.clear()
        self.directory.mkdir(parents=True, exist_ok=True)
        for manifest_path in sorted(self.directory.glob("*/manifest.json")):
            self._load_one(manifest_path)
        return self.status()

    def _load_one(self, manifest_path: Path):
        slug = manifest_path.parent.name
        try:
            manifest = validate_manifest(json.loads(manifest_path.read_text()))
            module_path = (manifest_path.parent / manifest["entrypoint"][0]).resolve()
            if not module_path.is_file() or not module_path.is_relative_to(
                    manifest_path.parent.resolve()):
                raise PluginError("entrypoint file does not exist inside the plugin")
            func = manifest["entrypoint"][1]
            if manifest["type"] == "tool":
                # Deliberately NOT imported here: plugin code must not execute
                # in the platform process. A bad entrypoint surfaces at call time.
                self._add_tool(manifest, module_path, func)
            elif manifest["type"] == "exporter":
                mod = _load_module(module_path, manifest["name"])
                fn = getattr(mod, func, None)
                if not callable(fn):
                    raise PluginError(f"entrypoint {func} is not callable")
                self.exporters[manifest["name"]] = fn
                self.loaded.append(self._entry(manifest, "loaded"))
            else:
                # agent plugins are a reserved manifest type; not wired yet.
                self.loaded.append(self._entry(manifest, "unsupported"))
        except (PluginError, OSError, ValueError, ImportError, AttributeError) as e:
            self.errors.append({"plugin": slug, "error": str(e)[:300]})

    def _add_tool(self, manifest: dict, module_path: Path, func: str):
        name = f"plugin_{manifest['name']}"
        spec = ToolSpec(
            name=name,
            description=manifest["description"],
            category=manifest["category"],
            params=manifest["params"],
            required=manifest["required"],
            read_only=manifest["read_only"],
            network_effect=manifest["network_effect"],
            destructive=manifest["destructive"],
            timeout_s=manifest["timeout_s"],
            target_param=manifest["target_param"],
            handler=_plugin_handler(module_path, func),
        )
        self.registry.register(spec)
        self._owned.add(name)
        self.loaded.append(self._entry(manifest, "loaded", tool=name))

    @staticmethod
    def _entry(manifest: dict, status: str, tool: str | None = None) -> dict:
        return {"name": manifest["name"], "version": manifest["version"],
                "type": manifest["type"], "status": status, "tool": tool}

    def status(self) -> dict:
        tools = [t for t in self.registry.available() if t["name"] in self._owned]
        return {"directory": str(self.directory), "loaded": self.loaded,
                "errors": self.errors, "exporters": sorted(self.exporters),
                "available": tools}


def load_plugins(directory: str | Path, registry: Registry) -> PluginHost:
    host = PluginHost(directory, registry)
    host.load()
    return host
