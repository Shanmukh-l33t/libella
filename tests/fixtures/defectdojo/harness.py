"""Run the vendored upstream DefectDojo Generic JSON parser without Django.

Stubs the handful of model modules the parser imports. This proves the payload passes the
parser's own validation (required fields, key whitelist, value types) and what the parsed
findings carry. It is NOT an API/database import: Django model saves, dedupe and the
importer pipeline are out of scope here.
"""
import importlib.util
import json
import sys
import types
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent


class CharField:
    def __init__(self, max_length=None):
        self.max_length = max_length


class _Field:
    def __init__(self, name, max_length=None):
        self.name, self.max_length = name, max_length


class _Meta:
    # Column widths the parser checks against; only the fields an export can carry.
    WIDTHS = {"unique_id_from_tool": 255, "vuln_id_from_tool": 255, "severity": 20,
              "component_name": 200, "component_version": 100, "file_path": 500,
              "service": 200, "param": 200, "payload": 5000, "references": 5000,
              "mitigation": 5000, "impact": 5000, "steps_to_reproduce": 5000}

    def get_fields(self):
        return [_Field(name, width) for name, width in self.WIDTHS.items()]


class Finding:
    # Class-level defaults mirror what an unsaved Django model returns for unset columns.
    cve = None
    cwe = None
    unique_id_from_tool = None
    vuln_id_from_tool = None
    file_path = None
    component_name = None
    component_version = None
    sast_source_object = None
    sast_sink_object = None
    sast_source_file_path = None
    line = None
    sast_source_line = None

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.unsaved_locations = []
        self.unsaved_endpoints = []
        self.unsaved_files = []
        self.unsaved_tags = []
        self.unsaved_vulnerability_ids = []
        self.unsaved_cwes = []

    _meta = _Meta()


class Endpoint:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    @classmethod
    def from_uri(cls, uri):
        if not urlparse(uri).hostname:
            raise ValueError(f"invalid endpoint: {uri}")
        return cls(url=uri)


class LocationData:
    @classmethod
    def url(cls, **kwargs):
        return {"kind": "url", **kwargs}

    @classmethod
    def dependency(cls, **kwargs):
        return {"kind": "dependency", **kwargs}

    @classmethod
    def code(cls, **kwargs):
        return {"kind": "code", **kwargs}


class ParserTest:
    def __init__(self, name, parser_type, version, description=None, **_):
        self.name, self.type, self.version = name, parser_type, version
        self.description = description
        self.findings = []


def _install_stubs():
    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        sys.modules[name] = m
        return m

    for pkg in ("dojo", "dojo.tools", "dojo.finding", "dojo.location",
                "django", "django.core", "django.core.files", "django.db"):
        mod(pkg)
    mod("django.core.files.base", ContentFile=lambda data: data)
    mod("django.db.models", CharField=CharField)
    mod("dojo.models", Endpoint=Endpoint, FileUpload=lambda **kw: kw, Finding=Finding)
    mod("dojo.finding.cwe", cwe_number=lambda v: int("".join(c for c in str(v) if c.isdigit())))
    mod("dojo.location.feature", locations_enabled=lambda: False)
    mod("dojo.tools.locations", LocationData=LocationData)
    mod("dojo.tools.parser_test", ParserTest=ParserTest)

    def mark(items):
        for item in items:
            item.ambiguous_when_repeated = True
        return items

    mod("dojo.tools.utils", mark_unique_ids_ambiguous_when_repeated=mark)
    try:
        import packageurl  # noqa: F401
    except ImportError:
        class PackageURL:
            @classmethod
            def from_string(cls, value):
                raise ValueError("stub: package URLs are not part of this export")

        mod("packageurl", PackageURL=PackageURL)
    try:
        import dateutil  # noqa: F401
        import dateutil.parser  # noqa: F401
    except ImportError:
        from datetime import datetime

        parser = types.ModuleType("dateutil.parser")
        parser.parse = lambda v: datetime.fromisoformat(v) if isinstance(v, str) else v
        mod("dateutil", parser=parser)
        sys.modules["dateutil.parser"] = parser


def _load_parser():
    _install_stubs()
    spec = importlib.util.spec_from_file_location("dojo_generic_json_parser",
                                                  HERE / "json_parser.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.GenericJSONParser()


def parse_generic_json(payload: dict) -> list:
    """Parse a Generic Findings JSON document exactly as the upstream parser would.

    Raises ValueError with the parser's message when the document is rejected.
    """
    return _load_parser()._get_test_json(json.loads(json.dumps(payload))).findings
