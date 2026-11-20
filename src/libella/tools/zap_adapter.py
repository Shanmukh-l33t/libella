"""OWASP ZAP adapter: typed params -> argv, report parsing, availability.

Two ZAP shapes exist: `zap.sh -cmd -quickurl` (one-shot, used here) and the
daemon + REST API (not used: it needs a long-lived process Libella does not
manage). The quick scan is spider + passive rules only, so the tool stays
read-only; active-scan policies are deliberately absent.

shortcut: the report goes to /dev/stdout and ZAP picks XML when the path has
no extension. A ZAP build that refuses /dev/stdout yields zero observations
(no findings), never a false positive. Upgrade to a temp file + daemon mode if
a target needs HTML/JSON reports or active scanning.
"""
import json
import re
import subprocess
import xml.etree.ElementTree as ET

from . import ToolSpec, resolve_binary

ZAP_NAMES = ("zap.sh", "zap")
RISK_BY_CODE = {"0": "info", "1": "low", "2": "medium", "3": "high"}
RISK_WORDS = ("informational", "info", "low", "medium", "high")


def zap_binary() -> str | None:
    """ZAP installs as zap.sh; some packages also/only ship a `zap` wrapper."""
    for name in ZAP_NAMES:
        p = resolve_binary(name)
        if p:
            return p
    return None


def zap_available() -> bool:
    return zap_binary() is not None


def zap_version(binary: str | None = None, timeout: int = 30) -> str | None:
    """`zap.sh -version` prints e.g. '2.15.0'. None if absent or unparseable."""
    binary = binary or zap_binary()
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "-version"], capture_output=True, timeout=timeout,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "NO_COLOR": "1"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", proc.stdout.decode(errors="replace"))
    return m.group(1) if m else None


def _zap_argv(p: dict, decision) -> list[str]:
    target = p["target"]
    # defense in depth: a url that starts with '-' or carries whitespace would
    # become another ZAP flag/argument, not a target
    if not re.match(r"https?://", target, re.I) or target.startswith("-") \
            or any(c.isspace() for c in target):
        raise ValueError("target must be an absolute http(s) url")
    depth = "5" if p.get("policy") == "deep" else "2"  # spider.maxDepth (real ZAP option)
    return [
        zap_binary() or "zap.sh", "-cmd", "-silent",
        "-config", "api.disablekey=true",
        "-config", "connection.timeoutInSecs=15",
        "-config", f"spider.maxDepth={depth}",
        "-quickurl", target,
        "-quickout", "/dev/stdout",
    ]


def _risk(code, desc) -> str:
    word = RISK_BY_CODE.get(str(code).strip())
    if word:
        return word
    head = (desc or "").split("(")[0].strip().lower()
    return "info" if head in ("informational",) else (head if head in RISK_WORDS else "info")


def _cwe(value) -> str | None:
    v = str(value or "").strip()
    return f"CWE-{v}" if v.isdigit() and v not in ("0", "-1") else None


def _obs(alert: dict, inst: dict, site: str) -> dict:
    """One normalized observation per (alert, instance)."""
    return {
        "alert": alert["alert"], "risk": alert["risk"], "confidence": alert["confidence"],
        "url": inst.get("uri") or site, "method": inst.get("method"),
        "param": inst.get("param"), "evidence": inst.get("evidence"),
        "cwe": _cwe(inst.get("cweid")), "plugin_id": alert["plugin_id"],
        "source": "zap",
    }


def _parse_json(text: str) -> list[dict]:
    data = None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        cut = text.rfind("}")
        if cut > 0:
            try:
                data = json.loads(text[:cut + 1])
            except json.JSONDecodeError:
                return []
    if not isinstance(data, dict):
        return []
    out = []
    for site in data.get("site") or []:
        for a in site.get("alerts") or []:
            alert = {"alert": a.get("alert") or a.get("name"),
                     "risk": _risk(a.get("riskcode"), a.get("riskdesc")),
                     "confidence": a.get("confidencedesc") or a.get("confidence"),
                     "plugin_id": a.get("pluginid")}
            for inst in a.get("instances") or [{}]:
                out.append(_obs(alert, inst, site.get("@name") or site.get("name")))
    return out


def _parse_xml(text: str) -> list[dict]:
    end = text.rfind("</OWASPZAPReport>")
    if end > 0:
        text = text[:end + len("</OWASPZAPReport>")]
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out = []
    for site in root.findall("site"):
        for a in site.findall("./alerts/alertitem"):
            alert = {"alert": (a.findtext("alert") or "").strip(),
                     "risk": _risk(a.findtext("riskcode"), a.findtext("riskdesc")),
                     "confidence": (a.findtext("confidencedesc") or a.findtext("confidence") or "").strip(),
                     "plugin_id": (a.findtext("pluginid") or "").strip()}
            insts = []
            for i in a.findall("./instances/instance"):
                insts.append({k: (i.findtext(k) or "").strip()
                              for k in ("uri", "method", "param", "evidence", "cweid")})
            for inst in insts or [{}]:
                out.append(_obs(alert, inst, site.get("name")))
    return out


def parse_zap_report(text: str) -> list[dict]:
    """Normalize a ZAP XML or JSON report into observations (junk-tolerant)."""
    if not isinstance(text, str):
        return []
    i = text.find("<OWASPZAPReport")
    if i >= 0:
        return _parse_xml(text[i:])
    j = text.find('{"@version"')
    if j < 0:
        j = text.find("{")
    return _parse_json(text[j:]) if j >= 0 else []


ZAP = ToolSpec(
    name="zap_baseline",
    description="OWASP ZAP quick scan of one in-scope URL (spider + passive rules).",
    category="web",
    binary=zap_binary() or "zap.sh",
    timeout_s=900,
    params={
        "target": {"type": "string", "maxLength": 2048},
        "policy": {"type": "string", "enum": ["baseline", "deep"],
                   "description": "baseline = spider depth 2; deep = depth 5"},
    },
    required=["target"],
    handler=_zap_argv,
    target_param="target",
)

SPECS = [ZAP]
