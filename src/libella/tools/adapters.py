"""External scanner adapters: typed params -> argv built by code.

Each adapter declares closed enums and typed values. No additional_args
escape hatch exists. Parsers produce structured results; raw output is
kept as an evidence artifact by the runner.
"""
import json
import os
import xml.etree.ElementTree as ET

from . import ToolSpec


def _confine_path(value: str, roots: list[str], what: str) -> str:
    """A filesystem parameter may only reference the tool's own data dirs."""
    real = os.path.realpath(os.path.expanduser(value))
    for root in roots:
        r = os.path.realpath(os.path.expanduser(root))
        if real == r or real.startswith(r + os.sep):
            return real
    raise ValueError(f"{what} '{value}' is outside the permitted directories")


def _wordlist_roots() -> list[str]:
    return [os.environ.get("LIBELLA_WORDLIST_DIR", "/usr/share/wordlists")]


def _template_roots() -> list[str]:
    return [os.environ.get("LIBELLA_TEMPLATE_DIR", "~/nuclei-templates"),
            "/usr/share/nuclei-templates"]

# ---- nmap ----

# nmap --max-rate is packets/s, not requests/s: a declared rps ceiling is carried
# over as packets and capped so a high rate_limit_rps cannot make the scan loud.
NMAP_MAX_RATE = 200


def _nmap_argv(p: dict, decision) -> list[str]:
    targets = decision.resolved_ips or [p["target"]]
    argv = ["nmap", "-Pn", "--open", "-oX", "-"]
    if p.get("service_detect"):
        argv += ["-sV", "--version-light"]
    ports = p.get("ports")
    if ports:
        argv += ["-p", ports]
    else:
        argv += ["--top-ports", str(p.get("top_ports", 100))]
    argv += ["-T3", "--max-retries", "1", "--host-timeout", "90s",
             "--max-rate", str(p.get("rate_limit", NMAP_MAX_RATE))]
    argv += targets
    return argv


def parse_nmap_xml(stdout: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        return hosts
    for h in root.findall("host"):
        addr_el = h.find("address")
        addr = addr_el.get("addr") if addr_el is not None else None
        ports = []
        for p in h.findall(".//port"):
            state = p.find("state")
            if state is not None and state.get("state") == "open":
                svc = p.find("service")
                ports.append({
                    "port": int(p.get("portid")), "proto": p.get("protocol"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                })
        hosts.append({"addr": addr, "ports": ports})
    return hosts


NMAP = ToolSpec(
    name="nmap", description="Port/service scan of an in-scope host (validated IPs only).",
    category="infra", binary="nmap", timeout_s=180,
    params={
        "target": {"type": "string", "maxLength": 253},
        "ports": {"type": "string", "maxLength": 100, "description": "e.g. 80,443 or 1-1024"},
        "top_ports": {"type": "integer", "minimum": 1, "maximum": 65535},
        "service_detect": {"type": "boolean"},
        "rate_limit": {"type": "integer", "minimum": 1, "maximum": NMAP_MAX_RATE},
    },
    required=["target"], handler=_nmap_argv, port_param="ports",
)

# ---- nuclei ----

# nuclei's own -rate-limit ceiling; the declared engagement rate is passed through.
NUCLEI_MAX_RATE = 150


def _nuclei_argv(p: dict, decision) -> list[str]:
    target = p["target"]
    argv = ["nuclei", "-u", target, "-jsonl", "-silent", "-no-color",
            "-rate-limit", str(p.get("rate_limit", 50)),
            "-timeout", str(p.get("timeout", 10)),
            "-retries", "0", "-disable-update-check"]
    tdir = os.path.expanduser("~/nuclei-templates")
    if os.path.isdir(tdir):
        argv += ["-t", tdir]
    sev = p.get("severity")
    if sev:
        argv += ["-severity", sev]
    tags = p.get("tags")
    if tags:
        argv += ["-tags", tags]
    if p.get("templates"):
        argv += ["-t", _confine_path(p["templates"], _template_roots(), "templates")]
    return argv


def parse_nuclei_jsonl(stdout: str) -> list[dict]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info", {})
        out.append({
            "template_id": r.get("template-id") or r.get("templateID"),
            "name": info.get("name"), "severity": info.get("severity"),
            "matched_at": r.get("matched-at") or r.get("matched"),
            "type": r.get("type"), "reference": info.get("reference"),
            "classification": info.get("classification"),
            "extracted": r.get("extracted-results"),
            "curl_command": r.get("curl-command"),
        })
    return out


NUCLEI = ToolSpec(
    name="nuclei", description="Template-based vulnerability scan (safe templates; severity filter).",
    category="web", binary="nuclei", timeout_s=600,
    params={
        "target": {"type": "string", "maxLength": 2048},
        "severity": {"type": "string",
                     "pattern": r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*"},
        "tags": {"type": "string", "maxLength": 200},
        "templates": {"type": "string", "maxLength": 500},
        "rate_limit": {"type": "integer", "minimum": 1, "maximum": NUCLEI_MAX_RATE},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 30},
    },
    required=["target"], handler=_nuclei_argv,
)

# ---- httpx (ProjectDiscovery) ----

def _httpx_argv(p: dict, decision) -> list[str]:
    argv = ["httpx", "-u", p["target"], "-json", "-silent", "-no-color",
            "-status-code", "-title", "-tech-detect", "-follow-redirects",
            "-timeout", str(p.get("timeout", 10)), "-disable-update-check"]
    return argv


def parse_httpx_jsonl(stdout: str) -> list[dict]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append({
            "url": r.get("url"), "status_code": r.get("status_code") or r.get("status-code"),
            "title": r.get("title"), "technologies": r.get("tech") or r.get("technologies"),
            "webserver": r.get("webserver"), "content_type": r.get("content_type"),
            "final_url": r.get("final_url"),
        })
    return out


HTTPX = ToolSpec(
    name="httpx", description="HTTP probe: status, title, technology fingerprint.",
    category="recon", binary="httpx", timeout_s=120,
    params={
        "target": {"type": "string", "maxLength": 2048},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 30},
    },
    required=["target"], handler=_httpx_argv,
)

# ---- subfinder (passive; no target egress) ----

def _subfinder_argv(p: dict, decision) -> list[str]:
    return ["subfinder", "-d", p["domain"], "-silent", "-timeout", "30", "-disable-update-check"]


SUBFINDER = ToolSpec(
    name="subfinder", description="Passive subdomain discovery (third-party sources only).",
    category="recon", binary="subfinder", timeout_s=180, network_effect=False,
    params={"domain": {"type": "string", "maxLength": 253}},
    required=["domain"], handler=_subfinder_argv, target_param="domain",
)

# ---- ffuf ----

def _ffuf_argv(p: dict, decision) -> list[str]:
    wordlist = _confine_path(p.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                             _wordlist_roots(), "wordlist")
    argv = ["ffuf", "-u", p["url"] + "/FUZZ", "-w", wordlist,
            "-of", "json", "-o", "/dev/stdout", "-s",
            "-mc", p.get("match_codes", "200,204,301,302,307,401,403"),
            "-t", str(p.get("threads", 10)), "-timeout", str(p.get("timeout", 10))]
    if p.get("extensions"):
        argv += ["-e", p["extensions"]]
    return argv


def parse_ffuf_json(stdout: str) -> list[dict]:
    # With -s and -o /dev/stdout, ffuf prints matched words before the JSON report;
    # parsing the whole stream silently returned [] for every real scan.
    r = None
    try:
        r = json.loads(stdout)
    except json.JSONDecodeError:
        for line in reversed(stdout.splitlines()):
            if line.lstrip().startswith("{"):
                try:
                    r = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
    if not isinstance(r, dict):
        return []
    return [{"url": x.get("url"), "status": x.get("status"), "length": x.get("length"),
             "words": x.get("words")} for x in r.get("results", [])]


FFUF = ToolSpec(
    name="ffuf", description="Content discovery (directory/file fuzzing) at a bounded rate.",
    category="recon", binary="ffuf", timeout_s=300,
    params={
        "url": {"type": "string", "maxLength": 2048},
        "wordlist": {"type": "string", "maxLength": 500},
        "extensions": {"type": "string", "maxLength": 100},
        "match_codes": {"type": "string", "maxLength": 60},
        "threads": {"type": "integer", "minimum": 1, "maximum": 20},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 30},
    },
    required=["url"], handler=_ffuf_argv, target_param="url",
)

ALL_ADAPTERS = [NMAP, NUCLEI, HTTPX, SUBFINDER, FFUF]
PARSERS = {"nmap": parse_nmap_xml, "nuclei": parse_nuclei_jsonl,
           "httpx": parse_httpx_jsonl, "ffuf": parse_ffuf_json}
