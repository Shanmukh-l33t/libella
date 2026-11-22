"""TLS/transport security audit: protocols, certificate validity, hostname match.

Scope-checked before connect. Facts are captured as evidence; findings carry
a TLS proof request that the verifier re-runs (not HTTP replay).
"""
import datetime
import socket
import ssl
import time

from .db import DB
from .evidence import EvidenceStore
from .findings import FindingPipeline
from .scope import Scope

WEAK_PROTOCOLS = ["TLSv1", "TLSv1.1"]


def _try_protocol(host: str, port: int, proto_name: str, ip: str | None = None) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ver = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1,
           "TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}[proto_name]
    try:
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except ValueError:
        return {"protocol": proto_name, "supported": False, "reason": "unsupported by local OpenSSL"}
    try:
        with socket.create_connection((ip or host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return {"protocol": proto_name, "supported": True,
                        "cipher": tls.cipher()[0]}
    except (ssl.SSLError, OSError) as e:
        return {"protocol": proto_name, "supported": False, "reason": type(e).__name__}


def scan_tls(host: str, port: int, ip: str | None = None) -> dict:
    """Collect transport facts. Caller MUST scope-check first.

    `ip` is the address the egress policy authorized: dial it, while still sending
    `host` as the TLS server name, so a DNS answer that changes after the decision
    cannot move the connection.
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    facts = {"host": host, "port": port, "scanned_at": time.time()}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip or host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                facts["negotiated_protocol"] = tls.version()
                facts["cipher"] = tls.cipher()[0]
                der = tls.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der)
                sans_dns, sans_ip = [], []
                try:
                    san = cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                    sans_dns = san.get_values_for_type(x509.DNSName)
                    sans_ip = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
                except x509.ExtensionNotFound:
                    pass
                cn = None
                try:
                    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
                except (IndexError, x509.AttributeNotFound):
                    pass
                not_after = cert.not_valid_after_utc
                now = datetime.datetime.now(datetime.timezone.utc)
                facts["cert"] = {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "notBefore": str(cert.not_valid_before_utc),
                    "notAfter": str(not_after),
                    "subjectAltName": sans_dns + sans_ip,
                    "common_name": cn,
                    "pem_sha256": __import__("hashlib").sha256(
                        ssl.DER_cert_to_PEM_cert(der).encode()).hexdigest(),
                }
                facts["self_signed"] = cert.subject == cert.issuer
                # hostname validation against SANs (IP literals vs iPAddress SANs)
                try:
                    import ipaddress
                    ipaddress.ip_address(host)
                    facts["hostname_match"] = host in sans_ip
                except ValueError:
                    h = host.lower().rstrip(".")
                    match = any(h == d.lower() or (d.startswith("*.") and
                                h.endswith(d[1:].lower()) and h.count(".") == d.count("."))
                                for d in sans_dns)
                    facts["hostname_match"] = match or (cn is not None and h == cn.lower())
                facts["expired"] = not_after < now
                facts["days_to_expiry"] = (not_after - now).days
    except (ssl.SSLError, OSError) as e:
        facts["error"] = f"{type(e).__name__}: {e}"
        return facts
    facts["weak_protocols"] = [p for p in WEAK_PROTOCOLS
                               if _try_protocol(host, port, p, ip).get("supported")]
    return facts


def audit_tls(host: str, port: int, db: DB, evidence: EvidenceStore,
              pipeline: FindingPipeline, scope: Scope, engagement_id: str,
              intent_id: str | None = None) -> list[dict]:
    from .egress import Egress
    decision = Egress(db, scope, engagement_id, tool="tls_audit", category="infra").decide(
        host, port, scheme="https")
    if not decision.allowed:
        return []  # Egress already emitted egress_denied + scope_refusal for this host
    facts = scan_tls(host, port, ip=decision.ip)
    ev = evidence.put_json(engagement_id, facts, "tls_scan")
    pipeline.record_observation(engagement_id, intent_id, "tls_scan",
                                f"{host}:{port} {facts.get('negotiated_protocol')} "
                                f"expired={facts.get('expired')} weak={facts.get('weak_protocols')}",
                                ev["id"])
    if facts.get("error"):
        pipeline.record_observation(engagement_id, intent_id, "degradation",
                                    f"tls_audit: {facts['error']}", ev["id"])
        return []
    base = f"tls://{host}:{port}"
    proof = {"method": "TLS", "url": base}
    candidates = []
    if facts.get("expired"):
        candidates.append({
            "title": f"Expired TLS certificate on {host}:{port}", "cwe": "CWE-298",
            "owasp": "A02:2021 Cryptographic Failures", "severity": "high",
            "confidence": "high", "endpoint": base,
            "description": f"Certificate notAfter {facts['cert']['notAfter']} is in the past.",
            "impact": "Clients cannot validate the server; MITM exposure and trust errors.",
            "remediation": "Renew the certificate and automate renewal monitoring.",
            "evidence_ids": [ev["id"]], "quote": "expired: true", "quote_in": "tls_fact",
            "proof_request": proof, "dedup_key": f"tls-expired:{host}:{port}",
        })
    if facts.get("hostname_match") is False:
        candidates.append({
            "title": f"TLS certificate hostname mismatch on {host}:{port}", "cwe": "CWE-297",
            "owasp": "A02:2021 Cryptographic Failures", "severity": "medium",
            "confidence": "high", "endpoint": base,
            "description": f"Certificate SANs {facts['cert']['subjectAltName']} do not match {host}.",
            "impact": "Hostname validation fails; users trained to bypass warnings; MITM risk.",
            "remediation": "Issue a certificate covering the served hostname.",
            "evidence_ids": [ev["id"]], "quote": "hostname_match: false", "quote_in": "tls_fact",
            "proof_request": proof, "dedup_key": f"tls-hostname:{host}:{port}",
        })
    if facts.get("weak_protocols"):
        candidates.append({
            "title": f"Weak TLS protocols enabled on {host}:{port} ({', '.join(facts['weak_protocols'])})",
            "cwe": "CWE-326", "owasp": "A02:2021 Cryptographic Failures", "severity": "medium",
            "confidence": "high", "endpoint": base,
            "description": "Server accepts TLSv1/TLSv1.1 connections.",
            "impact": "Deprecated protocols with known weaknesses (BEAST/POODLE-class).",
            "remediation": "Disable TLSv1/TLSv1.1; require TLSv1.2+.",
            "evidence_ids": [ev["id"]], "quote": f"weak_protocols: {','.join(facts['weak_protocols'])}",
            "quote_in": "tls_fact", "proof_request": proof,
            "dedup_key": f"tls-weak:{host}:{port}",
        })
    if facts.get("self_signed"):
        pipeline.record_observation(engagement_id, intent_id, "tls_self_signed",
                                    f"{host}:{port} uses a self-signed certificate "
                                    "(observation; expected in labs, context-dependent in prod)",
                                    ev["id"])
    submitted = []
    for cand in candidates:
        submitted.append(pipeline.submit_candidate(engagement_id, cand, intent_id))
    return submitted


def recheck_tls_fact(host: str, port: int, quote: str, scope: Scope, db: DB | None = None,
                     engagement_id: str | None = None) -> tuple[bool | None, str]:
    """Independent re-verification for tls_fact quotes (verifier dispatch).

    Returns (None, reason) when the fact cannot be judged — out of scope,
    unreachable, or an unknown quote. None is never "reproduced" or "fixed".
    """
    # before dialling: the same dial-time decision every other path makes
    if db is not None and engagement_id is not None:
        from .egress import Egress
        decision = Egress(db, scope, engagement_id, tool="tls_audit",
                          category="infra").decide(host, port, scheme="https")
    else:
        decision = scope.check_host_port(host, port, "infra")
    if not decision.allowed:
        return None, f"refused: {decision.reason}"
    facts = scan_tls(host, port, ip=getattr(decision, "ip", None))
    if facts.get("error"):
        return None, f"recheck failed: {facts['error']}"
    if quote.startswith("expired:"):
        ok = facts.get("expired") is True
        return ok, f"expired now {facts.get('expired')}"
    if quote.startswith("hostname_match:"):
        ok = facts.get("hostname_match") is False
        return ok, f"hostname_match now {facts.get('hostname_match')}"
    if quote.startswith("weak_protocols:"):
        want = set(quote.split(":", 1)[1].strip().split(","))
        now = set(facts.get("weak_protocols", []))
        ok = bool(want & now)
        return ok, f"weak protocols now {sorted(now)}"
    return None, "unknown tls_fact quote"
