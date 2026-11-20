"""TLS lab: vulnerable/hardened HTTPS twins for transport-security benchmarks.

vuln (:8443): expired + hostname-mismatched self-signed cert, TLSv1/1.1 enabled.
hardened (:8444): valid localhost cert, TLSv1.2+ only.
Certs generated at startup into labs/tlslab/certs/ (lab-only, fake).
"""
import datetime
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify

MODE = os.environ.get("LAB_MODE", "vuln")
VULN = MODE == "vuln"
PORT = int(os.environ.get("LAB_PORT", "8443"))
CERTS = Path(__file__).parent / "certs"


def make_cert(cn: str, san: str, days_valid: int, expired: bool = False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    if expired:
        not_before, not_after = now - datetime.timedelta(days=400), now - datetime.timedelta(days=30)
    else:
        not_before, not_after = now - datetime.timedelta(days=1), now + datetime.timedelta(days=days_valid)
    san_ext: list = [x509.DNSName(san)]
    if san == "localhost":
        import ipaddress
        san_ext.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(san_ext), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def ensure_certs():
    CERTS.mkdir(exist_ok=True)
    sets = {
        "expired": ("localhost", "localhost", True),
        "mismatch": ("wrong.invalid", "wrong.invalid", False),
        "valid": ("localhost", "localhost", False),
    }
    for tag, (cn, san, expired) in sets.items():
        kp, cp = CERTS / f"{tag}.key", CERTS / f"{tag}.crt"
        if kp.exists() and cp.exists():
            continue
        key, cert = make_cert(cn, san, 365, expired)
        kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption()))
        kp.chmod(0o600)
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok", mode=MODE, tls=True)


@app.get("/")
def index():
    return jsonify(service="tlslab", mode=MODE)


def main():
    ensure_certs()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_tag = os.environ.get("LAB_CERT", "expired" if VULN else "valid")
    ctx.load_cert_chain(CERTS / f"{cert_tag}.crt", CERTS / f"{cert_tag}.key")
    if VULN:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    app.run(host="127.0.0.1", port=PORT, ssl_context=ctx, debug=False)


if __name__ == "__main__":
    main()
