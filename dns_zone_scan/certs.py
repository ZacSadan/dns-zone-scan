"""TLS certificate retrieval and classification."""

from __future__ import annotations

import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

# Issuer organisation substring -> (provider, typical meaning)
ISSUER_PROVIDERS = [
    ("Google Trust Services", "Google", "Google-managed cert (GCP LB / Certificate Manager / Google front end)"),
    ("Amazon", "AWS", "AWS Certificate Manager (ACM) - ELB / CloudFront / API GW"),
    ("Let's Encrypt", "Let's Encrypt", "Free ACME CA (self-managed, or via a platform)"),
    ("Cloudflare", "Cloudflare", "Cloudflare edge certificate"),
    ("SSL Corporation", "SSL.com", "Commercial CA (often Cloudflare Universal SSL)"),
    ("SSL.com", "SSL.com", "Commercial CA (often Cloudflare Universal SSL)"),
    ("Microsoft", "Microsoft Azure", "Azure-managed certificate"),
    ("GoDaddy", "GoDaddy", "GoDaddy commercial / website-builder cert"),
    ("Starfield", "GoDaddy", "GoDaddy (Starfield) commercial cert"),
    ("GlobalSign", "GlobalSign", "Commercial CA"),
    ("DigiCert", "DigiCert", "Commercial CA"),
    ("Sectigo", "Sectigo", "Commercial CA"),
    ("ZeroSSL", "ZeroSSL", "Free ACME CA"),
    ("Entrust", "Entrust", "Commercial CA"),
    ("Buypass", "Buypass", "Free ACME / commercial CA"),
]


def issuer_provider(issuer_org: str | None, issuer_cn: str | None) -> dict:
    text = f"{issuer_org or ''} {issuer_cn or ''}"
    for needle, provider, meaning in ISSUER_PROVIDERS:
        if needle.lower() in text.lower():
            return {"provider": provider, "meaning": meaning}
    return {"provider": None, "meaning": None}


def _name_attr(name: x509.Name, oid) -> str | None:
    vals = name.get_attributes_for_oid(oid)
    return vals[0].value if vals else None


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == n[2:]:
                return True
    return False


def parse_der(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    issuer_org = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    return {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer_org": issuer_org,
        "issuer_cn": issuer_cn,
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": format(cert.serial_number, "x"),
        "sans": sans,
        "sig_alg": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "self_signed": cert.issuer == cert.subject,
        **{f"issuer_{k}": v for k, v in issuer_provider(issuer_org, issuer_cn).items()},
    }


def _handshake(host: str, port: int, timeout: float, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            return ss.getpeercert(binary_form=True), ss.version(), ss.getpeername()[0]


def get_cert(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Fetch the served certificate (SNI=host). Trust is checked first; on failure we still read the cert."""
    trusted, verify_error = True, None
    try:
        der, tls_version, peer = _handshake(host, port, timeout, verify=True)
    except ssl.SSLCertVerificationError as e:
        trusted, verify_error = False, (e.verify_message or str(e))[:200]
        try:
            der, tls_version, peer = _handshake(host, port, timeout, verify=False)
        except Exception as e2:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e2).__name__}: {e2}"[:200]}
    except socket.timeout:
        return {"ok": False, "error": "timeout"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "refused"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}
    if not der:
        return {"ok": False, "error": "no certificate presented"}
    info = parse_der(der)
    info.update({
        "ok": True,
        "trusted": trusted,
        "verify_error": verify_error,
        "tls_version": tls_version,
        "peer_ip": peer,
        "hostname_match": hostname_matches(host, info["sans"] or ([info["subject_cn"]] if info["subject_cn"] else [])),
    })
    return info
