"""IP ownership: ASN + RDAP whois via ipwhois."""

from __future__ import annotations

import time
import warnings

from . import cache


def rdap_lookup(ip: str, retries: int = 2) -> dict:
    cached = cache.get(f"rdap-ip-{ip}")
    if cached is not None:
        return cached
    from ipwhois import IPWhois

    last_err = None
    for attempt in range(retries + 1):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                res = IPWhois(ip, timeout=10).lookup_rdap(depth=1, retry_count=2, rate_limit_timeout=30)
            out = {"status": "OK", "raw": res, "summary": summarize(res)}
            cache.put(f"rdap-ip-{ip}", out)
            return out
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {e}"[:300]
            time.sleep(1.5 * (attempt + 1))
    return {"status": "ERROR", "error": last_err, "raw": None, "summary": {}}


def _entity_org(res: dict) -> str | None:
    objs = res.get("objects") or {}
    for handle in res.get("entities") or []:
        o = objs.get(handle) or {}
        roles = o.get("roles") or []
        contact = o.get("contact") or {}
        if "registrant" in roles or "administrative" in roles or not roles:
            if contact.get("name"):
                return contact["name"]
    for o in objs.values():
        c = (o or {}).get("contact") or {}
        if c.get("name"):
            return c["name"]
    return None


def summarize(res: dict) -> dict:
    net = res.get("network") or {}
    return {
        "asn": res.get("asn"),
        "asn_description": res.get("asn_description"),
        "asn_cidr": res.get("asn_cidr"),
        "asn_country": res.get("asn_country_code"),
        "asn_registry": res.get("asn_registry"),
        "net_name": net.get("name"),
        "net_handle": net.get("handle"),
        "net_cidr": net.get("cidr"),
        "net_country": net.get("country"),
        "net_type": net.get("type"),
        "org": _entity_org(res),
    }
