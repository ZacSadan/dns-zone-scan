"""Domain registration data (expiry, registrar) via RDAP, falling back to WHOIS."""

from __future__ import annotations

import datetime as dt

import requests

from . import cache

IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"


def _rdap_base_for(tld: str, timeout: float) -> str | None:
    boot = cache.get("rdap-bootstrap-dns", ttl=7 * 24 * 3600)
    if boot is None:
        try:
            boot = requests.get(IANA_BOOTSTRAP, timeout=timeout).json()
            cache.put("rdap-bootstrap-dns", boot)
        except Exception:  # noqa: BLE001
            return None
    for tlds, urls in boot.get("services", []):
        if tld.lower() in [t.lower() for t in tlds] and urls:
            return urls[0].rstrip("/") + "/"
    return None


def _vcard_fn(entity: dict) -> str | None:
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item[0] == "fn":
                return item[3]
    except (IndexError, TypeError):
        pass
    return None


def parse_rdap(data: dict) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = None
    abuse = None
    for ent in data.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_fn(ent) or ent.get("handle")
            for sub in ent.get("entities", []):
                if "abuse" in (sub.get("roles") or []):
                    abuse = _vcard_fn(sub)
    return {
        "expiration": events.get("expiration"),
        "registration": events.get("registration"),
        "last_changed": events.get("last changed"),
        "registrar": registrar,
        "registrar_abuse": abuse,
        "status": data.get("status", []),
        "nameservers": sorted(ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])),
        "dnssec": (data.get("secureDNS") or {}).get("delegationSigned"),
    }


def lookup(domain: str, timeout: float = 15.0) -> dict:
    tld = domain.rsplit(".", 1)[-1]
    tried = []
    urls = []
    base = _rdap_base_for(tld, timeout)
    if base:
        urls.append(base + "domain/" + domain)
    urls.append("https://rdap.org/domain/" + domain)
    for url in urls:
        try:
            r = requests.get(url, timeout=timeout, headers={"Accept": "application/rdap+json"})
            tried.append(f"{url} -> {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                return {"status": "OK", "source": url, "tried": tried, **parse_rdap(data), "raw": data}
        except Exception as e:  # noqa: BLE001
            tried.append(f"{url} -> {type(e).__name__}")
    # WHOIS fallback
    try:
        import whois  # python-whois

        w = whois.whois(domain)

        def first(v):
            if isinstance(v, list):
                v = v[0] if v else None
            if isinstance(v, dt.datetime):
                if v.tzinfo is None:
                    v = v.replace(tzinfo=dt.timezone.utc)
                return v.isoformat()
            return v

        ns = w.get("name_servers") or []
        return {
            "status": "OK",
            "source": "whois",
            "tried": tried,
            "expiration": first(w.get("expiration_date")),
            "registration": first(w.get("creation_date")),
            "last_changed": first(w.get("updated_date")),
            "registrar": first(w.get("registrar")),
            "registrar_abuse": None,
            "status_codes": w.get("status"),
            "nameservers": sorted({str(n).lower() for n in (ns if isinstance(ns, list) else [ns])}),
            "dnssec": w.get("dnssec"),
            "raw": {k: str(v) for k, v in dict(w).items()},
        }
    except Exception as e:  # noqa: BLE001
        tried.append(f"whois -> {type(e).__name__}: {e}"[:200])
    return {"status": "ERROR", "tried": tried}
