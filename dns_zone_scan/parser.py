"""Parse BIND-style zone files (e.g. GoDaddy exports) into a flat list of records."""

from __future__ import annotations

import re
from pathlib import Path

import dns.name
import dns.rdatatype
import dns.zone

# Order record types appear in the report.
TYPE_ORDER = ["SOA", "NS", "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"]


def _type_rank(rtype: str) -> int:
    return TYPE_ORDER.index(rtype) if rtype in TYPE_ORDER else len(TYPE_ORDER)


def detect_origin(text: str) -> str | None:
    m = re.search(r"^\$ORIGIN\s+(\S+)", text, re.MULTILINE)
    if m:
        return m.group(1)
    m = re.search(r"^;\s*Domain:\s*(\S+)", text, re.MULTILINE)
    if m:
        return m.group(1).rstrip(".") + "."
    return None


def detect_export_time(text: str) -> str | None:
    m = re.search(r"^;\s*Exported.*?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def txt_value(rdata) -> str:
    """Join the character-strings of a TXT record (multi-string TXT = one logical value)."""
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


def parse_zone_text(text: str, origin: str | None = None) -> dict:
    origin = origin or detect_origin(text)
    if not origin:
        raise ValueError("Cannot determine zone origin ($ORIGIN or '; Domain:' header missing)")
    zone = dns.zone.from_text(text, origin=origin, relativize=False, check_origin=False)
    origin_name = dns.name.from_text(origin)
    domain = origin_name.to_text(omit_final_dot=True)

    records = []
    for name, ttl, rdata in zone.iterate_rdatas():
        rtype = dns.rdatatype.to_text(rdata.rdtype)
        fqdn = name.to_text(omit_final_dot=True)
        rel = name.relativize(origin_name).to_text()
        rec = {
            "name": rel,
            "fqdn": fqdn,
            "type": rtype,
            "ttl": ttl,
            "value": rdata.to_text(),
        }
        if rtype == "TXT":
            rec["text"] = txt_value(rdata)
        elif rtype == "CNAME":
            rec["target"] = rdata.target.to_text(omit_final_dot=True)
        elif rtype == "MX":
            rec["preference"] = rdata.preference
            rec["target"] = rdata.exchange.to_text(omit_final_dot=True)
        elif rtype == "NS":
            rec["target"] = rdata.target.to_text(omit_final_dot=True)
        elif rtype in ("A", "AAAA"):
            rec["address"] = rdata.address
        records.append(rec)

    records.sort(key=lambda r: (_type_rank(r["type"]), r["fqdn"] != domain, r["fqdn"], r["value"]))
    for i, r in enumerate(records):
        r["id"] = i
    return {
        "domain": domain,
        "exported": detect_export_time(text),
        "records": records,
    }


def parse_zone_file(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_zone_text(text)
