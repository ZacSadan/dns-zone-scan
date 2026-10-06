"""Live DNS lookups: CNAME chains, A/AAAA, PTR, TXT, authoritative comparisons."""

from __future__ import annotations

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename

PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1"]


def make_resolver(nameservers: list[str] | None = None, timeout: float = 5.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = nameservers or PUBLIC_RESOLVERS
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def _err_name(e: Exception) -> str:
    if isinstance(e, dns.resolver.NXDOMAIN):
        return "NXDOMAIN"
    if isinstance(e, dns.resolver.NoAnswer):
        return "NOANSWER"
    if isinstance(e, dns.resolver.NoNameservers):
        return "SERVFAIL"
    if isinstance(e, dns.exception.Timeout):
        return "TIMEOUT"
    return type(e).__name__


def query(resolver, name: str, rtype: str) -> dict:
    """Return {status, values, cname_chain, canonical} for a single lookup."""
    out = {"status": "OK", "values": [], "cname_chain": [], "canonical": None}
    try:
        ans = resolver.resolve(name, rtype, raise_on_no_answer=True, search=False)
        out["canonical"] = ans.canonical_name.to_text(omit_final_dot=True)
        try:
            out["cname_chain"] = [rr[0].target.to_text(omit_final_dot=True) for rr in ans.chaining_result.cnames]
        except AttributeError:
            pass
        vals = []
        for rd in ans:
            if rtype in ("A", "AAAA"):
                vals.append(rd.address)
            elif rtype == "TXT":
                vals.append(b"".join(rd.strings).decode("utf-8", errors="replace"))
            elif rtype in ("CNAME", "NS", "PTR"):
                vals.append(rd.target.to_text(omit_final_dot=True))
            elif rtype == "MX":
                vals.append(f"{rd.preference} {rd.exchange.to_text(omit_final_dot=True)}")
            else:
                vals.append(rd.to_text())
        out["values"] = sorted(vals)
    except Exception as e:  # noqa: BLE001 - every failure is data
        out["status"] = _err_name(e)
    return out


def follow_cnames(resolver, name: str, max_depth: int = 10) -> dict:
    """Walk the CNAME chain hop by hop so a dangling final target is still visible."""
    chain = []
    current = name
    status = "OK"
    for _ in range(max_depth):
        r = query(resolver, current, "CNAME")
        if r["status"] == "OK" and r["values"]:
            current = r["values"][0]
            chain.append(current)
            continue
        if r["status"] == "NXDOMAIN":
            status = "NXDOMAIN"
        break
    return {"chain": chain, "final": current, "status": status}


def resolve_host(resolver, name: str) -> dict:
    """Full host resolution: CNAME chain + A + AAAA."""
    chain = follow_cnames(resolver, name)
    a = query(resolver, name, "A")
    aaaa = query(resolver, name, "AAAA")
    status = "OK"
    if not a["values"] and not aaaa["values"]:
        if chain["status"] == "NXDOMAIN" or "NXDOMAIN" in (a["status"], aaaa["status"]):
            status = "NXDOMAIN"
        elif "TIMEOUT" in (a["status"], aaaa["status"]):
            status = "TIMEOUT"
        elif "SERVFAIL" in (a["status"], aaaa["status"]):
            status = "SERVFAIL"
        else:
            status = "NOADDRESS"
    return {
        "status": status,
        "cname_chain": chain["chain"],
        "cname_final": chain["final"] if chain["chain"] else None,
        "cname_final_status": chain["status"] if chain["chain"] else None,
        "a": a["values"],
        "a_status": a["status"],
        "aaaa": aaaa["values"],
        "aaaa_status": aaaa["status"],
    }


def ptr(resolver, ip: str) -> dict:
    try:
        rev = dns.reversename.from_address(ip).to_text()
    except Exception as e:  # noqa: BLE001
        return {"status": type(e).__name__, "values": []}
    r = query(resolver, rev, "PTR")
    return {"status": r["status"], "values": r["values"]}


def auth_query(server_ip: str, name: str, rtype: str, timeout: float = 5.0) -> dict:
    """Ask an authoritative server directly (no recursion), compare to the zone export."""
    try:
        q = dns.message.make_query(name, rtype)
        q.flags &= ~0x0100  # clear RD
        resp = dns.query.udp(q, server_ip, timeout=timeout)
        if resp.flags & 0x0200:  # truncated
            resp = dns.query.tcp(q, server_ip, timeout=timeout)
        rcode = dns.rcode.to_text(resp.rcode())
        vals = []
        want = dns.rdatatype.from_text(rtype)
        qname = dns.name.from_text(name)
        for rrset in resp.answer:
            if rrset.name != qname or rrset.rdtype != want:
                continue
            for rd in rrset:
                if rtype == "TXT":
                    vals.append(b"".join(rd.strings).decode("utf-8", errors="replace"))
                elif rtype in ("A", "AAAA"):
                    vals.append(rd.address)
                elif rtype in ("CNAME", "NS"):
                    vals.append(rd.target.to_text(omit_final_dot=True))
                elif rtype == "MX":
                    vals.append(f"{rd.preference} {rd.exchange.to_text(omit_final_dot=True)}")
                elif rtype == "SOA":
                    vals.append(str(rd.serial))
                else:
                    vals.append(rd.to_text())
        return {"status": rcode, "values": sorted(vals)}
    except Exception as e:  # noqa: BLE001
        return {"status": _err_name(e), "values": []}
