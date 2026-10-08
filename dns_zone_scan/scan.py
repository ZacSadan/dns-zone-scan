"""Scan stage: collect every raw fact about a zone and return a JSON-serialisable dict.

Nothing here makes judgements - interpretation happens in insights.py at report time,
so reports can be regenerated (and rules improved) without re-scanning.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import platform
import secrets
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import SCHEMA_VERSION, __version__, certs, cloud, domain, ipinfo, probe, remote, resolve
from .parser import parse_zone_file


def log(msg: str) -> None:
    print(f"  {msg}", file=sys.stderr, flush=True)


def probe_name_for(fqdn: str) -> str:
    """Wildcard records can't be queried literally; use a random label under them."""
    if fqdn.startswith("*."):
        return f"zscan-probe-{secrets.token_hex(3)}.{fqdn[2:]}"
    return fqdn


def is_service_name(rel: str) -> bool:
    """Underscore labels (_acme-challenge, _domainkey, _dmarc, ...) are not web hosts."""
    return any(label.startswith("_") for label in rel.split("."))


def _pmap(fn, items, workers):
    items = list(items)
    if not items:
        return {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return dict(zip(items, ex.map(fn, items)))


def spf_expand(resolver, domain_name: str, depth: int = 0, seen: frozenset = frozenset()) -> dict:
    """Recursively expand SPF includes and count DNS-querying mechanisms (RFC 7208 limit = 10)."""
    node = {"domain": domain_name, "record": None, "status": None, "lookups": 0, "children": []}
    # `seen` holds only the ancestors: the same include reached via two branches is legal (and counts twice)
    if domain_name in seen or depth > 10:
        node["status"] = "LOOP"
        return node
    seen = seen | {domain_name}
    # Large TXT sets (e.g. secureserver.net) occasionally come back incomplete - retry before concluding "no SPF".
    for attempt in range(3):
        r = resolve.query(resolver, domain_name, "TXT")
        spf = [v for v in r["values"] if v.lower().startswith("v=spf1")]
        if spf or r["status"] == "NXDOMAIN":
            break
        resolver = resolve.make_resolver([resolve.PUBLIC_RESOLVERS[(attempt + 1) % len(resolve.PUBLIC_RESOLVERS)]])
    node["status"] = r["status"]
    if not spf:
        node["status"] = node["status"] if node["status"] != "OK" else "NO_SPF"
        return node
    node["record"] = spf[0]
    node["multiple_spf"] = len(spf) > 1
    for term in spf[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:"):
            node["lookups"] += 1
            node["children"].append(spf_expand(resolver, term.split(":", 1)[1], depth + 1, seen))
        elif t.startswith("redirect="):
            node["lookups"] += 1
            node["children"].append(spf_expand(resolver, term.split("=", 1)[1], depth + 1, seen))
        elif t.split(":")[0].split("/")[0] in ("a", "mx", "ptr", "exists"):
            node["lookups"] += 1
    return node


def spf_total_lookups(node: dict) -> int:
    return node.get("lookups", 0) + sum(spf_total_lookups(c) for c in node.get("children", []))


def scan_zone(path: Path, workers: int = 32, timeout: float = 5.0, cloud_ranges=None,
              remote_ipv6: bool = True, tcp_ports: list[int] | None = None) -> dict:
    tcp_ports = list(tcp_ports or [])
    started = dt.datetime.now(dt.timezone.utc)
    local_stamp = dt.datetime.now().strftime("%Y%m%d_%H%M")
    zone = parse_zone_file(path)
    dom = zone["domain"]
    records = zone["records"]
    log(f"{path.name}: {dom}, {len(records)} records")

    res = resolve.make_resolver(timeout=timeout)
    errors: list[str] = []

    # --- scanner environment ---------------------------------------------------------
    env = {"hostname": socket.gethostname(), "platform": platform.platform(),
           "python": platform.python_version(), "ipv6": probe.ipv6_available()}
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_dom = ex.submit(domain.lookup, dom)
        cr = cloud_ranges or cloud.CloudRanges()
        domain_info = f_dom.result()
    log(f"domain RDAP: {domain_info.get('status')} expiry={domain_info.get('expiration')}")

    # --- authoritative comparison (zone export vs what the auth server serves now) ------
    zone_ns = [r["target"] for r in records if r["type"] == "NS" and r["fqdn"] == dom]
    live_ns = resolve.query(res, dom, "NS")
    auth = {"server": None, "ip": None}
    for ns in zone_ns + live_ns["values"]:
        ips = resolve.query(res, ns, "A")["values"]
        if ips:
            auth = {"server": ns, "ip": ips[0]}
            break
    pairs = sorted({(r["fqdn"], r["type"]) for r in records})
    auth_answers = {}
    if auth["ip"]:
        got = _pmap(lambda p: resolve.auth_query(auth["ip"], p[0], p[1], timeout), pairs, workers)
        auth_answers = {f"{k[0]}|{k[1]}": v for k, v in got.items()}
    log(f"authoritative check via {auth['server']}: {len(auth_answers)} rrsets")

    # --- hosts: everything that could be a web endpoint -------------------------------
    host_fqdns = sorted({r["fqdn"] for r in records
                         if r["type"] in ("A", "AAAA", "CNAME") and not is_service_name(r["name"])})
    probe_names = {f: probe_name_for(f) for f in host_fqdns}
    resolved = _pmap(lambda f: resolve_host_safe(res, probe_names[f]), host_fqdns, workers)
    log(f"resolved {len(resolved)} hosts")

    # --- other targets (CNAME targets, MX, NS, DKIM) ---------------------------------
    targets = sorted({r["target"] for r in records if r["type"] in ("CNAME", "MX", "NS") and r.get("target")})
    target_res = _pmap(lambda t: resolve_host_safe(res, t), targets, workers)
    dkim_names = sorted({r["fqdn"] for r in records if "._domainkey" in r["fqdn"]})
    dkim = _pmap(lambda n: resolve.query(res, n, "TXT"), dkim_names, workers)
    # Validation CNAME targets (ACM / Google Certificate Manager / other underscore records): what do they serve?
    svc_targets = sorted({r["target"] for r in records
                          if r["type"] == "CNAME" and is_service_name(r["name"]) and r.get("target")})
    target_txt = _pmap(lambda t: resolve.query(res, t, "TXT"), svc_targets, workers)

    # --- IPs: zone addresses + whatever hosts resolve to now ---------------------------
    ip_set = {r["address"] for r in records if r["type"] in ("A", "AAAA")}
    for h in resolved.values():
        ip_set.update(h.get("a", []))
        ip_set.update(h.get("aaaa", []))
    ips = sorted(ip_set, key=lambda i: (ipaddress.ip_address(i).version, ipaddress.ip_address(i)))
    log(f"probing {len(ips)} IPs (ICMP/TCP {'/'.join(map(str, [80, 443] + tcp_ports))}/PTR/RDAP)...")

    def ip_facts(ip):
        v6 = ipaddress.ip_address(ip).version == 6
        out = {"version": 6 if v6 else 4}
        if v6 and not env["ipv6"]:
            out["icmp"] = {"reply": None, "error": "scanner has no IPv6"}
            out["tcp80"] = out["tcp443"] = {"open": None, "error": "scanner has no IPv6"}
            out["tcp_extra"] = {str(p): {"open": None, "error": "scanner has no IPv6"} for p in tcp_ports}
        else:
            out["icmp"] = probe.icmp(ip)
            out["tcp80"] = probe.tcp(ip, 80, timeout)
            out["tcp443"] = probe.tcp(ip, 443, timeout)
            out["tcp_extra"] = {str(p): probe.tcp(ip, p, timeout) for p in tcp_ports}
        out["ptr"] = resolve.ptr(res, ip)
        out["cloud"] = cr.match(ip)
        return out

    ip_data = _pmap(ip_facts, ips, workers)
    rdap = _pmap(ipinfo.rdap_lookup, ips, 6)
    for ip in ips:
        ip_data[ip]["rdap"] = rdap[ip]
        asn = (rdap[ip].get("summary") or {}).get("asn")
        ip_data[ip]["asn_provider"] = cloud.asn_provider(asn)
    log("IP data collected")

    # --- HTTP / HTTPS / certificate per host -----------------------------------------
    def host_facts(fqdn):
        name = probe_names[fqdn]
        r = resolved[fqdn]
        out = {"probe_name": name, "wildcard": fqdn.startswith("*."), "resolve": r}
        if r["status"] != "OK" or not r.get("a"):
            # no IPv4 answer: still try if there is IPv6 and the scanner has it
            if not (r.get("aaaa") and env["ipv6"]):
                out["http"] = out["https"] = {"responded": False, "error": "no address" if r["status"] == "OK" else r["status"]}
                out["cert"] = {"ok": False, "error": "not resolvable"}
                return out
        out["http"] = probe.http(name, "http", timeout)
        out["https"] = probe.http(name, "https", timeout)
        out["cert"] = certs.get_cert(name, 443, timeout)
        label = fqdn.split(".")[0]
        if label == "ftp" or label.startswith("ftp"):
            out["tcp21"] = probe.tcp(name, 21, timeout)
        return out

    hosts = _pmap(host_facts, host_fqdns, workers)
    log(f"probed {len(hosts)} hosts (HTTP/HTTPS/TLS)")

    # --- IPv6 via remote probes when this machine has no IPv6 ------------------------
    remote_v6 = None
    v6_ips = sorted({r["address"] for r in records if r["type"] == "AAAA"})
    v6_hosts = sorted({r["fqdn"] for r in records if r["type"] == "AAAA" and not r["fqdn"].startswith("*.")})
    if v6_ips and not env["ipv6"] and remote_ipv6:
        log(f"no local IPv6 - testing {len(v6_ips)} IPv6 addresses / {len(v6_hosts)} AAAA names via Globalping...")
        remote_v6 = remote.ipv6_checks(v6_ips, v6_hosts)
        for ip, ping in remote_v6["ping"].items():
            if ip in ip_data:
                ip_data[ip]["icmp_local"] = ip_data[ip].get("icmp")
                ip_data[ip]["icmp"] = ping
        for fqdn in v6_hosts:
            if fqdn in hosts:
                hosts[fqdn]["http6"] = remote_v6["http"].get(fqdn)
                hosts[fqdn]["https6"] = remote_v6["https"].get(fqdn)
        log(f"remote IPv6 checks done (Globalping quota left: {remote_v6.get('remaining_quota')})")

    # --- mail -------------------------------------------------------------------------
    spf = spf_expand(res, dom)
    spf["total_lookups"] = spf_total_lookups(spf)
    dmarc = resolve.query(res, f"_dmarc.{dom}", "TXT")
    mx_live = resolve.query(res, dom, "MX")

    finished = dt.datetime.now(dt.timezone.utc)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "input_file": path.name,
        "scan_started": started.isoformat(),
        "scan_finished": finished.isoformat(),
        "scan_local_stamp": local_stamp,
        "scanner": env,
        "tcp_ports": [80, 443] + tcp_ports,
        "cloud_ranges_loaded": cr.loaded,
        "domain": dom,
        "exported": zone["exported"],
        "records": records,
        "domain_info": domain_info,
        "live_ns": live_ns,
        "authoritative": auth,
        "auth_answers": auth_answers,
        "hosts": hosts,
        "targets": target_res,
        "target_txt": target_txt,
        "dkim": dkim,
        "ips": ip_data,
        "mail": {"spf": spf, "dmarc": dmarc, "mx": mx_live},
        "remote_ipv6": remote_v6,
        "errors": errors,
    }


def resolve_host_safe(res, name):
    try:
        return resolve.resolve_host(res, name)
    except Exception as e:  # noqa: BLE001
        return {"status": f"ERROR {type(e).__name__}", "cname_chain": [], "a": [], "aaaa": []}
