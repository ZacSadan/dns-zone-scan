"""Render a saved scan (+ insights) as Markdown. No network access."""

from __future__ import annotations

import html as _html
import ipaddress

from . import insights as ins_mod
from .insights import CRIT, INFO, OK, WARN, days_left, is_orange_date, is_red_date, parse_time, rel_of
from .scan import is_service_name

SEV_ICON = {CRIT: "🔴", WARN: "🟠", INFO: "🔵", OK: "✅"}
REMOVABLE_ICON = {"Yes": "🗑️ Yes", "Likely": "🗑️ Likely", "Review": "🔍 Review", "Optional": "Optional", "No": "No", "-": "-"}


def red(text: str) -> str:
    """RED marking: inline colour for VS Code / renderers that keep styles, emoji for GitHub (strips styles)."""
    return f'🔴 <span style="color:red">**{text}**</span>'


def orange(text: str) -> str:
    """ORANGE marking (< 90 days): same approach as red()."""
    return f'🟠 <span style="color:darkorange">**{text}**</span>'


# Brand colours for the Cloud column
CLOUD_COLORS = {"Google Cloud": "#1E64D4", "Google": "#1E64D4", "AWS": "#FB54FF", "Cloudflare": "#FE5E1F"}
# Certificate issuers coloured like the matching platform (Let's Encrypt shares the Cloudflare colour)
ISSUER_COLORS = {"Google": CLOUD_COLORS["Google"], "AWS": CLOUD_COLORS["AWS"], "Let's Encrypt": CLOUD_COLORS["Cloudflare"]}


def issuer_cell(cert: dict) -> str:
    text = esc(cert.get("issuer_org") or cert.get("issuer_cn"))
    if cert.get("issuer_provider"):
        text += f" ({esc(cert['issuer_provider'])})"
    color = ISSUER_COLORS.get(cert.get("issuer_provider"))
    return f'<span style="color:{color}">**{text}**</span>' if color else text


def cloud_cell(ip_data: dict | None, icon: bool = False) -> str:
    """Provider - service (region), coloured for GCP / AWS / Cloudflare."""
    if not ip_data:
        return ""
    c = ip_data.get("cloud")
    if c:
        provider = c["provider"]
        text = esc(provider) + (f" - {esc(c.get('service'))}" if c.get("service") and c.get("service") != provider else "") \
            + (f" ({esc(c['region'])})" if c.get("region") else "")
    elif ip_data.get("asn_provider"):
        provider = ip_data["asn_provider"]
        text = f"{esc(provider)} (by ASN)"
    else:
        return "not cloud"
    color = CLOUD_COLORS.get(provider) or next((v for k, v in CLOUD_COLORS.items() if provider.startswith(k)), None)
    if color:
        text = f'<span style="color:{color}">**{text}**</span>'
    return ("☁️ " if icon else "") + text


def esc(s) -> str:
    """Table-safe text. `<` is escaped because scanned values (HTTP headers, whois, TXT) end up in the HTML report."""
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("<", "&lt;").replace("\n", " ").replace("\r", "")


def code(s) -> str:
    if s in (None, ""):
        return ""
    s = str(s).replace("\n", " ").replace("\r", "")
    if "`" in s or "<" in s:  # would break out of a backtick span: use an escaped HTML <code> instead
        return f"<code>{_html.escape(s).replace('|', '&#124;')}</code>"
    return f"`{esc(s)}`"


def expandable(items: list[str], limit: int, sep: str = ", ") -> str:
    """First `limit` items inline; the rest behind a clickable "+N more" (<details> works in HTML, GitHub, VS Code)."""
    if len(items) <= limit + 1:  # never hide a single item behind "+1 more"
        return sep.join(code(i) for i in items)
    head = sep.join(code(i) for i in items[:limit])
    rest = items[limit:]
    hidden = sep.join(f"<code>{_html.escape(str(i))}</code>" for i in rest)
    return f'{head}<details class="more"><summary>+{len(rest)} more</summary>{hidden}</details>'


def trunc(s: str, n: int = 60) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


# Issuers whose certificates auto-renew: no orange (< 90 days) marking, red (< 60 days) still applies
AUTO_RENEW_ISSUERS = {"AWS", "Google", "Let's Encrypt"}


def date_cell(date_str: str | None, ref, orange_ok: bool = True) -> str:
    if not date_str:
        return ""
    d = days_left(date_str, ref)
    label = f"{date_str[:10]} ({d}d)" if d is not None else date_str[:10]
    if d is not None and d < 0:
        return red(f"{date_str[:10]} EXPIRED")
    if is_red_date(date_str, ref):
        return red(label)
    return orange(label) if orange_ok and is_orange_date(date_str, ref) else label


def insights_cell(items) -> str:
    return "<br>".join(f"{SEV_ICON.get(sev, '')} {esc(text)}" for sev, text in items)


def http_cell(r: dict) -> str:
    if not r:
        return ""
    if not r.get("responded"):
        return f"❌ {esc(r.get('error'))}"
    s = f"{r.get('status')}"
    if r.get("location"):
        s += f" → {esc(trunc(r['location'], 45))}"
    if r.get("server"):
        s += f" ({esc(trunc(r['server'], 25))})"
    return s


def asn_text(sm: dict) -> str:
    """ipwhois may return several origin ASNs ("15169 43515")."""
    asn = sm.get("asn")
    if not asn or asn == "NA":
        return ""
    return " / ".join(f"AS{a}" for a in str(asn).split())


def asn_name(sm: dict, ip_data: dict) -> str:
    return sm.get("asn_description") or ip_data.get("asn_provider") or sm.get("org") or ""


def ip_sort_key(ip):
    a = ipaddress.ip_address(ip)
    return (a.version, a)


class Report:
    def __init__(self, scan: dict):
        self.s = scan
        self.a = ins_mod.analyze(scan)
        self.ref = parse_time(scan["scan_started"])
        self.domain = scan["domain"]
        self.lines: list[str] = []

    def w(self, line: str = ""):
        self.lines.append(line)

    def table(self, headers: list[str], rows: list[list[str]]):
        self.w("| " + " | ".join(headers) + " |")
        self.w("|" + "|".join("---" for _ in headers) + "|")
        for r in rows:
            self.w("| " + " | ".join(c if c is not None else "" for c in r) + " |")
        self.w()

    # -- sections ---------------------------------------------------------------------------
    def header(self):
        s, di = self.s, self.s.get("domain_info") or {}
        self.w(f"# DNS zone report - {self.domain}")
        self.w()
        exp = di.get("expiration")
        if exp:
            d = days_left(exp, self.ref)
            txt = f"{exp[:10]} ({d} days left)" if d is not None and d >= 0 else f"{exp[:10]} (EXPIRED)"
            exp_cell = red(txt) if is_red_date(exp, self.ref) else \
                orange(txt) if is_orange_date(exp, self.ref) else f"**{txt}**"
        else:
            exp_cell = red("UNKNOWN - registry lookup failed")
        live_ns = (s.get("live_ns") or {}).get("values", [])
        rows = [
            ["**Domain expiry**", exp_cell],
            ["Registrar", esc(di.get("registrar"))],
            ["Registered", (di.get("registration") or "")[:10]],
            ["Registry status", esc(", ".join(di.get("status") or []) if isinstance(di.get("status"), list) else di.get("status_codes"))],
            ["DNSSEC", "signed" if di.get("dnssec") else "not signed"],
            ["Nameservers (registry)", esc(", ".join(di.get("nameservers") or []))],
            ["Nameservers (live)", esc(", ".join(live_ns))],
            ["Zone file", f"{code(s['input_file'])} (exported {esc(s.get('exported'))})"],
            ["Records", str(len(s["records"]))],
            ["Scan time (UTC)", f"{s['scan_started'][:19].replace('T', ' ')} → {s['scan_finished'][11:19]}"],
            ["Registry data source", esc(di.get("source"))],
        ]
        self.table(["", ""], rows)
        has_v6 = any(r["type"] == "AAAA" for r in s["records"])
        if has_v6 and not (s.get("scanner") or {}).get("ipv6"):
            rv6 = s.get("remote_ipv6")
            if rv6:
                self.w(f"> ℹ️ The scanner host has no IPv6 connectivity: the zone's IPv6 addresses and AAAA names were "
                       f"tested remotely through {rv6.get('service')} probes (ping + HTTP/HTTPS over IPv6), marked *(remote)*.")
            else:
                self.w("> ℹ️ The scanner host has no IPv6 connectivity: IPv6 addresses were not ping/port tested.")
            self.w()

    def summary(self):
        recs = self.s["records"]
        rem = [self.a["records"][r["id"]]["removable"] for r in recs]
        sev = [sv for r in recs for sv, _ in self.a["records"][r["id"]]["insights"]]
        by_type = {}
        for r in recs:
            by_type[r["type"]] = by_type.get(r["type"], 0) + 1
        self.w("## Summary")
        self.w()
        self.w("Records by type: " + ", ".join(f"**{t}** {n}" for t, n in by_type.items()))
        self.w()
        self.w(f"- 🔴 critical findings: **{sev.count(CRIT)}**  ·  🟠 warnings: **{sev.count(WARN)}**")
        self.w(f"- Removable: 🗑️ Yes **{rem.count('Yes')}**  ·  🗑️ Likely **{rem.count('Likely')}**  ·  🔍 Review **{rem.count('Review')}**")
        self.w()

    def actions(self):
        titles = [
            ("domain", "🔴 Domain registration"),
            ("security", "🔴 Security (dangling records / takeover risk)"),
            ("certs", "🔴 Certificates"),
            ("delete", "🗑️ Delete candidates"),
            ("cleanup", "🧹 Cleanup (stale verification / validation records)"),
            ("mail", "✉️ Mail authentication"),
            ("review", "🔍 Needs owner review"),
            ("info", "ℹ️ Informational"),
        ]
        acts = self.a["actions"]
        self.w("## Action items")
        self.w()
        if not any(acts.values()):
            self.w("No action items. ✅")
            self.w()
            return
        for key, title in titles:
            items = acts.get(key) or []
            if not items:
                continue
            self.w(f"### {title}")
            self.w()
            for it in items:
                self.w(f"- {it.replace('<', '&lt;')}")
            self.w()

    def host_records(self):
        recs = [r for r in self.s["records"]
                if r["type"] in ("A", "AAAA") or (r["type"] == "CNAME" and not is_service_name(r["name"]))]
        self.w("## Web records (A / AAAA / CNAME)")
        self.w()
        self.w("ICMP = ping replies / IPs tested · HTTP/HTTPS = status of `GET /` (no redirects followed) · "
               "Cert = certificate served on 443 with SNI = the record name.")
        self.w()
        rows = []
        for r in recs:
            h = self.s["hosts"].get(r["fqdn"]) or {}
            res = h.get("resolve") or {}
            an = self.a["records"][r["id"]]
            if r["type"] == "AAAA":
                ips = [r["address"]]
            else:
                ips = res.get("a", []) or res.get("aaaa", [])
            first = self.s["ips"].get(ips[0]) if ips else None
            ip_cell = expandable(ips, 3, "<br>")
            if r["type"] == "CNAME" and len(res.get("cname_chain") or []) > 1:
                ip_cell = "via " + " → ".join(code(c) for c in res["cname_chain"][1:]) + "<br>" + ip_cell
            if res.get("status") not in ("OK", None):
                ip_cell = f"❌ {res.get('status')}"
            ok, tested = an.get("icmp", (0, 0))
            if tested:
                icmp = f"{'✅' if ok else '❌'} {ok}/{tested}"
                if r["type"] == "AAAA" and ((self.s["ips"].get(r["address"]) or {}).get("icmp") or {}).get("via"):
                    icmp += " (remote)"
            else:
                icmp = "n/a" if ips else ""
            asn = cloud = ptr = ""
            if first:
                sm = (first.get("rdap") or {}).get("summary") or {}
                asn = f"{asn_text(sm)} {esc(trunc(asn_name(sm, first), 30))}".strip()
                cloud = cloud_cell(first, icon=True)
                ptr = "<br>".join(code(p) for p in (first.get("ptr") or {}).get("values", [])[:2])
            cert = h.get("cert") or {}
            if cert.get("ok"):
                cert_cell = issuer_cell(cert)
                if not cert.get("hostname_match"):
                    cert_cell += " ⚠️ name mismatch"
                exp = date_cell(cert.get("not_after"), self.ref,
                                orange_ok=cert.get("issuer_provider") not in AUTO_RENEW_ISSUERS)
            else:
                cert_cell = f"none ({esc(trunc(cert.get('error') or '', 30))})" if cert else ""
                exp = ""
            value = code(trunc(r.get("target") or r["value"], 50))
            name = code(r["name"]) + (f"<br>*{esc(an['purpose'])}*" if an.get("purpose") else "")
            v6r = r["type"] == "AAAA" and "http6" in h  # remote IPv6 results for this AAAA name
            hc = http_cell(h.get("http6") if v6r else h.get("http")) + (" (IPv6, remote)" if v6r else "")
            hsc = http_cell(h.get("https6") if v6r else h.get("https")) + (" (IPv6, remote)" if v6r else "")
            rows.append([name, r["type"], value, ip_cell, icmp, hc, hsc,
                         asn, cloud, ptr, cert_cell, exp, insights_cell(an["insights"]),
                         REMOVABLE_ICON.get(an["removable"], an["removable"])])
        self.table(["Name", "Type", "Zone value", "Resolves to (live)", "ICMP", "HTTP", "HTTPS", "ASN", "Cloud",
                    "Reverse DNS", "Certificate issuer", "Cert expiry", "Insights / action", "Removable?"], rows)

    def ip_details(self):
        self.w("## IP address details")
        self.w()
        self.w("Whois = RDAP registration of the IP block. Cloud = match against the provider's published IP ranges (AWS, GCP, Google, Cloudflare, DigitalOcean), else ASN.")
        self.w()
        users = {}
        for fqdn, h in self.s["hosts"].items():
            for ip in (h.get("resolve") or {}).get("a", []) + (h.get("resolve") or {}).get("aaaa", []):
                users.setdefault(ip, set()).add(rel_of(fqdn, self.domain))
        for r in self.s["records"]:
            if r["type"] in ("A", "AAAA"):
                users.setdefault(r["address"], set()).add(r["name"])
        zone_ips = {r["address"] for r in self.s["records"] if r["type"] in ("A", "AAAA")}
        shown = [ip for ip in self.s["ips"] if ip in zone_ips or ":" not in ip]
        hidden = len(self.s["ips"]) - len(shown)
        rows = []
        def by_users(ip):  # group IPs by the records that use them; unused IPs last
            names = sorted(users.get(ip, []))
            return (not names, [n.lower() for n in names], ip_sort_key(ip))

        for ip in sorted(shown, key=by_users):
            d = self.s["ips"][ip]
            sm = (d.get("rdap") or {}).get("summary") or {}
            ic = d.get("icmp") or {}
            icmp = "n/a" if ic.get("reply") is None else ("✅" + (f" {ic['rtt_ms']:.0f}ms" if ic.get("rtt_ms") is not None else "") if ic.get("reply") else "❌")
            if ic.get("via") and ic.get("reply") is not None:
                icmp += " (remote)"
            p80 = (d.get("tcp80") or {}).get("open")
            p443 = (d.get("tcp443") or {}).get("open")
            ports = "n/a" if p80 is None else " ".join(f"{p}{'✅' if o else '❌'}" for p, o in (("80", p80), ("443", p443)))
            cloud = cloud_cell(d)
            names = sorted(users.get(ip, []))
            name_cell = expandable(names, 8)
            whois_err = "" if (d.get("rdap") or {}).get("status") == "OK" else f"⚠️ {esc((d.get('rdap') or {}).get('error'))}"
            rows.append([code(ip), icmp, ports,
                         asn_text(sm), esc(asn_name(sm, d)),
                         esc(sm.get("org")) or whois_err, esc(sm.get("net_name")), esc(trunc(sm.get("net_cidr") or "", 40)),
                         esc(sm.get("asn_country") or sm.get("net_country")), cloud,
                         "<br>".join(code(p) for p in (d.get("ptr") or {}).get("values", [])[:2]) or esc((d.get("ptr") or {}).get("status")),
                         name_cell])
        self.table(["IP", "ICMP", "TCP", "ASN", "ASN name", "Whois org", "Net name", "Net CIDR", "Country",
                    "Cloud / service", "Reverse DNS (PTR)", "Used by"], rows)
        if hidden:
            self.w(f"*{hidden} IPv6 addresses returned by CNAME targets are omitted here (full data in the scan JSON).*")
            self.w()

    def other_records(self, title: str, pred, note: str | None = None):
        recs = [r for r in self.s["records"] if pred(r)]
        if not recs:
            return
        self.w(f"## {title}")
        self.w()
        if note:
            self.w(note)
            self.w()
        rows = []
        for r in recs:
            an = self.a["records"][r["id"]]
            v = r.get("text") if r["type"] == "TXT" else (f"{r['preference']} {r['target']}" if r["type"] == "MX" else (r.get("target") or r["value"]))
            rows.append([code(r["name"]), r["type"], code(trunc(v, 70)), esc(an.get("purpose")),
                         insights_cell(an["insights"]), REMOVABLE_ICON.get(an["removable"], an["removable"])])
        self.table(["Name", "Type", "Value", "Purpose", "Insights / action", "Removable?"], rows)

    def footer(self):
        s = self.s
        self.w("---")
        self.w()
        self.w("### Method & legend")
        self.w()
        self.w(f"- 🔴 critical · 🟠 warning · 🔵 info · ✅ OK. Expiry dates are marked {red('red')} when less than "
               f"{ins_mod.WARN_DAYS} days away (or already passed) and {orange('orange')} when less than "
               f"{ins_mod.NOTICE_DAYS} days away, relative to the scan time.")
        self.w("- **Removable?** 🗑️ Yes = evidence says safe to delete · 🗑️ Likely = probably unused, confirm with owner · "
               "🔍 Review = check in the relevant console · No = in use / required.")
        self.w("- DNS: public resolvers (8.8.8.8, 1.1.1.1) for live resolution; the zone's authoritative server "
               f"(`{esc((s.get('authoritative') or {}).get('server'))}`) to compare the export against what is served now.")
        self.w("- Wildcard records are probed via a random label under the wildcard.")
        self.w("- Whois/ASN via RDAP (ipwhois); domain expiry via registry RDAP (IANA bootstrap) with WHOIS fallback.")
        self.w("- Certificates fetched with SNI and read even when untrusted/expired; trust and name-match evaluated separately.")
        loaded = s.get("cloud_ranges_loaded") or {}
        missing = [k for k, v in loaded.items() if not v]
        if missing:
            self.w(f"- ⚠️ Cloud range lists that failed to load: {', '.join(missing)} (ASN fallback used).")
        self.w(f"- dns-zone-scan {s.get('tool_version')} · schema {s.get('schema_version')} · scanner `{esc((s.get('scanner') or {}).get('hostname'))}`")
        self.w()

    def render(self) -> str:
        self.header()
        self.summary()
        self.actions()
        self.host_records()
        self.ip_details()
        self.other_records("Certificate validation & service records (underscore CNAMEs)",
                           lambda r: r["type"] == "CNAME" and is_service_name(r["name"]))
        self.other_records("TXT records", lambda r: r["type"] == "TXT")
        self.other_records("Mail (MX)", lambda r: r["type"] == "MX")
        self.other_records("Delegation (NS / SOA)", lambda r: r["type"] in ("NS", "SOA"))
        self.other_records("Other records", lambda r: r["type"] not in ("A", "AAAA", "CNAME", "TXT", "MX", "NS", "SOA"))
        self.footer()
        return "\n".join(self.lines)


def render(scan: dict) -> str:
    return Report(scan).render()
