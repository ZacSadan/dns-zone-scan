"""Interpretation stage: turn raw scan facts into per-record purpose / insights / removability.

Pure functions over the saved scan JSON - no network access - so reports can be regenerated
from old scans and rules can be improved without re-scanning.
"""

from __future__ import annotations

import base64
import datetime as dt
import re
from collections import Counter, defaultdict

from . import knowledge as kb

WARN_DAYS = 60    # "less than 2 months" threshold for RED marking
NOTICE_DAYS = 90  # less than 90 days -> ORANGE marking

# severities
CRIT, WARN, INFO, OK = "crit", "warn", "info", "ok"


def parse_time(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def days_left(date_str: str | None, ref: dt.datetime) -> int | None:
    t = parse_time(date_str)
    return None if t is None else (t - ref).days


def is_red_date(date_str: str | None, ref: dt.datetime) -> bool:
    d = days_left(date_str, ref)
    return d is not None and d < WARN_DAYS


def is_orange_date(date_str: str | None, ref: dt.datetime) -> bool:
    d = days_left(date_str, ref)
    return d is not None and WARN_DAYS <= d < NOTICE_DAYS


def parent(fqdn: str) -> str:
    return fqdn.split(".", 1)[1] if "." in fqdn else ""


def rel_of(fqdn: str, domain: str) -> str:
    if fqdn == domain:
        return "@"
    return fqdn[: -(len(domain) + 1)] if fqdn.endswith("." + domain) else fqdn


# ---------------------------------------------------------------------------------------
class Analyzer:
    def __init__(self, scan: dict):
        self.s = scan
        self.domain = scan["domain"]
        self.ref = parse_time(scan["scan_started"])
        self.records = scan["records"]
        self.hosts = scan.get("hosts", {})
        self.ips = scan.get("ips", {})
        self.targets = scan.get("targets", {})
        self.ipv6 = (scan.get("scanner") or {}).get("ipv6", False)
        self.mx_targets = [r["target"] for r in self.records if r["type"] == "MX"]
        self.cf_cnames = {r["fqdn"] for r in self.records
                          if r["type"] == "CNAME" and r.get("target", "").endswith(".cdn.cloudflare.net")}
        self.actions: dict[str, list[str]] = defaultdict(list)
        self._explained: set = set()

    # -- helpers ----------------------------------------------------------------------
    def icmp_summary(self, ips: list[str]) -> tuple[int, int, int]:
        """(replied, tested, untestable)"""
        ok = tested = na = 0
        for ip in ips:
            ic = (self.ips.get(ip) or {}).get("icmp") or {}
            if ic.get("reply") is None:
                na += 1
                continue
            tested += 1
            ok += bool(ic.get("reply"))
        return ok, tested, na

    def tcp_any_open(self, ips: list[str]) -> bool:
        for ip in ips:
            d = self.ips.get(ip) or {}
            if (d.get("tcp80") or {}).get("open") or (d.get("tcp443") or {}).get("open"):
                return True
        return False

    def certs_for(self, domain_name: str, provider: str | None = None) -> list[tuple[str, dict]]:
        """Hosts whose served certificate covers domain_name (exact or wildcard SAN)."""
        out = []
        for fqdn, h in self.hosts.items():
            c = h.get("cert") or {}
            if not c.get("ok"):
                continue
            sans = [s.lower() for s in c.get("sans") or []]
            if domain_name in sans or f"*.{domain_name}" in sans:
                if provider is None or c.get("issuer_provider") == provider:
                    out.append((fqdn, c))
        return out

    def explain(self, key: str, text: str) -> tuple[str, str]:
        """Full explanation the first time a pattern appears, short pointer afterwards."""
        if key in self._explained:
            return (INFO, "Same pattern as above - see first occurrence")
        self._explained.add(key)
        return (INFO, text)

    def add_action(self, cat: str, text: str):
        if text not in self.actions[cat]:
            self.actions[cat].append(text)

    def drift(self, rec: dict) -> str | None:
        """Compare the export with what the authoritative server serves now."""
        key = f"{rec['fqdn']}|{rec['type']}"
        live = (self.s.get("auth_answers") or {}).get(key)
        if not live or rec["type"] == "SOA":
            return None
        if live["status"] not in ("NOERROR",):
            return f"authoritative server answers {live['status']} (record no longer served?)"
        want = {
            "A": rec.get("address"), "AAAA": rec.get("address"),
            "CNAME": rec.get("target"), "NS": rec.get("target"),
            "TXT": rec.get("text"),
            "MX": f"{rec.get('preference')} {rec.get('target')}",
        }.get(rec["type"], None)
        if want is None:
            return None
        if rec["type"] == "AAAA":
            import ipaddress
            vals = {str(ipaddress.ip_address(v)) for v in live["values"]}
            want = str(ipaddress.ip_address(want))
        else:
            vals = set(live["values"])
        if want not in vals:
            return f"value not served by authoritative DNS now (live: {', '.join(sorted(vals)) or 'none'})"
        return None

    # -- web / host records -----------------------------------------------------------
    def analyze_host_record(self, rec: dict) -> dict:
        fqdn, name, rtype = rec["fqdn"], rec["name"], rec["type"]
        h = self.hosts.get(fqdn) or {}
        res = h.get("resolve") or {}
        http, https, cert = h.get("http") or {}, h.get("https") or {}, h.get("cert") or {}
        ins: list[tuple[str, str]] = []
        removable = "No"
        purpose = None

        v4 = res.get("a", [])
        own_ips = [rec["address"]] if rtype in ("A", "AAAA") else v4  # A/AAAA: judge this record's own address
        icmp_ok, icmp_tested, _ = self.icmp_summary(own_ips)
        web = http.get("responded") or https.get("responded")
        tcp_open = self.tcp_any_open(own_ips)
        alive = bool(web or icmp_ok or tcp_open)
        temp_hints, nonprod_hints = kb.name_hints(name)

        # AAAA tested from remote IPv6 probes (scanner has no IPv6): judge the IPv6 path on its own
        icmp6 = ((self.ips.get(rec.get("address")) or {}).get("icmp") or {}) if rtype == "AAAA" else {}
        v6_remote = rtype == "AAAA" and not self.ipv6 and ("http6" in h or icmp6.get("via") == "globalping")
        web4 = web
        if v6_remote:
            http, https = h.get("http6") or {}, h.get("https6") or {}
            web = bool(http.get("responded") or https.get("responded"))
            alive = bool(web or icmp_ok)

        if rtype == "CNAME":
            target = rec.get("target", "")
            m = kb.first_match(kb.CNAME_TARGETS, target)
            purpose = m[1] if m else None
            tres = self.targets.get(target) or {}
            if target == self.domain:
                purpose = "Alias of the apex (" + self.domain + ")"
            if tres.get("status") == "NXDOMAIN" or res.get("cname_final_status") == "NXDOMAIN":
                prone = kb.is_takeover_prone(target)
                ins.append((CRIT, f"**Dangling CNAME**: target `{target}` does not exist (NXDOMAIN)"
                            + (" - provider allows re-claiming the name, **subdomain-takeover risk**" if prone else "")
                            + ". Delete the record."))
                removable = "Yes"
                self.add_action("security", f"`{name}` CNAME -> `{target}` is dangling (NXDOMAIN) - delete")
            elif kb.is_takeover_prone(target) and web:
                bad = self._unclaimed_signature(target, http, https)
                if bad:
                    ins.append((CRIT, f"Target answers like an **unclaimed resource** ({bad}) - subdomain-takeover risk."))
                    removable = "Yes"
                    self.add_action("security", f"`{name}` -> `{target}` looks unclaimed ({bad}) - delete or re-claim")

        if name.startswith("cloudflare-resolve-to."):
            origin_for = name[len("cloudflare-resolve-to."):]
            proxied = f"{origin_for}.{self.domain}"
            purpose = f"Cloudflare *Resolve Override* origin for `{origin_for}`"
            if proxied in self.cf_cnames:
                ins.append((INFO, f"Origin target for Cloudflare-proxied `{origin_for}` (CNAME to cdn.cloudflare.net). "
                                  "Keep while the Cloudflare origin rule references it."))
            else:
                ins.append((WARN, f"No `{origin_for}` CNAME to Cloudflare in this zone - override likely orphaned."))
                removable = "Likely"

        if h.get("wildcard"):
            ins.append((INFO, f"Wildcard - probed with random name `{h.get('probe_name')}`"))

        # --- liveness -------------------------------------------------------------
        if v6_remote:
            where = ", ".join(p["probe"] for p in (icmp6.get("probes") or [])[:2])
            ins.append((INFO, "IPv6 tested remotely via Globalping probes" + (f" ({where})" if where else "")
                              + " - ping and HTTP/HTTPS over IPv6; certificate shown is from the IPv4 path"))
        elif rtype == "AAAA" and not self.ipv6:
            ins.append((INFO, "IPv6 not testable from scanner (no IPv6 connectivity); HTTP/TLS results are via the IPv4 path of the same name"))
        if res.get("status") not in ("OK", None) and removable != "Yes":
            ins.append((WARN, f"Name does not resolve publicly ({res.get('status')})"))
        v6_untestable = rtype == "AAAA" and not self.ipv6 and not v6_remote
        if v6_remote and not web and web4:
            ins.append((WARN, "**IPv6 path broken**: the name works over IPv4 but HTTP/HTTPS over IPv6 fails "
                              f"(ping {'replies' if icmp_ok else 'no reply'}) - IPv6 clients get errors or fallback "
                              "delays. Fix the IPv6 frontend or delete this AAAA record"))
            if removable == "No":
                removable = "Likely"
            self.add_action("review", f"`{name}` AAAA {rec['address']} - IPv6 path broken while IPv4 works; fix or delete the AAAA")
        elif v6_untestable and not web:
            ins.append((WARN, "IPv6 address could not be tested (scanner has no IPv6) and the name serves no "
                              "HTTP/HTTPS over IPv4 either - verify from an IPv6-capable host"))
            if removable == "No":
                removable = "Review"
        elif not alive and res.get("status") == "OK":
            strong = bool(temp_hints)
            ins.append((WARN, "**Nothing answers** (no ICMP, no TCP 80/443, no HTTP/HTTPS) - candidate for deletion"
                        + (f"; name contains `{', '.join(temp_hints)}`" if strong else " (verify with the owner)")))
            if removable != "Yes":
                removable = "Yes" if strong else "Likely"
            self.add_action("delete", f"`{name}` ({rtype} {rec['value']}) - nothing answering"
                            + (f", name says `{', '.join(temp_hints)}`" if strong else ""))
        elif alive and not web and tcp_open:
            ins.append((WARN, "TCP 80/443 open but HTTP/HTTPS fails ("
                        f"{http.get('error') or '-'} / {https.get('error') or '-'}) - LB/frontend without a working "
                        "backend, or no certificate for this name"))
            if removable == "No":
                removable = "Review"
            self.add_action("review", f"`{name}` - ports open but HTTP/HTTPS broken ({https.get('error')})")
        elif alive and not web and icmp_ok:
            ins.append((WARN, "Answers ICMP only - nothing on TCP 80/443 (non-web service, or idle VM)"))
            if (temp_hints or nonprod_hints) and removable == "No":
                removable = "Likely" if temp_hints else "Review"
                hint = ", ".join(temp_hints or nonprod_hints)
                self.add_action("delete" if temp_hints else "review",
                                f"`{name}` - ping only, no web service, name says `{hint}`")

        if temp_hints and alive and removable == "No":
            ins.append((WARN, f"Name contains `{', '.join(temp_hints)}` but it still answers - confirm it's still needed"))
            removable = "Review"
            self.add_action("review", f"`{name}` - name says `{', '.join(temp_hints)}` but still answers")
        elif nonprod_hints and alive:
            ins.append((INFO, f"Non-production name (`{', '.join(nonprod_hints)}`)"))

        # --- HTTP semantics --------------------------------------------------------
        hs = https.get("status")
        ps = http.get("status")
        if hs and hs >= 500:
            ins.append((WARN, f"HTTPS returns {hs} - backend unhealthy / missing"))
        elif hs == 404 and (not ps or ps in (301, 302, 308, 404)):
            ins.append((INFO, "HTTPS answers 404 at `/` - API-only, or LB with no matching route"))
        if ps and 200 <= ps < 300 and https.get("responded") and hs and hs < 400:
            ins.append((INFO, "HTTP is served without redirect to HTTPS"))
        if ps and not https.get("responded"):
            ins.append((WARN if ps < 400 else INFO, f"HTTP only - no HTTPS ({https.get('error')})"))

        # --- certificate -----------------------------------------------------------
        is_cf_origin = name.startswith("cloudflare-resolve-to.")
        tgt = rec.get("target", "")
        external = rtype == "CNAME" and tgt != self.domain and not tgt.endswith("." + self.domain)
        if cert.get("ok") and not cert.get("hostname_match") and (external or is_cf_origin):
            if is_cf_origin:
                ins.append((INFO, "Certificate name mismatch is expected: Cloudflare connects to this origin using the "
                                  "proxied hostname's SNI, not this name"))
            else:
                ins.append((WARN, f"Provider's certificate (CN={cert.get('subject_cn')}) does not cover this name - "
                                  f"browsers get a certificate error on https://{fqdn}; the certificate lifecycle is the provider's"))
        elif cert.get("ok"):
            d = days_left(cert.get("not_after"), self.ref)
            if d is not None and d < 0:
                ins.append((CRIT, f"Certificate **expired** {-d} days ago"))
                self.add_action("certs", f"`{name}` certificate expired {cert.get('not_after', '')[:10]}")
            elif d is not None and d < WARN_DAYS:
                auto = cert.get("issuer_provider") in ("Google", "AWS", "Let's Encrypt", "Cloudflare", "SSL.com")
                late = auto and d < 20  # managed certs normally renew ~30 days before expiry
                if auto and not late:
                    ins.append((INFO, f"Certificate expires in {d} days - managed/ACME issuer, normally auto-renews "
                                      "~30 days before expiry (re-check if still unrenewed in 2 weeks)"))
                    self.add_action("info", f"`{name}` managed certificate ({cert.get('issuer_org')}) expires in {d} days - auto-renewal expected")
                else:
                    ins.append((WARN, f"Certificate expires in {d} days"
                                + (" - managed certificate has **not auto-renewed**; check the LB / validation records"
                                   if late else " - **manual renewal needed**")))
                    self.add_action("certs", f"`{name}` certificate ({cert.get('issuer_org')}) expires in {d} days"
                                    + (" - auto-renewal appears stuck" if late else " - manual renewal"))
            elif d is not None and d < NOTICE_DAYS:
                auto = cert.get("issuer_provider") in ("Google", "AWS", "Let's Encrypt", "Cloudflare", "SSL.com")
                ins.append((INFO, f"Certificate expires in {d} days"
                            + (" - managed/ACME issuer, auto-renewal expected" if auto else " - plan the renewal")))
                if not auto:
                    self.add_action("info", f"`{name}` certificate ({cert.get('issuer_org')}) expires in {d} days - plan renewal")
            if not cert.get("hostname_match"):
                ins.append((WARN, f"Certificate does not cover this name (CN={cert.get('subject_cn')}) - clients get a TLS error"))
                self.add_action("certs", f"`{name}` serves a certificate that does not cover the name (CN={cert.get('subject_cn')})")
            if not cert.get("trusted") and "mismatch" not in (cert.get("verify_error") or "").lower():
                ins.append((WARN, f"Certificate not trusted: {cert.get('verify_error')}"))

        if name.split(".")[0] == "ftp":
            t21 = h.get("tcp21") or {}
            if t21 and not t21.get("open"):
                ins.append((INFO, "Registrar-default `ftp` record; FTP port 21 is closed"))
                if removable == "No":
                    removable = "Likely"
                self.add_action("delete", f"`{name}` - legacy default record, FTP (21) closed")

        if rtype == "CNAME" and rec.get("target") == "email.secureserver.net":
            mx_gd = any("secureserver.net" in t for t in self.mx_targets)
            if not mx_gd:
                ins.append((WARN, "Webmail shortcut for GoDaddy email, but MX points elsewhere - not used"))
                removable = "Likely"
                self.add_action("delete", f"`{name}` - GoDaddy webmail shortcut, but mail is not hosted at GoDaddy")
            else:
                ins.append((INFO, "Webmail shortcut for GoDaddy email (MX is GoDaddy) - keep if users use it"))

        if removable == "No" and not ins:
            ins.append((OK, "Active"))
        return {"purpose": purpose, "insights": ins, "removable": removable, "alive": alive,
                "icmp": (icmp_ok, icmp_tested)}

    @staticmethod
    def _unclaimed_signature(target, http, https) -> str | None:
        for r in (https, http):
            title = (r.get("title") or "").lower()
            st = r.get("status")
            if "cloudfront" in target and st in (403, 421) and "could not be satisfied" in title:
                return f"CloudFront {st} 'request could not be satisfied'"
            if "ghs.google" in target and st == 404:
                return "Google hosted 404"
            if "readme" in target and st == 404:
                return "ReadMe 404"
            if "github.io" in target and st == 404:
                return "GitHub Pages 404"
            if "herokuapp" in target and "no such app" in title:
                return "Heroku 'no such app'"
        return None

    # -- service / validation CNAMEs --------------------------------------------------
    def analyze_service_cname(self, rec: dict) -> dict:
        target, name = rec.get("target", ""), rec["name"]
        m = kb.first_match(kb.CNAME_TARGETS, target)
        purpose = m[1] if m else "Service record (underscore name)"
        ins, removable = [], "Review"
        ttxt = (self.s.get("target_txt") or {}).get(target) or {}

        if target.endswith(".acm-validations.aws"):
            validated = parent(rec["fqdn"])  # _<hash>.s2s.example.com validates s2s.example.com
            users = self.certs_for(validated, "AWS")
            live = ttxt.get("status") == "OK"
            ins.append((INFO, f"Validates ACM certificates for `{validated}` / `*.{validated}`. ACM re-checks it for "
                              "**automatic renewal**, so it must stay while the ACM certificate exists."))
            ins.append((INFO, "AWS still serves the validation target" if live else
                        f"Validation target answers {ttxt.get('status')} (ACM may have deleted the request)"))
            if users:
                ins.append((OK, "In use: " + ", ".join(f"`{rel_of(f, self.domain)}`" for f, _ in users[:6])
                            + " serve(s) an Amazon certificate for this name"))
                removable = "No"
            else:
                ins.append((WARN, f"No scanned host presents an Amazon certificate for `{validated}` "
                                  "(it may be on CloudFront/ELB listeners not in this zone, or the cert is unused). "
                                  "Check ACM: if no certificate uses it, delete."))
                removable = "Review"
                self.add_action("review", f"`{name}` ACM validation - no live Amazon cert seen for `{validated}`; check ACM")
        elif target.endswith(".authorize.certificatemanager.goog"):
            validated = rec["fqdn"].split(".", 1)[1] if "." in rec["fqdn"] else self.domain
            users = self.certs_for(validated, "Google")
            ins.append((INFO, f"DNS authorization for Google-managed certificates covering `{validated}` / "
                              f"`*.{validated}` (Certificate Manager). Google needs it for every renewal."))
            if users:
                ins.append((OK, "In use: " + ", ".join(f"`{rel_of(f, self.domain)}`" for f, _ in users[:6])
                            + " serve(s) a Google Trust Services certificate for this name"))
                removable = "No"
            else:
                ins.append((WARN, f"No scanned host presents a Google certificate for `{validated}`. "
                                  "Check `gcloud certificate-manager dns-authorizations list`; delete if unused."))
                self.add_action("review", f"`{name}` Google Certificate Manager auth - no live Google cert seen for `{validated}`")
        elif target == "_domainconnect.gd.domaincontrol.com":
            ins.append((INFO, "GoDaddy default; enables one-click DNS setup for third-party services. Harmless; "
                              "can be removed if Domain Connect is not used."))
            removable = "Optional"
        elif "._domainkey" in rec["fqdn"]:
            purpose = "DKIM key (delegated by CNAME)" + (f" - {m[1]}" if m else "")
            ins.extend(self._dkim_insights(rec["fqdn"]))
            removable = "No"
        else:
            tres = self.targets.get(target) or {}
            if tres.get("status") == "NXDOMAIN" and ttxt.get("status") == "NXDOMAIN":
                ins.append((WARN, f"Target `{target}` does not exist"))
                removable = "Likely"
        dr = self.drift(rec)
        if dr:
            ins.append((WARN, dr))
        return {"purpose": purpose, "insights": ins, "removable": removable}

    # -- TXT ----------------------------------------------------------------------------
    def analyze_txt(self, rec: dict, same_name_counts: Counter) -> dict:
        text, name = rec.get("text", ""), rec["name"]
        ins, removable = [], "Review"
        m = kb.first_match(kb.TXT_PATTERNS, text)
        nm = kb.first_match(kb.TXT_NAME_PATTERNS, name)
        purpose = m[1] if m else (nm[1] if nm else None)

        if text.lower().startswith("v=spf1"):
            ins.extend(self._spf_insights(text))
            removable = "No"
        elif text.startswith("v=DMARC1"):
            ins.extend(self._dmarc_insights(text))
            removable = "No"
        elif "._domainkey" in rec["fqdn"]:
            purpose = "DKIM public key"
            ins.extend(self._dkim_insights(rec["fqdn"], text))
            removable = "No"
        elif re.match(r"^_?globalsign-domain-verification=", text):
            users = self.certs_for(self.domain, "GlobalSign")
            n = same_name_counts["globalsign"]
            ins.append(self.explain("globalsign", m[2]))
            if users:
                ins.append((INFO, "A GlobalSign certificate is still served by "
                                  + ", ".join(f"`{rel_of(f, self.domain)}`" for f, _ in users[:4])
                                  + " - remove after its renewal is validated"))
                removable = "Review"
            else:
                ins.append((OK, "No host serves a GlobalSign certificate - validation is over"))
                removable = "Yes"
            if n > 1 and "gs-count" not in self._explained:
                self._explained.add("gs-count")
                ins.append((INFO, f"{n} GlobalSign tokens present - older ones are definitely stale"))
            self.add_action("cleanup", f"`{name}` TXT GlobalSign verification token(s) - one-time CA validation, removable")
        elif text.startswith("google-site-verification="):
            n = same_name_counts[("gsv", rec["fqdn"])]
            ins.append(self.explain("gsv", m[2]))
            if rec["fqdn"] != self.domain:
                ins.append((INFO, f"On subdomain `{name}` - typically for a Search Console URL-prefix property or a "
                                  "GCS domain-named bucket / Cloud Run domain mapping"))
            if n > 1 and ("gsv-count", rec["fqdn"]) not in self._explained:
                self._explained.add(("gsv-count", rec["fqdn"]))
                ins.append((WARN, f"{n} Google verification tokens on this name - usually left by different "
                                  "people/properties over time; prune the ones not in Search Console"))
                self.add_action("cleanup", f"`{name}` has {n} google-site-verification tokens - prune unused (check Search Console / Google Admin)")
        elif text.startswith("vpce:"):
            ins.append(self.explain("vpce", m[2]))
            n = same_name_counts["vpce"]
            if n > 1 and "vpce-count" not in self._explained:
                self._explained.add("vpce-count")
                ins.append((WARN, f"{n} `vpce:` tokens in this zone - one per endpoint service (or repeated "
                                  "verification attempts); stale ones are clutter"))
            self.add_action("cleanup", f"{same_name_counts['vpce']} AWS PrivateLink `vpce:` TXT tokens - keep only those matching a current endpoint service")
        elif nm and nm[0] == r"^cloudflare-verify$":
            if self.cf_cnames:
                ins.append((OK, f"Cloudflare CNAME setup in use ({len(self.cf_cnames)} hostnames point to cdn.cloudflare.net) - keep"))
                removable = "No"
            else:
                ins.append((WARN, "No hostname points to cdn.cloudflare.net - Cloudflare CNAME setup appears unused"))
                removable = "Likely"
        elif m:
            if m[2]:
                ins.append((INFO, m[2]))
            removable = m[3]
        elif nm:
            if nm[2]:
                ins.append((INFO, nm[2]))
            removable = nm[3]
        else:
            purpose = "Unidentified verification token"
            ins.append((WARN, "Unknown TXT (bare token, no vendor prefix). Usually a one-time SaaS/CA ownership "
                              "check. Ask owners; if nobody claims it, remove it."))
            removable = "Review"
            self.add_action("review", f"`{name}` TXT `{text[:40]}` - unidentified token, find owner or remove")
        dr = self.drift(rec)
        if dr:
            ins.append((WARN, dr))
        return {"purpose": purpose, "insights": ins, "removable": removable}

    # -- mail ---------------------------------------------------------------------------
    def _spf_insights(self, text: str) -> list:
        ins = []
        spf = ((self.s.get("mail") or {}).get("spf")) or {}
        total = spf.get("total_lookups")
        incs = [t.split(":", 1)[1] for t in text.split() if t.lstrip("+-~?").lower().startswith("include:")]
        names = []
        for i in incs:
            p = kb.first_match(kb.SPF_INCLUDES, i)
            names.append(f"{i} ({p[1]})" if p else i)
        ins.append((INFO, "Senders: " + "; ".join(names)))
        if total is not None:
            if total > 10:
                ins.append((CRIT, f"SPF needs {total} DNS lookups (> 10) - **permerror**, SPF fails everywhere"))
                self.add_action("mail", f"SPF exceeds 10 DNS lookups ({total})")
            else:
                ins.append((OK if total <= 8 else WARN, f"{total}/10 DNS lookups used"))
        allm = re.search(r"([+\-~?]?)all\b", text)
        q = allm.group(1) if allm else None
        if q in ("+", ""):
            ins.append((CRIT, "`+all` lets anyone send as this domain"))
        elif q == "?":
            ins.append((WARN, "`?all` (neutral) - no protection"))
        elif q == "~":
            ins.append((INFO, "`~all` softfail - with DMARC p=reject this is fine; `-all` is stricter"))
        mx_prov = {kb.first_match(kb.MX_PROVIDERS, t)[1] for t in self.mx_targets if kb.first_match(kb.MX_PROVIDERS, t)}
        if any("secureserver" in i for i in incs) and not any("GoDaddy" in p for p in mx_prov):
            ins.append((INFO, "Includes GoDaddy (secureserver.net) although MX is not GoDaddy - keep only if GoDaddy still sends mail (e.g. DKIM records point there)"))
        for c in spf.get("children", []):
            st = c.get("status")
            if st in ("NO_SPF", "NXDOMAIN"):
                ins.append((CRIT, f"include `{c['domain']}` has no SPF record ({st}) - per RFC 7208 this makes the "
                                  "whole SPF evaluation **permerror**"))
                self.add_action("mail", f"SPF include `{c['domain']}` has no SPF record ({st}) - SPF permerror")
            elif st != "OK":
                ins.append((WARN, f"include `{c['domain']}` could not be resolved at scan time ({st})"))
                self.add_action("mail", f"SPF include `{c['domain']}` did not resolve at scan time ({st})")
        ins.append((INFO, "Review whether every listed sender (marketing/support tools) is still in use"))
        return ins

    def _dmarc_insights(self, text: str) -> list:
        tags = dict(t.strip().split("=", 1) for t in text.split(";") if "=" in t)
        p = tags.get("p", "").lower()
        ins = [(OK if p == "reject" else WARN if p == "quarantine" else CRIT,
                f"Policy p={p or 'missing'}" + (" (monitoring only - spoofing not blocked)" if p == "none" else ""))]
        if "rua" in tags:
            ins.append((INFO, f"Aggregate reports -> {tags['rua']}"))
        else:
            ins.append((WARN, "No `rua` - you get no reports"))
        return ins

    def _dkim_insights(self, fqdn: str, text: str | None = None) -> list:
        if text is None:
            d = (self.s.get("dkim") or {}).get(fqdn) or {}
            if d.get("status") != "OK" or not d.get("values"):
                self.add_action("mail", f"DKIM `{rel_of(fqdn, self.domain)}` does not resolve ({d.get('status')})")
                return [(WARN, f"DKIM key does not resolve ({d.get('status')}) - stale selector?")]
            text = d["values"][0]
        m = re.search(r"\bp=([A-Za-z0-9+/=\s]*)", text)
        if not m or not m.group(1).strip():
            return [(INFO, "Empty key (p=) - selector revoked")]
        try:
            from cryptography.hazmat.primitives.serialization import load_der_public_key

            key = load_der_public_key(base64.b64decode(m.group(1).replace(" ", "")))
            bits = key.key_size
            return [(OK if bits >= 2048 else WARN, f"RSA {bits}-bit key resolves" + ("" if bits >= 2048 else " - weak, rotate to 2048"))]
        except Exception:  # noqa: BLE001
            return [(INFO, "Key present (could not parse)")]

    def analyze_mx(self, rec: dict) -> dict:
        t = rec.get("target", "")
        p = kb.first_match(kb.MX_PROVIDERS, t)
        ins = []
        tres = self.targets.get(t) or {}
        if tres.get("status") != "OK":
            ins.append((CRIT, f"MX host does not resolve ({tres.get('status')})"))
            self.add_action("mail", f"MX `{t}` does not resolve")
        else:
            ins.append((OK, "MX host resolves"))
        if t.endswith("googlemail.com") or t.endswith("aspmx.l.google.com"):
            ins.append(self.explain("google-mx", "Legacy 5-record Google MX set - still valid; Google now also supports a single `smtp.google.com` MX (optional)"))
        if "secureserver.net" in t:
            ins.append((INFO, "GoDaddy-hosted email"))
        provs = {kb.first_match(kb.MX_PROVIDERS, x)[1] for x in self.mx_targets if kb.first_match(kb.MX_PROVIDERS, x)}
        if len(provs) > 1:
            ins.append((WARN, "MX records point to **different providers** - mail is split / one is stale"))
        dr = self.drift(rec)
        if dr:
            ins.append((WARN, dr))
        return {"purpose": f"Mail exchanger - {p[1] if p else 'unknown provider'}", "insights": ins, "removable": "No"}

    def analyze_ns_soa(self, rec: dict) -> dict:
        ins = []
        di = self.s.get("domain_info") or {}
        if rec["type"] == "NS":
            reg_ns = di.get("nameservers") or []
            live = (self.s.get("live_ns") or {}).get("values", [])
            t = rec.get("target")
            if reg_ns and t not in reg_ns:
                ins.append((CRIT, "Not a delegated nameserver at the registry - zone file NS differs from delegation"))
            else:
                ins.append((OK, "Matches registry delegation"))
            if live and t not in live:
                ins.append((WARN, "Not returned in live NS set"))
            purpose = "Nameserver" + (" - GoDaddy DNS" if "domaincontrol.com" in (t or "") else "")
            return {"purpose": purpose, "insights": ins, "removable": "No"}
        parts = rec["value"].split()
        serial = parts[2] if len(parts) > 2 else None
        live = ((self.s.get("auth_answers") or {}).get(f"{rec['fqdn']}|SOA") or {}).get("values", [])
        if live and serial and live[0] != serial:
            ins.append((WARN, f"Zone changed since export: export serial {serial}, live serial {live[0]} - re-export to keep this report current"))
            self.add_action("info", f"SOA serial changed since export ({serial} -> {live[0]})")
        elif live:
            ins.append((OK, f"Serial {serial} matches live authoritative DNS (export is current)"))
        return {"purpose": "Start of authority" + (" - GoDaddy DNS" if "domaincontrol" in rec["value"] else ""),
                "insights": ins, "removable": "No"}

    # -- domain-level ------------------------------------------------------------------
    def domain_level(self):
        has_mx = bool(self.mx_targets)
        has_spf = any(r["type"] == "TXT" and r["fqdn"] == self.domain and r.get("text", "").lower().startswith("v=spf1")
                      for r in self.records)
        has_dmarc = any(r["type"] == "TXT" and r["name"] == "_dmarc" for r in self.records)
        if not has_spf:
            self.add_action("mail", "No SPF record at the apex - anyone can spoof mail from this domain. Add one "
                                    "(or `v=spf1 -all` if the domain sends no mail)")
        if not has_dmarc:
            self.add_action("mail", "No DMARC record (`_dmarc`) - add at least `v=DMARC1; p=none; rua=...` and move to reject")
        if has_mx and not any("._domainkey" in r["fqdn"] for r in self.records):
            self.add_action("mail", "No DKIM selector records in the zone (may live elsewhere if signing via a provider default)")
        di = self.s.get("domain_info") or {}
        if di.get("expiration"):
            d = days_left(di["expiration"], self.ref)
            if d is not None and d < WARN_DAYS:
                self.add_action("domain", f"Domain registration expires {di['expiration'][:10]} ({d} days) - renew")
            elif d is not None and d < NOTICE_DAYS:
                self.add_action("info", f"Domain registration expires {di['expiration'][:10]} ({d} days) - renewal due soon")
        if di.get("dnssec") is False:
            self.add_action("info", "DNSSEC not enabled at the registry")

    # ---------------------------------------------------------------------------------
    def run(self) -> dict:
        per = {}
        counts = Counter()
        for r in self.records:
            if r["type"] == "TXT":
                t = r.get("text", "")
                if re.match(r"^_?globalsign-domain-verification=", t):
                    counts["globalsign"] += 1
                if t.startswith("google-site-verification="):
                    counts[("gsv", r["fqdn"])] += 1
                if t.startswith("vpce:"):
                    counts["vpce"] += 1
        from .scan import is_service_name

        for r in self.records:
            if r["type"] in ("A", "AAAA") or (r["type"] == "CNAME" and not is_service_name(r["name"])):
                a = self.analyze_host_record(r)
                dr = self.drift(r)
                if dr:
                    a["insights"].append((WARN, dr))
                    self.add_action("info", f"`{r['name']}` {r['type']}: {dr}")
            elif r["type"] == "CNAME":
                a = self.analyze_service_cname(r)
            elif r["type"] == "TXT":
                a = self.analyze_txt(r, counts)
            elif r["type"] == "MX":
                a = self.analyze_mx(r)
            elif r["type"] in ("NS", "SOA"):
                a = self.analyze_ns_soa(r)
            else:
                a = {"purpose": None, "insights": [], "removable": "-"}
                dr = self.drift(r)
                if dr:
                    a["insights"].append((WARN, dr))
            per[r["id"]] = a
        self.domain_level()
        return {"records": per, "actions": dict(self.actions)}


def analyze(scan: dict) -> dict:
    return Analyzer(scan).run()
