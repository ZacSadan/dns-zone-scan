"""Cloud provider detection: official published IP ranges first, ASN mapping as fallback."""

from __future__ import annotations

import ipaddress

import requests

from . import cache

SOURCES = {
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",
    "google": "https://www.gstatic.com/ipranges/goog.json",
    "cloudflare_v4": "https://www.cloudflare.com/ips-v4",
    "cloudflare_v6": "https://www.cloudflare.com/ips-v6",
    "digitalocean": "https://digitalocean.com/geo/google.csv",
}

# ASN -> provider (fallback when the IP is not in a published range list)
ASN_PROVIDERS = {
    "15169": "Google", "396982": "Google Cloud", "19527": "Google", "36040": "Google (YouTube)",
    "16509": "AWS", "14618": "AWS", "8987": "AWS",
    "13335": "Cloudflare", "209242": "Cloudflare",
    "8075": "Microsoft Azure", "8068": "Microsoft", "8069": "Microsoft",
    "14061": "DigitalOcean",
    "31898": "Oracle Cloud", "45102": "Alibaba Cloud", "37963": "Alibaba Cloud",
    "20940": "Akamai", "16625": "Akamai", "63949": "Akamai (Linode)",
    "54113": "Fastly", "24940": "Hetzner", "16276": "OVH", "20473": "Vultr (Choopa)",
    "26496": "GoDaddy", "398101": "GoDaddy", "44273": "GoDaddy",
    "36351": "IBM Cloud (SoftLayer)", "62567": "DigitalOcean",
}


def _fetch(name: str, url: str, timeout: float):
    key = f"cloud-{name}"
    data = cache.get(key)
    if data is not None:
        return data
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "dns-zone-scan"})
        r.raise_for_status()
        data = r.json() if url.endswith(".json") else r.text
        cache.put(key, data)
        return data
    except Exception:  # noqa: BLE001
        return None


class CloudRanges:
    def __init__(self, timeout: float = 15.0):
        self.entries: list[tuple] = []  # (network, provider, service, region)
        self.loaded: dict[str, bool] = {}
        aws = _fetch("aws", SOURCES["aws"], timeout)
        self.loaded["aws"] = bool(aws)
        if aws:
            for p in aws.get("prefixes", []):
                self._add(p["ip_prefix"], "AWS", p.get("service"), p.get("region"))
            for p in aws.get("ipv6_prefixes", []):
                self._add(p["ipv6_prefix"], "AWS", p.get("service"), p.get("region"))
        gcp = _fetch("gcp", SOURCES["gcp"], timeout)
        self.loaded["gcp"] = bool(gcp)
        if gcp:
            for p in gcp.get("prefixes", []):
                pre = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                self._add(pre, "Google Cloud", p.get("service"), p.get("scope"))
        goog = _fetch("google", SOURCES["google"], timeout)
        self.loaded["google"] = bool(goog)
        if goog:
            for p in goog.get("prefixes", []):
                pre = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                self._add(pre, "Google", "Google services", None)
        for key in ("cloudflare_v4", "cloudflare_v6"):
            txt = _fetch(key, SOURCES[key], timeout)
            self.loaded[key] = bool(txt)
            for line in (txt or "").split():
                self._add(line.strip(), "Cloudflare", "CDN/Proxy", None)
        do = _fetch("digitalocean", SOURCES["digitalocean"], timeout)
        self.loaded["digitalocean"] = bool(do)
        for line in (do or "").splitlines():
            parts = line.split(",")
            if parts and "/" in parts[0]:
                region = ",".join(p for p in parts[1:4] if p)
                self._add(parts[0], "DigitalOcean", "Droplet/LB", region)

    def _add(self, prefix, provider, service, region):
        if not prefix:
            return
        try:
            self.entries.append((ipaddress.ip_network(prefix, strict=False), provider, service, region))
        except ValueError:
            pass

    def match(self, ip: str) -> dict | None:
        """Most specific matching prefix; for AWS prefer a concrete service over the AMAZON umbrella."""
        addr = ipaddress.ip_address(ip)
        hits = [e for e in self.entries if e[0].version == addr.version and addr in e[0]]
        if not hits:
            return None

        def rank(e):
            net, provider, service, _ = e
            generic = service in ("AMAZON", "Google services")
            return (provider != "Google", not generic, net.prefixlen)

        best = max(hits, key=rank)
        return {
            "provider": best[1],
            "service": best[2],
            "region": best[3],
            "prefix": str(best[0]),
            "source": "published ranges",
            "all_services": sorted({e[2] for e in hits if e[2]}),
        }


def asn_provider(asn: str | None) -> str | None:
    if not asn:
        return None
    first = str(asn).split()[0]
    return ASN_PROVIDERS.get(first)
