"""Build the README demo report from 100% synthetic data - no network, no real zones.

Uses the reserved example.com domain, documentation-only IP ranges (RFC 5737: 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24; RFC 3849: 2001:db8::/32) and made-up tokens. The output
(docs/demo/*.md|html) and the screenshots (docs/screenshots/*.png) are safe to publish.

    python scripts/make_demo.py                 # demo .json/.md/.html into docs/demo/
    python scripts/make_demo.py --screenshots   # + PNGs via headless Edge/Chrome (needs Pillow)
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dns_zone_scan import html_report, report  # noqa: E402
from dns_zone_scan.parser import parse_zone_text  # noqa: E402

DOMAIN = "example.com"
SCAN_TIME = "2026-10-06T09:00:00+00:00"

ZONE = f"""; Domain: {DOMAIN}
; Exported (y-m-d hh:mm:ss): 2026-10-06 08:55:00
$ORIGIN {DOMAIN}.
@	3600	IN	SOA	ns1.dns-provider.example. hostmaster.example.com. ( 2026100601 28800 7200 604800 3600 )
@	3600	IN	NS	ns1.dns-provider.example.
@	3600	IN	NS	ns2.dns-provider.example.
@	3600	IN	A	192.0.2.10
www	3600	IN	A	192.0.2.10
api	3600	IN	A	198.51.100.20
api	3600	IN	AAAA	2001:db8:10::20
app	3600	IN	A	198.51.100.30
*.preview	3600	IN	A	198.51.100.40
staging	3600	IN	A	203.0.113.60
legacy-vm	3600	IN	A	203.0.113.50
old-test-todelete	3600	IN	A	203.0.113.99
cdn	3600	IN	CNAME	d111111abcdef8.cloudfront.net.
lb	3600	IN	CNAME	demo-nlb-0123456789abcdef.elb.us-east-1.amazonaws.com.
shop	3600	IN	CNAME	shop.example.com.cdn.cloudflare.net.
docs	3600	IN	CNAME	missing-docs-site.herokuapp.com.
ftp	3600	IN	CNAME	@
_0123456789abcdef0123456789abcdef	3600	IN	CNAME	_fedcba9876543210fedcba9876543210.abcdefghij.acm-validations.aws.
_acme-challenge	3600	IN	CNAME	00000000-1111-2222-3333-444444444444.1.authorize.certificatemanager.goog.
@	3600	IN	MX	1	aspmx.l.google.com.
@	3600	IN	TXT	"v=spf1 include:_spf.google.com ~all"
@	3600	IN	TXT	"google-site-verification=EXAMPLE-token-one"
@	3600	IN	TXT	"google-site-verification=EXAMPLE-token-two"
@	3600	IN	TXT	"_globalsign-domain-verification=EXAMPLE-globalsign-token"
@	3600	IN	TXT	"a1b2c3d4e5"
_abcdefghij0123456789	3600	IN	TXT	"vpce:EXAMPLEvpceToken01"
cloudflare-verify	3600	IN	TXT	"123456789-987654321"
_dmarc	3600	IN	TXT	"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com"
"""

# -- fact builders -------------------------------------------------------------------------


def http(status, location=None, server=None):
    return {"responded": True, "status": status, "location": location, "server": server}


def down(err="connect timeout"):
    return {"responded": False, "error": err}


def cert(issuer, provider, not_after, sans, cn=None, match=True, trusted=True):
    return {"ok": True, "issuer_org": issuer, "issuer_cn": None, "issuer_provider": provider,
            "subject_cn": cn or sans[0], "sans": sans, "not_after": not_after,
            "trusted": trusted, "hostname_match": match, "verify_error": None}


def res(a=(), aaaa=(), chain=(), status="OK"):
    return {"status": status, "a": list(a), "aaaa": list(aaaa), "cname_chain": list(chain),
            "cname_final_status": ("NXDOMAIN" if status == "NXDOMAIN" else "OK") if chain else None}


def host(r, h, hs, c, **extra):
    return {"resolve": r, "http": h, "https": hs, "cert": c, **extra}


def ip(asn, asn_desc, org, net, cidr, cloud=None, ptr=(), up=True, ports=True, v6=False, asn_provider=None):
    return {
        "version": 6 if v6 else 4,
        "icmp": {"reply": up, "rtt_ms": 4.0 if up else None, **({"via": "globalping", "probes": [
            {"probe": "Frankfurt DE (Example Net)"}, {"probe": "Singapore SG (Example Net)"}]} if v6 else {})},
        "tcp80": {"open": None if v6 else ports}, "tcp443": {"open": None if v6 else ports},
        "ptr": {"status": "OK" if ptr else "NXDOMAIN", "values": list(ptr)},
        "cloud": cloud, "asn_provider": asn_provider,
        "rdap": {"status": "OK", "summary": {"asn": asn, "asn_description": asn_desc, "org": org,
                                             "net_name": net, "net_cidr": cidr, "asn_country": "US"}},
    }


GCP = lambda region: {"provider": "Google Cloud", "service": "Google Cloud", "region": region}  # noqa: E731
AWS = lambda svc, region: {"provider": "AWS", "service": svc, "region": region}  # noqa: E731
CF = {"provider": "Cloudflare", "service": "CDN/Proxy", "region": None}

GTS, AMZ, LE = "Google Trust Services", "Amazon", "Let's Encrypt"
WILD = [DOMAIN, f"*.{DOMAIN}"]


def build_scan() -> dict:
    zone = parse_zone_text(ZONE)
    d = DOMAIN
    hosts = {
        d: host(res(["192.0.2.10"]), http(301, f"https://www.{d}/"), http(301, f"https://www.{d}/"),
                cert(GTS, "Google", "2027-03-01T00:00:00+00:00", WILD)),
        f"www.{d}": host(res(["192.0.2.10"]), http(301, f"https://www.{d}/"), http(200, server="Google Frontend"),
                         cert(GTS, "Google", "2027-03-01T00:00:00+00:00", WILD)),
        f"api.{d}": host(res(["198.51.100.20"], ["2001:db8:10::20"]), http(301, f"https://api.{d}/"), http(404),
                         cert(GTS, "Google", "2026-11-20T00:00:00+00:00", [f"api.{d}"]),
                         http6=http(301, f"https://api.{d}/"), https6=http(404)),
        f"app.{d}": host(res(["198.51.100.30"]), http(301, f"https://app.{d}/"), http(200, server="nginx"),
                         cert("GoDaddy.com, Inc.", "GoDaddy", "2026-12-20T00:00:00+00:00", WILD)),
        f"*.preview.{d}": host(res(["198.51.100.40"]), http(301), http(404, server="nginx"),
                               cert(GTS, "Google", "2026-12-28T00:00:00+00:00", [f"*.preview.{d}"]),
                               wildcard=True, probe_name=f"zscan-probe-1a2b3c.preview.{d}"),
        f"staging.{d}": host(res(["203.0.113.60"]), down("connection error"), down("TLS error"),
                             {"ok": False, "error": "SSLEOFError"}),
        f"legacy-vm.{d}": host(res(["203.0.113.50"]), down(), down(), {"ok": False, "error": "timeout"}),
        f"old-test-todelete.{d}": host(res(["203.0.113.99"]), down(), down(), {"ok": False, "error": "timeout"}),
        f"cdn.{d}": host(res(["192.0.2.101", "192.0.2.102"], chain=["d111111abcdef8.cloudfront.net"]),
                         http(301, f"https://cdn.{d}/", "CloudFront"), http(200, server="AmazonS3"),
                         cert(AMZ, "AWS", "2027-05-01T00:00:00+00:00", WILD)),
        f"lb.{d}": host(res(["192.0.2.120"], chain=["demo-nlb-0123456789abcdef.elb.us-east-1.amazonaws.com"]),
                        http(404, server="envoy"), http(404, server="envoy"),
                        cert(AMZ, "AWS", "2027-05-01T00:00:00+00:00", WILD)),
        f"shop.{d}": host(res(["198.51.100.200", "198.51.100.201"], chain=[f"shop.{d}.cdn.cloudflare.net"]),
                          http(301, f"https://shop.{d}/", "cloudflare"), http(200, server="cloudflare"),
                          cert(LE, "Let's Encrypt", "2026-12-30T00:00:00+00:00", [f"shop.{d}"])),
        f"docs.{d}": host(res(chain=["missing-docs-site.herokuapp.com"], status="NXDOMAIN"),
                          down("no address"), down("no address"), {"ok": False, "error": "not resolvable"}),
        f"ftp.{d}": host(res(["192.0.2.10"], chain=[d]), http(301, f"https://www.{d}/"), http(301, f"https://www.{d}/"),
                         cert(GTS, "Google", "2027-03-01T00:00:00+00:00", WILD), tcp21={"open": False, "error": "timeout"}),
    }
    google = ("396982", "GOOGLE-CLOUD-PLATFORM - Google LLC, US", "Google LLC", "GOOGLE-CLOUD")
    amazon = ("16509", "AMAZON-02 - Amazon.com, Inc., US", "Amazon Technologies Inc.", "AMAZON-IAD")
    ips = {
        "192.0.2.10": ip(*google, "192.0.2.0/24", GCP("global"), ["10.2.0.192.bc.googleusercontent.com"]),
        "198.51.100.20": ip(*google, "198.51.100.0/24", GCP("us-central1"), ["20.100.51.198.bc.googleusercontent.com"]),
        "198.51.100.30": ip(*google, "198.51.100.0/24", GCP("europe-west1"), ["30.100.51.198.bc.googleusercontent.com"]),
        "198.51.100.40": ip(*google, "198.51.100.0/24", GCP("global"), ["40.100.51.198.bc.googleusercontent.com"]),
        "203.0.113.60": ip(*google, "203.0.113.0/24", GCP("us-east1"), ["60.113.0.203.bc.googleusercontent.com"]),
        "203.0.113.50": ip("64500", "EXAMPLE-HOSTING - Example Hosting Ltd, US", "Example Hosting Ltd", "EXH-NET",
                           "203.0.113.0/24", None, ["vm50.hosting.example"], up=True, ports=False),
        "203.0.113.99": ip(*google, "203.0.113.0/24", GCP("us-central1"), [], up=False, ports=False),
        "192.0.2.101": ip(*amazon, "192.0.2.0/24", AWS("CLOUDFRONT", "GLOBAL"), ["server-192-0-2-101.example.r.cloudfront.net"]),
        "192.0.2.102": ip(*amazon, "192.0.2.0/24", AWS("CLOUDFRONT", "GLOBAL"), ["server-192-0-2-102.example.r.cloudfront.net"]),
        "192.0.2.120": ip(*amazon, "192.0.2.0/24", AWS("EC2", "us-east-1"), ["ec2-192-0-2-120.compute-1.amazonaws.com"], up=False),
        "198.51.100.200": ip("13335", "CLOUDFLARENET - Cloudflare, Inc., US", "Cloudflare, Inc.", "CLOUDFLARENET", "198.51.100.0/24", CF),
        "198.51.100.201": ip("13335", "CLOUDFLARENET - Cloudflare, Inc., US", "Cloudflare, Inc.", "CLOUDFLARENET", "198.51.100.0/24", CF),
        "2001:db8:10::20": ip(*google, "2001:db8::/32", GCP("global"), [], v6=True),
    }
    return {
        "schema_version": 1, "tool_version": "demo", "input_file": f"{DOMAIN}.txt",
        "scan_started": SCAN_TIME, "scan_finished": "2026-10-06T09:01:30+00:00", "scan_local_stamp": "demo",
        "scanner": {"hostname": "demo", "ipv6": False}, "cloud_ranges_loaded": {},
        "domain": DOMAIN, "exported": zone["exported"], "records": zone["records"],
        "domain_info": {"source": "synthetic demo data", "expiration": "2026-12-25T00:00:00Z",
                        "registration": "2015-01-15T00:00:00Z", "registrar": "Example Registrar, Inc.",
                        "status": ["client transfer prohibited"], "dnssec": False,
                        "nameservers": ["ns1.dns-provider.example", "ns2.dns-provider.example"]},
        "live_ns": {"status": "OK", "values": ["ns1.dns-provider.example", "ns2.dns-provider.example"]},
        "authoritative": {"server": "ns1.dns-provider.example"}, "auth_answers": {},
        "hosts": hosts,
        "targets": {"missing-docs-site.herokuapp.com": {"status": "NXDOMAIN"}, "aspmx.l.google.com": {"status": "OK"},
                    "d111111abcdef8.cloudfront.net": {"status": "OK"}, f"shop.{d}.cdn.cloudflare.net": {"status": "OK"},
                    "demo-nlb-0123456789abcdef.elb.us-east-1.amazonaws.com": {"status": "OK"}},
        "target_txt": {"_fedcba9876543210fedcba9876543210.abcdefghij.acm-validations.aws": {"status": "OK", "values": ["x"]}},
        "dkim": {}, "ips": ips,
        "mail": {"spf": {"domain": d, "status": "OK", "lookups": 1, "total_lookups": 1, "record": "v=spf1 include:_spf.google.com ~all",
                         "children": [{"domain": "_spf.google.com", "status": "OK", "lookups": 0, "children": []}]},
                 "dmarc": {"status": "OK"}, "mx": {}},
        "remote_ipv6": {"service": "globalping.io"},
        "errors": [],
    }


# -- screenshots ---------------------------------------------------------------------------

# (file, h2 ids to keep, window width, extra CSS)
SHOTS = [
    ("overview.png", ["summary", "action-items"], 1400, ""),
    ("web-records.png", ["web-records-a-aaaa-cname"], 1600, ""),
    ("ip-details.png", ["ip-address-details"], 1600, ""),
    ("txt-records.png", ["txt-records"], 1600, ""),
]


def find_browser() -> str | None:
    for c in [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Google\Chrome\Application\chrome.exe"]:
        if Path(c).exists():
            return c
    return shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("msedge")


def screenshots(page: Path, out_dir: Path):
    from PIL import Image, ImageChops

    browser = find_browser()
    if not browser:
        sys.exit("No Edge/Chrome found for screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)
    html = page.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        for name, keep, width, css in SHOTS:
            # keep the title block + chosen sections only, so no scrolling is needed
            script = """<script>
(function(){var keep=%s, main=document.querySelector('main'), on=true, header=true;
 Array.prototype.slice.call(main.children).forEach(function(el){
   if(el.tagName==='H2'){header=false; on=keep.indexOf(el.id)!==-1;}
   var isTitle=el.tagName==='H1'||el.classList.contains('toolbar');
   var isHead=header&&keep.indexOf('summary')!==-1;
   if(!(on&&!header)&&!isTitle&&!isHead) el.style.display='none';
 });})();
</script><style>%s</style></body>""" % (json.dumps(keep), css)
            variant = Path(tmp) / f"{name}.html"
            variant.write_text(html.replace("</body>", script), encoding="utf-8")
            raw = Path(tmp) / name
            subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                            "--force-device-scale-factor=1", f"--window-size={width},4000",
                            f"--screenshot={raw}", variant.as_uri()], capture_output=True, timeout=60)
            img = Image.open(raw).convert("RGB")
            bbox = ImageChops.difference(img, Image.new("RGB", img.size, (255, 255, 255))).getbbox()
            if bbox:
                img = img.crop((0, 0, img.width, min(img.height, bbox[3] + 16)))
            img.save(out_dir / name, optimize=True)
            print(f"  -> {out_dir / name} ({img.width}x{img.height})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--screenshots", action="store_true")
    a = ap.parse_args()
    demo_dir = ROOT / "docs" / "demo"
    demo_dir.mkdir(parents=True, exist_ok=True)
    scan = build_scan()
    base = f"{DOMAIN}.txt.demo"
    (demo_dir / f"{DOMAIN}.txt").write_text(ZONE, encoding="utf-8")
    (demo_dir / f"{base}.json").write_text(json.dumps(scan, indent=1), encoding="utf-8")
    md = report.render(scan)
    (demo_dir / f"{base}.md").write_text(md, encoding="utf-8")
    page = demo_dir / f"{base}.html"
    page.write_text(html_report.render(scan, md), encoding="utf-8")
    print(f"  -> {demo_dir / base}.json/.md/.html")
    if a.screenshots:
        screenshots(page, ROOT / "docs" / "screenshots")


if __name__ == "__main__":
    main()
