"""Offline tests: synthetic zone data only (no real zones in this public repo, no network)."""

import datetime as dt
import json
from pathlib import Path

from dns_zone_scan import insights, knowledge, report
from dns_zone_scan.__main__ import do_report, latest_scans
from dns_zone_scan.certs import hostname_matches, issuer_provider
from dns_zone_scan.parser import parse_zone_text
from dns_zone_scan.scan import is_service_name, probe_name_for

ZONE = """; Domain: example.test
; Exported (y-m-d hh:mm:ss): 2026-01-02 03:04:05
$ORIGIN example.test.
@	3600	IN	SOA	ns1.example.net. hostmaster.example.net. ( 2026010101 28800 7200 604800 3600 )
@	3600	IN	NS	ns1.example.net.
@	3600	IN	A	192.0.2.10
www	3600	IN	A	192.0.2.10
old-test-todelete	3600	IN	A	192.0.2.99
*.wild	3600	IN	A	192.0.2.10
ftp	3600	IN	CNAME	@
gone	3600	IN	CNAME	missing-thing.cloudfront.net.
_abc.api	3600	IN	CNAME	_def.xyz.acm-validations.aws.
@	3600	IN	MX	10 mail.example.net.
@	3600	IN	TXT	"_globalsign-domain-verification=AAA"
@	3600	IN	TXT	"google-site-verification=one"
@	3600	IN	TXT	"google-site-verification=two"
_x1	3600	IN	TXT	"vpce:abc"
@	3600	IN	TXT	"v=spf1 include:_spf.google.com ~all"
key._domainkey	3600	IN	TXT	"v=DKIM1; k=rsa; " "p=MIIB"
@	3600	IN	TXT	"Z0000000"
"""

REF = "2026-01-02T10:00:00+00:00"


def parsed():
    return parse_zone_text(ZONE)


def test_parser_basics():
    z = parsed()
    assert z["domain"] == "example.test"
    assert z["exported"] == "2026-01-02 03:04:05"
    by = {(r["name"], r["type"], r.get("text") or r.get("target") or r.get("address")) for r in z["records"]}
    assert ("ftp", "CNAME", "example.test") in by
    assert ("*.wild", "A", "192.0.2.10") in by
    # multi-string TXT is joined
    assert ("key._domainkey", "TXT", "v=DKIM1; k=rsa; p=MIIB") in by
    assert [r["id"] for r in z["records"]] == list(range(len(z["records"])))


def test_helpers():
    assert is_service_name("_acme-challenge.s2s")
    assert is_service_name("key._domainkey")
    assert not is_service_name("www")
    assert probe_name_for("*.s2s.example.test").endswith(".s2s.example.test")
    assert not probe_name_for("*.s2s.example.test").startswith("*")
    assert hostname_matches("a.example.test", ["*.example.test"])
    assert not hostname_matches("a.b.example.test", ["*.example.test"])
    assert issuer_provider("Google Trust Services", "WR3")["provider"] == "Google"
    assert issuer_provider("Amazon", "Amazon RSA 2048 M02")["provider"] == "AWS"
    temp, nonprod = knowledge.name_hints("latency-test-todelete")
    assert "todelete" in temp and "test" in temp
    assert knowledge.name_hints("js-staging2")[1] == ["staging"]


def test_red_date_threshold():
    ref = dt.datetime.fromisoformat(REF)
    assert insights.is_red_date("2026-02-01T00:00:00Z", ref)          # 29 days
    assert insights.is_red_date("2025-12-01T00:00:00Z", ref)          # passed
    assert not insights.is_red_date("2026-06-01T00:00:00Z", ref)      # ~5 months
    assert "color:red" in report.date_cell("2026-02-01T00:00:00Z", ref)
    assert "EXPIRED" in report.date_cell("2025-12-01T00:00:00Z", ref)
    assert "color:red" not in report.date_cell("2026-06-01T00:00:00Z", ref)
    # 60..89 days -> orange, >= 90 -> unmarked
    assert insights.is_orange_date("2026-03-15T00:00:00Z", ref)            # 71 days
    assert "color:darkorange" in report.date_cell("2026-03-15T00:00:00Z", ref)
    assert not insights.is_orange_date("2026-02-01T00:00:00Z", ref)        # red, not orange
    assert "color:" not in report.date_cell("2026-06-01T00:00:00Z", ref)


def fake_scan():
    z = parsed()
    dead = {"responded": False, "error": "connect timeout"}
    ok_http = {"responded": True, "status": 200, "server": "nginx"}
    cert = {"ok": True, "issuer_org": "Let's Encrypt", "issuer_provider": "Let's Encrypt", "subject_cn": "example.test",
            "sans": ["example.test", "*.example.test"], "not_after": "2026-01-20T00:00:00+00:00",
            "trusted": True, "hostname_match": True}
    hosts = {
        "example.test": {"resolve": {"status": "OK", "a": ["192.0.2.10"], "aaaa": [], "cname_chain": []},
                         "http": ok_http, "https": ok_http, "cert": cert},
        "www.example.test": {"resolve": {"status": "OK", "a": ["192.0.2.10"], "aaaa": [], "cname_chain": []},
                             "http": ok_http, "https": ok_http, "cert": cert},
        "old-test-todelete.example.test": {"resolve": {"status": "OK", "a": ["192.0.2.99"], "aaaa": [], "cname_chain": []},
                                           "http": dead, "https": dead, "cert": {"ok": False, "error": "timeout"}},
        "*.wild.example.test": {"probe_name": "zscan-probe-x.wild.example.test", "wildcard": True,
                                "resolve": {"status": "OK", "a": ["192.0.2.10"], "aaaa": [], "cname_chain": []},
                                "http": ok_http, "https": ok_http, "cert": cert},
        "ftp.example.test": {"resolve": {"status": "OK", "a": ["192.0.2.10"], "aaaa": [], "cname_chain": ["example.test"]},
                             "http": ok_http, "https": ok_http, "cert": cert, "tcp21": {"open": False, "error": "timeout"}},
        "gone.example.test": {"resolve": {"status": "NXDOMAIN", "a": [], "aaaa": [], "cname_chain": ["missing-thing.cloudfront.net"],
                                          "cname_final_status": "NXDOMAIN"},
                              "http": dead, "https": dead, "cert": {"ok": False, "error": "not resolvable"}},
    }
    ip = lambda up: {"icmp": {"reply": up}, "tcp80": {"open": up}, "tcp443": {"open": up}, "ptr": {"values": []},
                     "cloud": None, "rdap": {"status": "OK", "summary": {"asn": "64500"}}}
    return {
        "schema_version": 1, "tool_version": "test", "input_file": "example.test.txt",
        "scan_started": REF, "scan_finished": REF, "scan_local_stamp": "20260102_1000",
        "scanner": {"ipv6": False, "hostname": "t"}, "cloud_ranges_loaded": {},
        "domain": z["domain"], "exported": z["exported"], "records": z["records"],
        "domain_info": {"status": "OK", "expiration": "2026-02-15T00:00:00Z", "registrar": "Example Registrar",
                        "nameservers": ["ns1.example.net"], "dnssec": False},
        "live_ns": {"values": ["ns1.example.net"]}, "authoritative": {"server": "ns1.example.net"},
        "auth_answers": {}, "hosts": hosts,
        "targets": {"missing-thing.cloudfront.net": {"status": "NXDOMAIN"}, "mail.example.net": {"status": "OK"}},
        "target_txt": {"_def.xyz.acm-validations.aws": {"status": "OK", "values": ["x"]}},
        "dkim": {}, "ips": {"192.0.2.10": ip(True), "192.0.2.99": ip(False)},
        "mail": {"spf": {"domain": "example.test", "status": "OK", "lookups": 1, "total_lookups": 1,
                         "children": [{"domain": "_spf.google.com", "status": "OK", "children": [], "lookups": 0}]},
                 "dmarc": {"status": "NXDOMAIN"}, "mx": {}},
        "errors": [],
    }


def rec(scan, name, rtype, contains=""):
    for r in scan["records"]:
        if r["name"] == name and r["type"] == rtype and contains in (r.get("text") or r["value"]):
            return r
    raise KeyError(name)


def test_insights_rules():
    scan = fake_scan()
    a = insights.analyze(scan)
    per = a["records"]
    assert per[rec(scan, "old-test-todelete", "A")["id"]]["removable"] == "Yes"
    assert per[rec(scan, "gone", "CNAME")["id"]]["removable"] == "Yes"
    assert any("takeover" in t for _, t in per[rec(scan, "gone", "CNAME")["id"]]["insights"])
    assert per[rec(scan, "www", "A")["id"]]["removable"] == "No"
    assert per[rec(scan, "ftp", "CNAME")["id"]]["removable"] == "Likely"
    assert per[rec(scan, "@", "TXT", "globalsign")["id"]]["removable"] == "Yes"
    assert per[rec(scan, "@", "TXT", "google-site")["id"]]["removable"] == "Review"
    assert per[rec(scan, "_x1", "TXT")["id"]]["removable"] == "Review"
    assert per[rec(scan, "@", "TXT", "Z0000000")["id"]]["purpose"] == "Unidentified verification token"
    acm = per[rec(scan, "_abc.api", "CNAME")["id"]]
    assert "ACM" in acm["purpose"]
    assert acm["removable"] == "Review"  # no host serves an Amazon cert for api.example.test
    acts = a["actions"]
    assert any("No DMARC" in x for x in acts["mail"])
    assert any("expires" in x for x in acts["domain"])
    assert any("gone" in x for x in acts["security"])


def test_report_render_and_regenerate(tmp_path: Path):
    scan = fake_scan()
    p = tmp_path / "example.test.txt.20260102_1000.json"
    p.write_text(json.dumps(scan), encoding="utf-8")
    assert latest_scans(tmp_path) == [p]
    out1 = do_report([p])[0]
    assert out1.name == "example.test.txt.20260102_1000.md"
    md = out1.read_text(encoding="utf-8")
    assert md.startswith("# DNS zone report - example.test")
    # domain expiry is < 60 days -> red, and it is in the header before any table of records
    head = md.split("## Summary")[0]
    assert "Domain expiry" in head and "color:red" in head
    for section in ("## Action items", "## Web records", "## IP address details", "## TXT records"):
        assert section in md
    # deterministic: regenerating from the same JSON gives the same output
    assert do_report([p])[0].read_text(encoding="utf-8") == md
    # HTML twin with the same content
    page = (tmp_path / "example.test.txt.20260102_1000.html").read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>")
    assert "<title>DNS zone report - example.test</title>" in page
    assert '<div class="tw wide"><table>' in page and 'id="action-items"' in page
    assert "color:red" in page and "old-test-todelete" in page


def test_remote_result_parsing():
    from dns_zone_scan import remote

    probe = {"city": "Berlin", "country": "DE", "network": "Example"}
    ping = remote._ping_summary({"status": "finished", "results": [
        {"probe": probe, "result": {"status": "finished", "stats": {"rcv": 0, "loss": 100, "avg": None}}},
        {"probe": probe, "result": {"status": "finished", "stats": {"rcv": 3, "loss": 0, "avg": 5.2}}}]})
    assert ping["reply"] is True and ping["rtt_ms"] == 5.2 and ping["via"] == "globalping"
    dead = remote._ping_summary({"status": "finished", "results": [
        {"probe": probe, "result": {"stats": {"rcv": 0, "loss": 100}}}]})
    assert dead["reply"] is False
    http = remote._http_summary({"results": [{"probe": probe, "result": {
        "statusCode": 301, "headers": {"Location": "https://x.example.test/", "Server": "nginx"}}}]}, "http://x/")
    assert http["responded"] and http["status"] == 301 and http["location"] == "https://x.example.test/"
    fail = remote._http_summary({"results": [{"probe": probe, "result": {
        "status": "failed", "rawOutput": "Request timed out"}}]}, "https://x/")
    assert not fail["responded"] and "timed out" in fail["error"]


def test_cloud_colors():
    gcp = report.cloud_cell({"cloud": {"provider": "Google Cloud", "service": "Google Cloud", "region": "global"}})
    assert "color:#1E64D4" in gcp and "Google Cloud (global)" in gcp
    assert "color:#FB54FF" in report.cloud_cell({"cloud": {"provider": "AWS", "service": "EC2", "region": "us-east-1"}})
    assert "color:#FE5E1F" in report.cloud_cell({"cloud": None, "asn_provider": "Cloudflare"})
    assert report.cloud_cell({"cloud": {"provider": "DigitalOcean", "service": "Droplet/LB", "region": None}}).startswith("DigitalOcean")
    assert report.cloud_cell({"cloud": None, "asn_provider": None}) == "not cloud"


def test_issuer_colors():
    assert "color:#FB54FF" in report.issuer_cell({"issuer_org": "Amazon", "issuer_provider": "AWS"})
    assert "color:#FE5E1F" in report.issuer_cell({"issuer_org": "Let's Encrypt", "issuer_provider": "Let's Encrypt"})
    assert "color:#1E64D4" in report.issuer_cell({"issuer_org": "Google Trust Services", "issuer_provider": "Google"})
    assert "color" not in report.issuer_cell({"issuer_org": "GoDaddy.com, Inc.", "issuer_provider": "GoDaddy"})


def test_no_orange_for_auto_renew_issuers():
    ref = dt.datetime.fromisoformat(REF)
    in_71_days, in_29_days = "2026-03-15T00:00:00Z", "2026-02-01T00:00:00Z"
    assert "color:darkorange" not in report.date_cell(in_71_days, ref, orange_ok=False)
    assert "color:red" in report.date_cell(in_29_days, ref, orange_ok=False)   # red still applies
    assert "color:darkorange" in report.date_cell(in_71_days, ref)


def test_expandable_lists():
    assert report.expandable(["a", "b"], 3) == "`a`, `b`"
    cell = report.expandable([f"n{i}" for i in range(12)], 8)
    assert cell.startswith("`n0`") and '<summary>+4 more</summary>' in cell
    assert "<code>n11</code>" in cell and "+4 more" in cell


def test_scanned_values_cannot_inject_html():
    evil = '<img src=x onerror="alert(1)">'
    assert "<img" not in report.esc(evil)
    assert "<img" not in report.code(evil) and report.code(evil).startswith("<code>")
    assert "<img" not in report.code("a`" + evil)  # a backtick must not end the code span early
    assert report.code("plain.example.test") == "`plain.example.test`"
    assert "<img" not in report.http_cell({"responded": True, "status": 200, "server": evil})


def test_spf_same_include_twice_is_not_a_loop(monkeypatch):
    from dns_zone_scan import resolve, scan

    txt = {"example.test": "v=spf1 include:a.test include:b.test -all",
           "a.test": "v=spf1 include:shared.test -all", "b.test": "v=spf1 include:shared.test -all",
           "shared.test": "v=spf1 ip4:192.0.2.1 -all", "loop.test": "v=spf1 include:loop.test -all"}
    monkeypatch.setattr(resolve, "query", lambda _r, name, _t: {"status": "OK", "values": [txt[name]]})
    tree = scan.spf_expand(None, "example.test")
    assert [g["status"] for c in tree["children"] for g in c["children"]] == ["OK", "OK"]
    assert scan.spf_total_lookups(tree) == 4
    assert scan.spf_expand(None, "loop.test")["children"][0]["status"] == "LOOP"
