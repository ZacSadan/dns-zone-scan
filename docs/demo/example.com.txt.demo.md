# DNS zone report - example.com

|  |  |
|---|---|
| **Domain expiry** | 🟠 <span style="color:darkorange">**2026-12-25 (79 days left)**</span> |
| Registrar | Example Registrar, Inc. |
| Registered | 2015-01-15 |
| Registry status | client transfer prohibited |
| DNSSEC | not signed |
| Nameservers (registry) | ns1.dns-provider.example, ns2.dns-provider.example |
| Nameservers (live) | ns1.dns-provider.example, ns2.dns-provider.example |
| Zone file | `example.com.txt` (exported 2026-10-06 08:55:00) |
| Records | 28 |
| Scan time (UTC) | 2026-10-06 09:00:00 → 09:01:30 |
| Registry data source | synthetic demo data |

> ℹ️ The scanner host has no IPv6 connectivity: the zone's IPv6 addresses and AAAA names were tested remotely through globalping.io probes (ping + HTTP/HTTPS over IPv6), marked *(remote)*.

## Summary

Records by type: **SOA** 1, **NS** 2, **A** 8, **AAAA** 1, **CNAME** 7, **MX** 1, **TXT** 8

- 🔴 critical findings: **1**  ·  🟠 warnings: **6**
- Removable: 🗑️ Yes **3**  ·  🗑️ Likely **2**  ·  🔍 Review **5**

## Action items

### 🔴 Security (dangling records / takeover risk)

- `docs` CNAME -> `missing-docs-site.herokuapp.com` is dangling (NXDOMAIN) - delete

### 🗑️ Delete candidates

- `legacy-vm` - ping only, no web service, name says `legacy`
- `old-test-todelete` (A 203.0.113.99) - nothing answering, name says `todelete, delete, test, old`
- `ftp` - legacy default record, FTP (21) closed

### 🧹 Cleanup (stale verification / validation records)

- `@` TXT GlobalSign verification token(s) - one-time CA validation, removable
- `@` has 2 google-site-verification tokens - prune unused (check Search Console / Google Admin)
- 1 AWS PrivateLink `vpce:` TXT tokens - keep only those matching a current endpoint service

### ✉️ Mail authentication

- No DKIM selector records in the zone (may live elsewhere if signing via a provider default)

### 🔍 Needs owner review

- `staging` - ports open but HTTP/HTTPS broken (TLS error)
- `@` TXT `a1b2c3d4e5` - unidentified token, find owner or remove

### ℹ️ Informational

- `api` managed certificate (Google Trust Services) expires in 44 days - auto-renewal expected
- `app` certificate (GoDaddy.com, Inc.) expires in 74 days - plan renewal
- Domain registration expires 2026-12-25 (79 days) - renewal due soon
- DNSSEC not enabled at the registry

## Web records (A / AAAA / CNAME)

ICMP = ping replies / IPs tested · HTTP/HTTPS = status of `GET /` (no redirects followed) · Cert = certificate served on 443 with SNI = the record name.

| Name | Type | Zone value | Resolves to (live) | ICMP | HTTP | HTTPS | ASN | Cloud | Reverse DNS | Certificate issuer | Cert expiry | Insights / action | Removable? |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `@` | A | `192.0.2.10` | `192.0.2.10` | ✅ 1/1 | 301 → https://www.example.com/ | 301 → https://www.example.com/ | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (global)**</span> | `10.2.0.192.bc.googleusercontent.com` | <span style="color:#1E64D4">**Google Trust Services (Google)**</span> | 2027-03-01 (145d) | ✅ Active | No |
| `*.preview` | A | `198.51.100.40` | `198.51.100.40` | ✅ 1/1 | 301 | 404 (nginx) | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (global)**</span> | `40.100.51.198.bc.googleusercontent.com` | <span style="color:#1E64D4">**Google Trust Services (Google)**</span> | 2026-12-28 (82d) | 🔵 Wildcard - probed with random name `zscan-probe-1a2b3c.preview.example.com`<br>🔵 Non-production name (`preview`)<br>🔵 HTTPS answers 404 at `/` - API-only, or LB with no matching route<br>🔵 Certificate expires in 82 days - managed/ACME issuer, auto-renewal expected | No |
| `api` | A | `198.51.100.20` | `198.51.100.20` | ✅ 1/1 | 301 → https://api.example.com/ | 404 | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (us-central1)**</span> | `20.100.51.198.bc.googleusercontent.com` | <span style="color:#1E64D4">**Google Trust Services (Google)**</span> | 🔴 <span style="color:red">**2026-11-20 (44d)**</span> | 🔵 HTTPS answers 404 at `/` - API-only, or LB with no matching route<br>🔵 Certificate expires in 44 days - managed/ACME issuer, normally auto-renews ~30 days before expiry (re-check if still unrenewed in 2 weeks) | No |
| `app` | A | `198.51.100.30` | `198.51.100.30` | ✅ 1/1 | 301 → https://app.example.com/ | 200 (nginx) | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (europe-west1)**</span> | `30.100.51.198.bc.googleusercontent.com` | GoDaddy.com, Inc. (GoDaddy) | 🟠 <span style="color:darkorange">**2026-12-20 (74d)**</span> | 🔵 Certificate expires in 74 days - plan the renewal | No |
| `legacy-vm` | A | `203.0.113.50` | `203.0.113.50` | ✅ 1/1 | ❌ connect timeout | ❌ connect timeout | AS64500 EXAMPLE-HOSTING - Example Hos… | not cloud | `vm50.hosting.example` | none (timeout) |  | 🟠 Answers ICMP only - nothing on TCP 80/443 (non-web service, or idle VM) | 🗑️ Likely |
| `old-test-todelete` | A | `203.0.113.99` | `203.0.113.99` | ❌ 0/1 | ❌ connect timeout | ❌ connect timeout | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (us-central1)**</span> |  | none (timeout) |  | 🟠 **Nothing answers** (no ICMP, no TCP 80/443, no HTTP/HTTPS) - candidate for deletion; name contains `todelete, delete, test, old` | 🗑️ Yes |
| `staging` | A | `203.0.113.60` | `203.0.113.60` | ✅ 1/1 | ❌ connection error | ❌ TLS error | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (us-east1)**</span> | `60.113.0.203.bc.googleusercontent.com` | none (SSLEOFError) |  | 🟠 TCP 80/443 open but HTTP/HTTPS fails (connection error / TLS error) - LB/frontend without a working backend, or no certificate for this name<br>🔵 Non-production name (`staging`) | 🔍 Review |
| `www` | A | `192.0.2.10` | `192.0.2.10` | ✅ 1/1 | 301 → https://www.example.com/ | 200 (Google Frontend) | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (global)**</span> | `10.2.0.192.bc.googleusercontent.com` | <span style="color:#1E64D4">**Google Trust Services (Google)**</span> | 2027-03-01 (145d) | ✅ Active | No |
| `api` | AAAA | `2001:db8:10::20` | `2001:db8:10::20` | ✅ 1/1 (remote) | 301 → https://api.example.com/ (IPv6, remote) | 404 (IPv6, remote) | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (global)**</span> |  | <span style="color:#1E64D4">**Google Trust Services (Google)**</span> | 🔴 <span style="color:red">**2026-11-20 (44d)**</span> | 🔵 IPv6 tested remotely via Globalping probes (Frankfurt DE (Example Net), Singapore SG (Example Net)) - ping and HTTP/HTTPS over IPv6; certificate shown is from the IPv4 path<br>🔵 HTTPS answers 404 at `/` - API-only, or LB with no matching route<br>🔵 Certificate expires in 44 days - managed/ACME issuer, normally auto-renews ~30 days before expiry (re-check if still unrenewed in 2 weeks) | No |
| `cdn`<br>*AWS CloudFront distribution* | CNAME | `d111111abcdef8.cloudfront.net` | `192.0.2.101`<br>`192.0.2.102` | ✅ 2/2 | 301 → https://cdn.example.com/ (CloudFront) | 200 (AmazonS3) | AS16509 AMAZON-02 - Amazon.com, Inc.,… | ☁️ <span style="color:#FB54FF">**AWS - CLOUDFRONT (GLOBAL)**</span> | `server-192-0-2-101.example.r.cloudfront.net` | <span style="color:#FB54FF">**Amazon (AWS)**</span> | 2027-05-01 (206d) | ✅ Active | No |
| `docs`<br>*Heroku app* | CNAME | `missing-docs-site.herokuapp.com` | ❌ NXDOMAIN |  | ❌ no address | ❌ no address |  |  |  | none (not resolvable) |  | 🔴 **Dangling CNAME**: target `missing-docs-site.herokuapp.com` does not exist (NXDOMAIN) - provider allows re-claiming the name, **subdomain-takeover risk**. Delete the record. | 🗑️ Yes |
| `ftp`<br>*Alias of the apex (example.com)* | CNAME | `example.com` | `192.0.2.10` | ✅ 1/1 | 301 → https://www.example.com/ | 301 → https://www.example.com/ | AS396982 GOOGLE-CLOUD-PLATFORM - Googl… | ☁️ <span style="color:#1E64D4">**Google Cloud (global)**</span> | `10.2.0.192.bc.googleusercontent.com` | <span style="color:#1E64D4">**Google Trust Services (Google)**</span> | 2027-03-01 (145d) | 🔵 Registrar-default `ftp` record; FTP port 21 is closed | 🗑️ Likely |
| `lb`<br>*AWS Elastic Load Balancer* | CNAME | `demo-nlb-0123456789abcdef.elb.us-east-1.amazonaws…` | `192.0.2.120` | ❌ 0/1 | 404 (envoy) | 404 (envoy) | AS16509 AMAZON-02 - Amazon.com, Inc.,… | ☁️ <span style="color:#FB54FF">**AWS - EC2 (us-east-1)**</span> | `ec2-192-0-2-120.compute-1.amazonaws.com` | <span style="color:#FB54FF">**Amazon (AWS)**</span> | 2027-05-01 (206d) | 🔵 HTTPS answers 404 at `/` - API-only, or LB with no matching route | No |
| `shop`<br>*Cloudflare proxied hostname (partial / CNAME setup)* | CNAME | `shop.example.com.cdn.cloudflare.net` | `198.51.100.200`<br>`198.51.100.201` | ✅ 2/2 | 301 → https://shop.example.com/ (cloudflare) | 200 (cloudflare) | AS13335 CLOUDFLARENET - Cloudflare, I… | ☁️ <span style="color:#FE5E1F">**Cloudflare - CDN/Proxy**</span> |  | <span style="color:#FE5E1F">**Let's Encrypt (Let's Encrypt)**</span> | 2026-12-30 (84d) | 🔵 Certificate expires in 84 days - managed/ACME issuer, auto-renewal expected | No |

## IP address details

Whois = RDAP registration of the IP block. Cloud = match against the provider's published IP ranges (AWS, GCP, Google, Cloudflare, DigitalOcean), else ASN.

| IP | ICMP | TCP | ASN | ASN name | Whois org | Net name | Net CIDR | Country | Cloud / service | Reverse DNS (PTR) | Used by |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `198.51.100.40` | ✅ 4ms | 80✅ 443✅ | AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | Google LLC | GOOGLE-CLOUD | 198.51.100.0/24 | US | <span style="color:#1E64D4">**Google Cloud (global)**</span> | `40.100.51.198.bc.googleusercontent.com` | `*.preview` |
| `192.0.2.10` | ✅ 4ms | 80✅ 443✅ | AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | Google LLC | GOOGLE-CLOUD | 192.0.2.0/24 | US | <span style="color:#1E64D4">**Google Cloud (global)**</span> | `10.2.0.192.bc.googleusercontent.com` | `@`, `ftp`, `www` |
| `198.51.100.20` | ✅ 4ms | 80✅ 443✅ | AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | Google LLC | GOOGLE-CLOUD | 198.51.100.0/24 | US | <span style="color:#1E64D4">**Google Cloud (us-central1)**</span> | `20.100.51.198.bc.googleusercontent.com` | `api` |
| `2001:db8:10::20` | ✅ 4ms (remote) | n/a | AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | Google LLC | GOOGLE-CLOUD | 2001:db8::/32 | US | <span style="color:#1E64D4">**Google Cloud (global)**</span> | NXDOMAIN | `api` |
| `198.51.100.30` | ✅ 4ms | 80✅ 443✅ | AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | Google LLC | GOOGLE-CLOUD | 198.51.100.0/24 | US | <span style="color:#1E64D4">**Google Cloud (europe-west1)**</span> | `30.100.51.198.bc.googleusercontent.com` | `app` |
| `192.0.2.101` | ✅ 4ms | 80✅ 443✅ | AS16509 | AMAZON-02 - Amazon.com, Inc., US | Amazon Technologies Inc. | AMAZON-IAD | 192.0.2.0/24 | US | <span style="color:#FB54FF">**AWS - CLOUDFRONT (GLOBAL)**</span> | `server-192-0-2-101.example.r.cloudfront.net` | `cdn` |
| `192.0.2.102` | ✅ 4ms | 80✅ 443✅ | AS16509 | AMAZON-02 - Amazon.com, Inc., US | Amazon Technologies Inc. | AMAZON-IAD | 192.0.2.0/24 | US | <span style="color:#FB54FF">**AWS - CLOUDFRONT (GLOBAL)**</span> | `server-192-0-2-102.example.r.cloudfront.net` | `cdn` |
| `192.0.2.120` | ❌ | 80✅ 443✅ | AS16509 | AMAZON-02 - Amazon.com, Inc., US | Amazon Technologies Inc. | AMAZON-IAD | 192.0.2.0/24 | US | <span style="color:#FB54FF">**AWS - EC2 (us-east-1)**</span> | `ec2-192-0-2-120.compute-1.amazonaws.com` | `lb` |
| `203.0.113.50` | ✅ 4ms | 80❌ 443❌ | AS64500 | EXAMPLE-HOSTING - Example Hosting Ltd, US | Example Hosting Ltd | EXH-NET | 203.0.113.0/24 | US | not cloud | `vm50.hosting.example` | `legacy-vm` |
| `203.0.113.99` | ❌ | 80❌ 443❌ | AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | Google LLC | GOOGLE-CLOUD | 203.0.113.0/24 | US | <span style="color:#1E64D4">**Google Cloud (us-central1)**</span> | NXDOMAIN | `old-test-todelete` |
| `198.51.100.200` | ✅ 4ms | 80✅ 443✅ | AS13335 | CLOUDFLARENET - Cloudflare, Inc., US | Cloudflare, Inc. | CLOUDFLARENET | 198.51.100.0/24 | US | <span style="color:#FE5E1F">**Cloudflare - CDN/Proxy**</span> | NXDOMAIN | `shop` |
| `198.51.100.201` | ✅ 4ms | 80✅ 443✅ | AS13335 | CLOUDFLARENET - Cloudflare, Inc., US | Cloudflare, Inc. | CLOUDFLARENET | 198.51.100.0/24 | US | <span style="color:#FE5E1F">**Cloudflare - CDN/Proxy**</span> | NXDOMAIN | `shop` |
| `203.0.113.60` | ✅ 4ms | 80✅ 443✅ | AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC, US | Google LLC | GOOGLE-CLOUD | 203.0.113.0/24 | US | <span style="color:#1E64D4">**Google Cloud (us-east1)**</span> | `60.113.0.203.bc.googleusercontent.com` | `staging` |

## Certificate validation & service records (underscore CNAMEs)

| Name | Type | Value | Purpose | Insights / action | Removable? |
|---|---|---|---|---|---|
| `_0123456789abcdef0123456789abcdef` | CNAME | `_fedcba9876543210fedcba9876543210.abcdefghij.acm-validations.aws` | AWS Certificate Manager (ACM) DNS validation | 🔵 Validates ACM certificates for `example.com` / `*.example.com`. ACM re-checks it for **automatic renewal**, so it must stay while the ACM certificate exists.<br>🔵 AWS still serves the validation target<br>✅ In use: `cdn`, `lb` serve(s) an Amazon certificate for this name | No |
| `_acme-challenge` | CNAME | `00000000-1111-2222-3333-444444444444.1.authorize.certificatemanager.g…` | Google Certificate Manager DNS authorization | 🔵 DNS authorization for Google-managed certificates covering `example.com` / `*.example.com` (Certificate Manager). Google needs it for every renewal.<br>✅ In use: `@`, `www`, `ftp` serve(s) a Google Trust Services certificate for this name | No |

## TXT records

| Name | Type | Value | Purpose | Insights / action | Removable? |
|---|---|---|---|---|---|
| `@` | TXT | `_globalsign-domain-verification=EXAMPLE-globalsign-token` | GlobalSign CA domain-control validation (one-time, at certificate order) | 🔵 Only needed while GlobalSign validates an order. After issuance it can be removed (GlobalSign re-validates via a new token at renewal).<br>✅ No host serves a GlobalSign certificate - validation is over | 🗑️ Yes |
| `@` | TXT | `a1b2c3d4e5` | Unidentified verification token | 🟠 Unknown TXT (bare token, no vendor prefix). Usually a one-time SaaS/CA ownership check. Ask owners; if nobody claims it, remove it. | 🔍 Review |
| `@` | TXT | `google-site-verification=EXAMPLE-token-one` | Google site verification (Search Console / Workspace / GCS domain-named buckets / Cloud domain mapping) | 🔵 Google re-checks ownership periodically, so removing an *active* token un-verifies the property. Keep the active ones; delete the tokens no longer listed under Search Console > Settings > Ownership verification (or Google Admin > Domains).<br>🟠 2 Google verification tokens on this name - usually left by different people/properties over time; prune the ones not in Search Console | 🔍 Review |
| `@` | TXT | `google-site-verification=EXAMPLE-token-two` | Google site verification (Search Console / Workspace / GCS domain-named buckets / Cloud domain mapping) | 🔵 Same pattern as above - see first occurrence | 🔍 Review |
| `@` | TXT | `v=spf1 include:_spf.google.com ~all` | SPF - authorised mail senders | 🔵 Senders: _spf.google.com (Google Workspace)<br>✅ 1/10 DNS lookups used<br>🔵 `~all` softfail - with DMARC p=reject this is fine; `-all` is stricter<br>🔵 Review whether every listed sender (marketing/support tools) is still in use | No |
| `_abcdefghij0123456789` | TXT | `vpce:EXAMPLEvpceToken01` | AWS VPC Endpoint Service (PrivateLink) private-DNS-name ownership verification | 🔵 AWS needs it until the endpoint service's private DNS name shows **verified**. Match the token against `aws ec2 describe-vpc-endpoint-service-configurations --query "ServiceConfigurations[].PrivateDnsNameConfiguration"` (in every region used). Tokens that no current endpoint service lists are leftovers and can be deleted. | 🔍 Review |
| `_dmarc` | TXT | `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com` | DMARC policy | 🟠 Policy p=quarantine<br>🔵 Aggregate reports -> mailto:dmarc-reports@example.com | No |
| `cloudflare-verify` | TXT | `123456789-987654321` | Cloudflare partial (CNAME) setup zone-ownership verification | ✅ Cloudflare CNAME setup in use (1 hostnames point to cdn.cloudflare.net) - keep | No |

## Mail (MX)

| Name | Type | Value | Purpose | Insights / action | Removable? |
|---|---|---|---|---|---|
| `@` | MX | `1 aspmx.l.google.com` | Mail exchanger - Google Workspace | ✅ MX host resolves<br>🔵 Legacy 5-record Google MX set - still valid; Google now also supports a single `smtp.google.com` MX (optional) | No |

## Delegation (NS / SOA)

| Name | Type | Value | Purpose | Insights / action | Removable? |
|---|---|---|---|---|---|
| `@` | SOA | `ns1.dns-provider.example. hostmaster.example.com. 2026100601 28800 72…` | Start of authority |  | No |
| `@` | NS | `ns1.dns-provider.example` | Nameserver | ✅ Matches registry delegation | No |
| `@` | NS | `ns2.dns-provider.example` | Nameserver | ✅ Matches registry delegation | No |

---

### Method & legend

- 🔴 critical · 🟠 warning · 🔵 info · ✅ OK. Expiry dates are marked 🔴 <span style="color:red">**red**</span> when less than 60 days away (or already passed) and 🟠 <span style="color:darkorange">**orange**</span> when less than 90 days away, relative to the scan time.
- **Removable?** 🗑️ Yes = evidence says safe to delete · 🗑️ Likely = probably unused, confirm with owner · 🔍 Review = check in the relevant console · No = in use / required.
- DNS: public resolvers (8.8.8.8, 1.1.1.1) for live resolution; the zone's authoritative server (`ns1.dns-provider.example`) to compare the export against what is served now.
- Wildcard records are probed via a random label under the wildcard.
- Whois/ASN via RDAP (ipwhois); domain expiry via registry RDAP (IANA bootstrap) with WHOIS fallback.
- Certificates fetched with SNI and read even when untrusted/expired; trust and name-match evaluated separately.
- dns-zone-scan demo · schema 1 · scanner `demo`
