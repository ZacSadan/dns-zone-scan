"""Static knowledge: what common DNS record patterns mean and whether they can be removed.

`removable` vocabulary used everywhere:
  "Yes"     - safe to delete based on the evidence
  "Likely"  - probably safe, verify with the owner first
  "Review"  - needs a human check in the relevant console
  "No"      - in use / required
  "-"       - not applicable
"""

from __future__ import annotations

import re

# --- TXT verification tokens -----------------------------------------------------------
# (regex on the TXT value, purpose, insight, default removable)
TXT_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"^v=spf1\b", "SPF - authorised mail senders", "", "No"),
    (r"^v=DMARC1\b", "DMARC policy", "", "No"),
    (r"^v=DKIM1\b|^k=rsa;|\bp=MI", "DKIM public key", "", "No"),
    (r"^v=BIMI1\b", "BIMI brand logo", "", "No"),
    (r"^v=STSv1\b", "MTA-STS policy id", "", "No"),
    (r"^v=TLSRPTv1\b", "SMTP TLS reporting", "", "No"),
    (r"^google-site-verification=",
     "Google site verification (Search Console / Workspace / GCS domain-named buckets / Cloud domain mapping)",
     "Google re-checks ownership periodically, so removing an *active* token un-verifies the property. "
     "Keep the active ones; delete the tokens no longer listed under Search Console > Settings > Ownership "
     "verification (or Google Admin > Domains).", "Review"),
    (r"^_?globalsign-domain-verification=",
     "GlobalSign CA domain-control validation (one-time, at certificate order)",
     "Only needed while GlobalSign validates an order. After issuance it can be removed (GlobalSign "
     "re-validates via a new token at renewal).", "Yes"),
    (r"^globalsign-smime-dv=", "GlobalSign S/MIME domain validation", "One-time validation; removable after issuance.", "Yes"),
    (r"^vpce:",
     "AWS VPC Endpoint Service (PrivateLink) private-DNS-name ownership verification",
     "AWS needs it until the endpoint service's private DNS name shows **verified**. Match the token against "
     "`aws ec2 describe-vpc-endpoint-service-configurations --query "
     "\"ServiceConfigurations[].PrivateDnsNameConfiguration\"` (in every region used). Tokens that no current "
     "endpoint service lists are leftovers and can be deleted.", "Review"),
    (r"^MS=ms\d+", "Microsoft 365 / Azure AD domain verification", "Needed only during tenant domain verification; removable after it is verified.", "Likely"),
    (r"^facebook-domain-verification=", "Meta (Facebook) Business domain verification", "Meta re-checks it, so keep it while the Business Manager uses the domain.", "Review"),
    (r"^apple-domain-verification=", "Apple domain verification", "Keep while the Apple service (Sign in with Apple / Business) is used.", "Review"),
    (r"^atlassian-domain-verification=", "Atlassian domain verification", "Keep while Atlassian claims the domain (managed accounts).", "Review"),
    (r"^adobe-idp-site-verification=", "Adobe IdP / Admin Console domain verification", "Keep while Adobe SSO is used.", "Review"),
    (r"^docusign=", "DocuSign domain verification", "Keep while DocuSign claims the domain.", "Review"),
    (r"^stripe-verification=", "Stripe domain verification", "Usually one-time.", "Likely"),
    (r"^ZOOM_verify_", "Zoom domain verification", "Keep while Zoom managed domain is used.", "Review"),
    (r"^slack-domain-verification=", "Slack domain verification", "Keep while Slack uses it.", "Review"),
    (r"^dropbox-domain-verification=", "Dropbox domain verification", "Keep while Dropbox Business uses it.", "Review"),
    (r"^hubspot-developer-verification=|^hubspot", "HubSpot domain verification", "", "Review"),
    (r"^openai-domain-verification=", "OpenAI domain verification", "", "Review"),
    (r"^miro-verification=", "Miro domain verification", "", "Review"),
    (r"^postman-domain-verification=", "Postman domain verification", "", "Review"),
    (r"^mongodb-site-verification=", "MongoDB Atlas domain verification", "", "Review"),
    (r"^yandex-verification:", "Yandex webmaster verification", "", "Review"),
    (r"^have-i-been-pwned-verification=", "Have I Been Pwned domain search verification", "One-time; removable.", "Yes"),
    (r"^knowbe4-site-verification=", "KnowBe4 domain verification", "", "Review"),
    (r"^onetrust-domain-verification=", "OneTrust domain verification", "", "Review"),
    (r"^cisco-ci-domain-verification=|^webexdomainverification", "Cisco / Webex domain verification", "", "Review"),
    (r"^teamviewer-sso-verification=", "TeamViewer SSO verification", "", "Review"),
    (r"^status-page-domain-verification=", "Atlassian Statuspage verification", "", "Review"),
    (r"^brevo-code:|^sendinblue-code:", "Brevo (Sendinblue) domain verification", "", "Review"),
    (r"^pardot\d*[:=]|^pardot_", "Salesforce Pardot domain verification", "", "Review"),
    (r"^amazonses:", "Amazon SES domain verification (legacy)", "", "Review"),
    (r"^_github-challenge|^github-verification", "GitHub organisation domain verification", "", "Review"),
]

TXT_NAME_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"^cloudflare-verify$", "Cloudflare partial (CNAME) setup zone-ownership verification",
     "Cloudflare uses it to verify the zone when DNS stays at the registrar (CNAME setup).", "No"),
    (r"^_dmarc$", "DMARC policy", "", "No"),
    (r"\._domainkey$|^_domainkey$", "DKIM public key", "", "No"),
    (r"^_mta-sts$", "MTA-STS policy id", "", "No"),
    (r"^_smtp\._tls$", "SMTP TLS reporting", "", "No"),
    (r"^_amazonses$", "Amazon SES domain verification", "", "Review"),
    (r"^_github-challenge", "GitHub organisation domain verification", "", "Review"),
    (r"^_acme-challenge", "ACME DNS-01 challenge (Let's Encrypt/other)", "Only needed during issuance unless delegated; stale tokens can be removed.", "Likely"),
]

# --- CNAME targets -------------------------------------------------------------------------
# (regex on the target, purpose, default insight)
CNAME_TARGETS: list[tuple[str, str]] = [
    (r"\.acm-validations\.aws$", "AWS Certificate Manager (ACM) DNS validation"),
    (r"\.authorize\.certificatemanager\.goog$", "Google Certificate Manager DNS authorization"),
    (r"^_domainconnect\.gd\.domaincontrol\.com$", "GoDaddy Domain Connect (registrar default)"),
    (r"\.elb\.[a-z0-9-]+\.amazonaws\.com$", "AWS Elastic Load Balancer"),
    (r"\.cloudfront\.net$", "AWS CloudFront distribution"),
    (r"\.cdn\.cloudflare\.net$", "Cloudflare proxied hostname (partial / CNAME setup)"),
    (r"^ghs\.google\.com$|^ghs\.googlehosted\.com$", "Google hosted (Blogger / Google Sites / App Engine custom domain)"),
    (r"\.readmessl\.com$|\.readme\.io$", "ReadMe.com hosted documentation"),
    (r"^email\.secureserver\.net$", "GoDaddy Workspace webmail shortcut"),
    (r"\.onsecureserver\.net$|\.dkim\..*secureserver", "GoDaddy (Microsoft/Workspace) DKIM key"),
    (r"\.s3[.-]", "AWS S3 bucket website"),
    (r"\.azurewebsites\.net$|\.cloudapp\.|\.trafficmanager\.net$|\.azureedge\.net$", "Azure hosted endpoint"),
    (r"\.herokuapp\.com$|\.herokudns\.com$", "Heroku app"),
    (r"\.github\.io$", "GitHub Pages"),
    (r"\.netlify\.app$|\.netlify\.com$", "Netlify site"),
    (r"\.vercel-dns\.com$|\.vercel\.app$", "Vercel site"),
    (r"\.zendesk\.com$", "Zendesk help centre"),
    (r"\.hubspot", "HubSpot hosted pages"),
    (r"\.mktoweb\.com$|\.mktossl\.com$", "Marketo landing pages"),
    (r"\.statuspage\.io$", "Atlassian Statuspage"),
]

# Providers where a CNAME pointing at an unclaimed resource can be taken over by anyone.
TAKEOVER_PRONE = [
    r"\.cloudfront\.net$", r"\.s3[.-]", r"\.azurewebsites\.net$", r"\.cloudapp\.", r"\.trafficmanager\.net$",
    r"\.azureedge\.net$", r"\.herokuapp\.com$", r"\.herokudns\.com$", r"\.github\.io$", r"\.readmessl\.com$",
    r"\.readme\.io$", r"^ghs\.google\.com$", r"^ghs\.googlehosted\.com$", r"\.netlify\.", r"\.zendesk\.com$",
    r"\.statuspage\.io$", r"\.elasticbeanstalk\.com$", r"\.ghost\.io$", r"\.myshopify\.com$", r"\.wpengine\.com$",
    r"\.pantheonsite\.io$", r"\.fastly\.net$", r"\.unbouncepages\.com$", r"\.surge\.sh$", r"\.bitbucket\.io$",
]

# --- Mail ------------------------------------------------------------------------------
MX_PROVIDERS = [
    (r"(^|\.)aspmx\.l\.google\.com$|\.googlemail\.com$|^smtp\.google\.com$", "Google Workspace"),
    (r"\.mail\.protection\.outlook\.com$", "Microsoft 365"),
    (r"\.secureserver\.net$", "GoDaddy email (Workspace Email / Microsoft 365 via GoDaddy)"),
    (r"\.pphosted\.com$", "Proofpoint"),
    (r"\.mimecast\.com$", "Mimecast"),
    (r"\.zoho\.", "Zoho Mail"),
    (r"\.mailgun\.org$", "Mailgun"),
    (r"amazonaws\.com$", "Amazon SES / WorkMail"),
]

SPF_INCLUDES = [
    (r"^_spf\.google\.com$", "Google Workspace"),
    (r"^spf\.protection\.outlook\.com$", "Microsoft 365"),
    (r"mktomail\.com$", "Marketo"),
    (r"pardot\.com$", "Salesforce Pardot (Account Engagement)"),
    (r"^_spf\.salesforce\.com$", "Salesforce"),
    (r"zendesk\.com$", "Zendesk"),
    (r"secureserver\.net$", "GoDaddy email"),
    (r"sendgrid\.net$", "SendGrid"),
    (r"mailgun\.org$", "Mailgun"),
    (r"amazonses\.com$", "Amazon SES"),
    (r"servers\.mcsv\.net$", "Mailchimp"),
    (r"hubspotemail\.net$|hubspot", "HubSpot"),
    (r"freshdesk\.com$", "Freshdesk"),
    (r"zoho\.", "Zoho"),
]

# Name fragments that suggest a record was temporary / non-production.
TEMP_NAME_HINTS = ["todelete", "to-delete", "delete", "test", "tmp", "temp", "old", "deprecated", "legacy",
                   "poc", "demo", "backup", "bak", "latency"]
NONPROD_NAME_HINTS = ["staging", "stage", "dev", "qa", "preview", "sandbox"]


def first_match(table, text: str):
    for row in table:
        if re.search(row[0], text, re.IGNORECASE):
            return row
    return None


def name_hints(rel_name: str) -> tuple[list[str], list[str]]:
    labels = re.split(r"[.\-_]", rel_name.lower())
    joined = rel_name.lower()
    temp = [h for h in TEMP_NAME_HINTS if h in labels or (len(h) > 4 and h in joined)]
    nonprod = [h for h in NONPROD_NAME_HINTS if h in labels or any(lbl.startswith(h) and lbl[len(h):].isdigit() for lbl in labels)]
    return temp, nonprod


def is_takeover_prone(target: str) -> bool:
    return any(re.search(p, target, re.IGNORECASE) for p in TAKEOVER_PRONE)
