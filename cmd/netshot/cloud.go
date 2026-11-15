package main

// Cloud and SaaS footprint of the scanned organisation (passive, no key):
//  1. Microsoft 365 / Entra ID tenant: OpenID configuration (tenant ID, region), getuserrealm
//     (managed or federated, identity provider), Autodiscover (other domains of the tenant).
//     Google Workspace from the MX records.
//  2. SaaS, PaaS and IaaS recognised from the TXT (verification tokens), SPF includes, MX, NS and the
//     CNAME of the scanned names and of a few standard names (autodiscover, enterpriseregistration…).
//  3. Public IPs mapped to AWS, Azure, Google Cloud and Cloudflare (service, region) with the ranges
//     those providers publish (cached 7 days).
//  4. Dangling CNAMEs: the subdomain takeover check (recon.go) runs with this footprint too.
//  5. Report section, cloud.csv, "Cloud et SaaS" sheet, "cloud" in results.json.
//
// Domains of the tenant and the federation host of the organisation are added to the scan (all
// ports); its SaaS tenant pages (SharePoint, Okta…) are added on 443 only: one https page, as a
// browser would load it. -no-cloud-targets keeps the footprint without adding anything.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type CloudTenant struct {
	Provider string   `json:"provider"` // "Microsoft 365 / Entra ID", "Google Workspace"
	Domain   string   `json:"domain"`   // domain looked up
	TenantID string   `json:"tenant_id,omitempty"`
	Name     string   `json:"name,omitempty"`   // xxx of xxx.onmicrosoft.com
	Region   string   `json:"region,omitempty"` // EU, NA, WW…
	Auth     string   `json:"auth,omitempty"`   // "gérée (Entra ID)", "fédérée"
	IdP      string   `json:"idp,omitempty"`    // federation URL host
	Brand    string   `json:"brand,omitempty"`
	Domains  []string `json:"domains,omitempty"` // other domains of the tenant
}

type CloudService struct {
	Service  string `json:"service"`
	Category string `json:"category"`
	Source   string `json:"source"`   // TXT, SPF, MX, NS, CNAME, takeover
	Host     string `json:"host"`     // name the record belongs to
	Evidence string `json:"evidence"` // the record or CNAME target
}

type CloudIP struct {
	IP       string   `json:"ip"`
	Provider string   `json:"provider"`
	Service  string   `json:"service,omitempty"`
	Region   string   `json:"region,omitempty"`
	Prefix   string   `json:"prefix"`
	Hosts    []string `json:"hosts,omitempty"`
}

type CloudReport struct {
	Domains  []string       `json:"domains"`
	Tenants  []CloudTenant  `json:"tenants,omitempty"`
	Services []CloudService `json:"services,omitempty"`
	IPs      []CloudIP      `json:"ips,omitempty"`
	Added    []string       `json:"added,omitempty"`       // hosts added to the scan ("host" or "host (443)")
	Own      []string       `json:"org_domains,omitempty"` // registrable domains of the organisation (scanned + tenant)
	Errors   []string       `json:"errors,omitempty"`
}

// --- Signatures --------------------------------------------------------------------------------

type cloudSig struct {
	source, match, service, category string
}

// cloudSigs: match is a lowercase substring (TXT: prefix of the record).
var cloudSigs = []cloudSig{
	// TXT verification tokens
	{"TXT", "ms=", "Microsoft 365", "Messagerie / collaboration"},
	{"TXT", "google-site-verification=", "Google (Search Console / Workspace)", "Vérification"},
	{"TXT", "atlassian-domain-verification=", "Atlassian Cloud", "Développement / tickets"},
	{"TXT", "docusign=", "DocuSign", "Signature électronique"},
	{"TXT", "facebook-domain-verification=", "Meta (Facebook)", "Marketing"},
	{"TXT", "workplace-domain-verification=", "Meta Workplace", "Collaboration"},
	{"TXT", "adobe-idp-site-verification=", "Adobe (SSO)", "Bureautique"},
	{"TXT", "adobe-sign-verification=", "Adobe Acrobat Sign", "Signature électronique"},
	{"TXT", "apple-domain-verification=", "Apple Business", "Gestion des appareils"},
	{"TXT", "zoom_verify_", "Zoom", "Visioconférence"},
	{"TXT", "slack-domain-verification=", "Slack", "Collaboration"},
	{"TXT", "dropbox-domain-verification=", "Dropbox", "Stockage"},
	{"TXT", "box-domain-verification=", "Box", "Stockage"},
	{"TXT", "stripe-verification=", "Stripe", "Paiement"},
	{"TXT", "hubspot-developer-verification=", "HubSpot", "CRM / marketing"},
	{"TXT", "hubspot-site-verification=", "HubSpot", "CRM / marketing"},
	{"TXT", "pardot", "Salesforce Pardot", "CRM / marketing"},
	{"TXT", "cisco-ci-domain-verification=", "Cisco Webex", "Visioconférence"},
	{"TXT", "webexdomainverification", "Cisco Webex", "Visioconférence"},
	{"TXT", "teamviewer-sso-verification=", "TeamViewer", "Accès distant"},
	{"TXT", "logmein-verification-code=", "GoTo (LogMeIn)", "Accès distant"},
	{"TXT", "citrix-verification-code=", "Citrix Cloud", "Accès distant"},
	{"TXT", "miro-verification=", "Miro", "Collaboration"},
	{"TXT", "onetrust-domain-verification=", "OneTrust", "Conformité"},
	{"TXT", "knowbe4-site-verification=", "KnowBe4", "Sensibilisation"},
	{"TXT", "globalsign-domain-verification=", "GlobalSign", "Certificats"},
	{"TXT", "mongodb-site-verification=", "MongoDB Atlas", "Base de données"},
	{"TXT", "status-page-domain-verification=", "Atlassian Statuspage", "Supervision"},
	{"TXT", "brevo-code:", "Brevo", "E-mailing"},
	{"TXT", "sendinblue-code:", "Brevo (Sendinblue)", "E-mailing"},
	{"TXT", "zoho-verification=", "Zoho", "Bureautique"},
	{"TXT", "lastpass-verification-code=", "LastPass", "Mots de passe"},
	{"TXT", "openai-domain-verification=", "OpenAI", "IA"},
	{"TXT", "anthropic-domain-verification", "Anthropic", "IA"},
	{"TXT", "canva-site-verification=", "Canva", "Bureautique"},
	{"TXT", "heroku-domain-verification=", "Heroku", "PaaS"},
	{"TXT", "jamf-site-verification=", "Jamf", "Gestion des appareils"},
	{"TXT", "airtable-verification=", "Airtable", "Bureautique"},
	{"TXT", "smartsheet-site-validation=", "Smartsheet", "Bureautique"},
	{"TXT", "yandex-verification:", "Yandex", "Vérification"},
	{"TXT", "amazonses:", "AWS SES", "E-mailing"},
	// SPF includes
	{"SPF", "spf.protection.outlook.com", "Microsoft 365 (Exchange Online)", "Messagerie / collaboration"},
	{"SPF", "_spf.google.com", "Google Workspace", "Messagerie / collaboration"},
	{"SPF", "_spf.salesforce.com", "Salesforce", "CRM / marketing"},
	{"SPF", "sendgrid.net", "SendGrid", "E-mailing"},
	{"SPF", "servers.mcsv.net", "Mailchimp", "E-mailing"},
	{"SPF", "mail.zendesk.com", "Zendesk", "Support"},
	{"SPF", "hubspotemail.net", "HubSpot", "CRM / marketing"},
	{"SPF", "amazonses.com", "AWS SES", "E-mailing"},
	{"SPF", "mailgun.org", "Mailgun", "E-mailing"},
	{"SPF", "spf.mandrillapp.com", "Mailchimp Transactional", "E-mailing"},
	{"SPF", "sendinblue.com", "Brevo", "E-mailing"},
	{"SPF", "spf.brevo.com", "Brevo", "E-mailing"},
	{"SPF", "mailjet.com", "Mailjet", "E-mailing"},
	{"SPF", "mtasv.net", "Postmark", "E-mailing"},
	{"SPF", "sparkpostmail.com", "SparkPost", "E-mailing"},
	{"SPF", "mlsend.com", "MailerLite", "E-mailing"},
	{"SPF", "elasticemail.com", "Elastic Email", "E-mailing"},
	{"SPF", "smtp2go.com", "SMTP2GO", "E-mailing"},
	{"SPF", "freshdesk.com", "Freshdesk", "Support"},
	{"SPF", "atlassian.net", "Atlassian Cloud", "Développement / tickets"},
	{"SPF", "mktomail.com", "Marketo", "CRM / marketing"},
	{"SPF", "service-now.com", "ServiceNow", "Support"},
	{"SPF", "pphosted.com", "Proofpoint", "Sécurité e-mail"},
	{"SPF", "mimecast", "Mimecast", "Sécurité e-mail"},
	{"SPF", "messagelabs.com", "Broadcom Email Security", "Sécurité e-mail"},
	{"SPF", "zoho.", "Zoho Mail", "Messagerie / collaboration"},
	{"SPF", "mx.ovh.com", "OVHcloud (e-mail)", "Messagerie / collaboration"},
	{"SPF", "ionos.", "IONOS", "Messagerie / collaboration"},
	{"SPF", "_spf.docusign.", "DocuSign", "Signature électronique"},
	// MX
	{"MX", "mail.protection.outlook.com", "Microsoft 365 (Exchange Online)", "Messagerie / collaboration"},
	{"MX", "google.com", "Google Workspace", "Messagerie / collaboration"},
	{"MX", "googlemail.com", "Google Workspace", "Messagerie / collaboration"},
	{"MX", "pphosted.com", "Proofpoint", "Sécurité e-mail"},
	{"MX", "mimecast.com", "Mimecast", "Sécurité e-mail"},
	{"MX", "messagelabs.com", "Broadcom Email Security", "Sécurité e-mail"},
	{"MX", "barracudanetworks.com", "Barracuda Email Protection", "Sécurité e-mail"},
	{"MX", "iphmx.com", "Cisco Secure Email", "Sécurité e-mail"},
	{"MX", "trendmicro", "Trend Micro Email Security", "Sécurité e-mail"},
	{"MX", "sophos.com", "Sophos Email", "Sécurité e-mail"},
	{"MX", "vadesecure.com", "Vade (Hornetsecurity)", "Sécurité e-mail"},
	{"MX", "hornetsecurity.com", "Hornetsecurity", "Sécurité e-mail"},
	{"MX", "mailinblack.com", "Mailinblack", "Sécurité e-mail"},
	{"MX", "altospam.com", "Altospam", "Sécurité e-mail"},
	{"MX", "mail.ovh.net", "OVHcloud (e-mail)", "Messagerie / collaboration"},
	{"MX", "zoho.", "Zoho Mail", "Messagerie / collaboration"},
	{"MX", "secureserver.net", "GoDaddy (e-mail)", "Messagerie / collaboration"},
	{"MX", "ionos.", "IONOS (e-mail)", "Messagerie / collaboration"},
	{"MX", "gandi.net", "Gandi (e-mail)", "Messagerie / collaboration"},
	// NS
	{"NS", ".awsdns-", "AWS Route 53", "DNS"},
	{"NS", "azure-dns.", "Azure DNS", "DNS"},
	{"NS", ".ns.cloudflare.com", "Cloudflare DNS", "DNS"},
	{"NS", "googledomains.com", "Google Cloud DNS", "DNS"},
	{"NS", "ns-cloud-", "Google Cloud DNS", "DNS"},
	{"NS", ".ovh.net", "OVHcloud DNS", "DNS"},
	{"NS", "gandi.net", "Gandi DNS", "DNS"},
	{"NS", "ui-dns.", "IONOS DNS", "DNS"},
	// CNAME targets
	{"CNAME", ".azurewebsites.net", "Azure App Service", "PaaS"},
	{"CNAME", ".azurestaticapps.net", "Azure Static Web Apps", "PaaS"},
	{"CNAME", ".cloudapp.azure.com", "Azure (machine virtuelle)", "IaaS"},
	{"CNAME", ".cloudapp.net", "Azure Cloud Service", "IaaS"},
	{"CNAME", ".blob.core.windows.net", "Azure Blob Storage", "Stockage"},
	{"CNAME", ".web.core.windows.net", "Azure Storage (site statique)", "Stockage"},
	{"CNAME", ".azurefd.net", "Azure Front Door", "CDN"},
	{"CNAME", ".azureedge.net", "Azure CDN", "CDN"},
	{"CNAME", ".trafficmanager.net", "Azure Traffic Manager", "PaaS"},
	{"CNAME", ".azure-api.net", "Azure API Management", "PaaS"},
	{"CNAME", ".sharepoint.com", "SharePoint Online", "Messagerie / collaboration"},
	{"CNAME", "autodiscover.outlook.com", "Microsoft 365 (Exchange Online)", "Messagerie / collaboration"},
	{"CNAME", "webdir.online.lync.com", "Microsoft Teams / Skype Entreprise", "Visioconférence"},
	{"CNAME", "sipdir.online.lync.com", "Microsoft Teams / Skype Entreprise", "Visioconférence"},
	{"CNAME", "enterpriseregistration.windows.net", "Entra ID (inscription des appareils)", "Identité"},
	{"CNAME", "manage.microsoft.com", "Microsoft Intune", "Gestion des appareils"},
	{"CNAME", ".s3.amazonaws.com", "AWS S3", "Stockage"},
	{"CNAME", ".s3-website", "AWS S3 (site statique)", "Stockage"},
	{"CNAME", ".elb.amazonaws.com", "AWS Elastic Load Balancing", "IaaS"},
	{"CNAME", ".compute.amazonaws.com", "AWS EC2", "IaaS"},
	{"CNAME", ".execute-api.", "AWS API Gateway", "PaaS"},
	{"CNAME", ".elasticbeanstalk.com", "AWS Elastic Beanstalk", "PaaS"},
	{"CNAME", ".cloudfront.net", "AWS CloudFront", "CDN"},
	{"CNAME", ".awsglobalaccelerator.com", "AWS Global Accelerator", "CDN"},
	{"CNAME", ".amplifyapp.com", "AWS Amplify", "PaaS"},
	{"CNAME", ".amazonaws.com", "AWS", "IaaS"},
	{"CNAME", ".appspot.com", "Google App Engine", "PaaS"},
	{"CNAME", ".run.app", "Google Cloud Run", "PaaS"},
	{"CNAME", ".web.app", "Firebase Hosting", "PaaS"},
	{"CNAME", ".firebaseapp.com", "Firebase Hosting", "PaaS"},
	{"CNAME", "storage.googleapis.com", "Google Cloud Storage", "Stockage"},
	{"CNAME", "ghs.googlehosted.com", "Google Sites / App Engine", "PaaS"},
	{"CNAME", ".cdn.cloudflare.net", "Cloudflare", "CDN"},
	{"CNAME", ".pages.dev", "Cloudflare Pages", "PaaS"},
	{"CNAME", ".workers.dev", "Cloudflare Workers", "PaaS"},
	{"CNAME", ".akamaiedge.net", "Akamai", "CDN"},
	{"CNAME", ".edgekey.net", "Akamai", "CDN"},
	{"CNAME", ".edgesuite.net", "Akamai", "CDN"},
	{"CNAME", ".fastly.net", "Fastly", "CDN"},
	{"CNAME", ".fastlylb.net", "Fastly", "CDN"},
	{"CNAME", ".incapdns.net", "Imperva", "CDN"},
	{"CNAME", ".sucuri.net", "Sucuri", "CDN"},
	{"CNAME", ".b-cdn.net", "Bunny CDN", "CDN"},
	{"CNAME", ".herokuapp.com", "Heroku", "PaaS"},
	{"CNAME", ".herokudns.com", "Heroku", "PaaS"},
	{"CNAME", "vercel-dns.com", "Vercel", "PaaS"},
	{"CNAME", ".vercel.app", "Vercel", "PaaS"},
	{"CNAME", ".netlify.app", "Netlify", "PaaS"},
	{"CNAME", ".github.io", "GitHub Pages", "PaaS"},
	{"CNAME", ".gitlab.io", "GitLab Pages", "PaaS"},
	{"CNAME", ".okta.com", "Okta", "Identité"},
	{"CNAME", ".okta-emea.com", "Okta", "Identité"},
	{"CNAME", ".oktapreview.com", "Okta", "Identité"},
	{"CNAME", ".onelogin.com", "OneLogin", "Identité"},
	{"CNAME", ".auth0.com", "Auth0", "Identité"},
	{"CNAME", ".pingone.", "Ping Identity", "Identité"},
	{"CNAME", ".atlassian.net", "Atlassian Cloud", "Développement / tickets"},
	{"CNAME", ".statuspage.io", "Atlassian Statuspage", "Supervision"},
	{"CNAME", ".zendesk.com", "Zendesk", "Support"},
	{"CNAME", ".freshdesk.com", "Freshdesk", "Support"},
	{"CNAME", ".freshservice.com", "Freshservice", "Support"},
	{"CNAME", ".service-now.com", "ServiceNow", "Support"},
	{"CNAME", ".force.com", "Salesforce", "CRM / marketing"},
	{"CNAME", ".salesforce.com", "Salesforce", "CRM / marketing"},
	{"CNAME", ".hubspot.net", "HubSpot", "CRM / marketing"},
	{"CNAME", ".hs-sites.com", "HubSpot", "CRM / marketing"},
	{"CNAME", ".mktoweb.com", "Marketo", "CRM / marketing"},
	{"CNAME", ".pardot.com", "Salesforce Pardot", "CRM / marketing"},
	{"CNAME", ".myshopify.com", "Shopify", "E-commerce"},
	{"CNAME", ".wpengine.com", "WP Engine", "Hébergement web"},
	{"CNAME", ".wordpress.com", "WordPress.com", "Hébergement web"},
	{"CNAME", ".webflow.io", "Webflow", "Hébergement web"},
	{"CNAME", "webflow.com", "Webflow", "Hébergement web"},
	{"CNAME", ".squarespace.com", "Squarespace", "Hébergement web"},
	{"CNAME", ".wixdns.net", "Wix", "Hébergement web"},
	{"CNAME", ".ghost.io", "Ghost", "Hébergement web"},
	{"CNAME", ".kinsta.cloud", "Kinsta", "Hébergement web"},
	{"CNAME", ".pantheonsite.io", "Pantheon", "Hébergement web"},
	{"CNAME", ".readthedocs.io", "Read the Docs", "Documentation"},
	{"CNAME", ".helpscoutdocs.com", "Help Scout", "Support"},
	{"CNAME", "intercom.help", "Intercom", "Support"},
	{"CNAME", ".sendgrid.net", "SendGrid", "E-mailing"},
	{"CNAME", ".docusign.net", "DocuSign", "Signature électronique"},
	{"CNAME", ".zoom.us", "Zoom", "Visioconférence"},
	{"CNAME", ".webex.com", "Cisco Webex", "Visioconférence"},
	{"CNAME", ".ovh.net", "OVHcloud", "Hébergement web"},
	{"CNAME", ".scw.cloud", "Scaleway", "IaaS"},
	{"CNAME", ".oraclecloud.com", "Oracle Cloud", "IaaS"},
	{"CNAME", ".ondigitalocean.app", "DigitalOcean App Platform", "PaaS"},
	{"CNAME", ".digitaloceanspaces.com", "DigitalOcean Spaces", "Stockage"},
}

// matchSig returns the first signature of source that value matches.
func matchSig(source, value string) (cloudSig, bool) {
	v := strings.ToLower(strings.Trim(value, `". `))
	for _, s := range cloudSigs {
		if s.source != source {
			continue
		}
		if source == "TXT" && strings.HasPrefix(v, s.match) || source != "TXT" && strings.Contains(v, s.match) {
			return s, true
		}
	}
	return cloudSig{}, false
}

var spfInclude = regexp.MustCompile(`(?i)\b(?:include|redirect|exists)[:=]([^\s"]+)`)

// recordServices recognises the services in the TXT, MX and NS records of domain.
func recordServices(domain string, recs []DNSRecord) []CloudService {
	var out []CloudService
	for _, r := range recs {
		data := strings.Trim(r.Data, `"`)
		switch r.Type {
		case "TXT":
			if strings.HasPrefix(strings.ToLower(data), "v=spf1") {
				for _, m := range spfInclude.FindAllStringSubmatch(data, -1) {
					if s, ok := matchSig("SPF", m[1]); ok {
						out = append(out, CloudService{s.service, s.category, "SPF", domain, m[1]})
					}
				}
				continue
			}
			if s, ok := matchSig("TXT", data); ok {
				ev := data
				if len(ev) > 70 {
					ev = ev[:70] + "…"
				}
				out = append(out, CloudService{s.service, s.category, "TXT", domain, ev})
			}
		case "MX", "NS":
			target := r.Data
			if f := strings.Fields(target); len(f) > 0 {
				target = f[len(f)-1]
			}
			if s, ok := matchSig(r.Type, target); ok {
				out = append(out, CloudService{s.service, s.category, r.Type, domain, strings.TrimSuffix(target, ".")})
			}
		}
	}
	return out
}

// --- Microsoft 365 / Entra ID ------------------------------------------------------------------

var cloudClient = &http.Client{Timeout: 15 * time.Second}

var (
	msLogin        = "https://login.microsoftonline.com"
	msAutodiscover = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
)

func cloudJSON(ctx context.Context, u string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cloudClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	return 200, json.Unmarshal(body, out)
}

var tenantGUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// microsoftTenant looks up the Entra ID tenant of domain; nil when there is none.
func microsoftTenant(ctx context.Context, domain string) (*CloudTenant, error) {
	var oidc struct {
		Issuer string `json:"issuer"`
		Region string `json:"tenant_region_scope"`
	}
	code, err := cloudJSON(ctx, msLogin+"/"+url.PathEscape(domain)+"/v2.0/.well-known/openid-configuration", &oidc)
	if err != nil {
		return nil, err
	}
	var realm struct {
		NameSpaceType string `json:"NameSpaceType"`
		Brand         string `json:"FederationBrandName"`
		AuthURL       string `json:"AuthURL"`
	}
	_, rerr := cloudJSON(ctx, msLogin+"/getuserrealm.srf?json=1&login="+url.QueryEscape("netshot@"+domain), &realm)
	if code != 200 && (rerr != nil || realm.NameSpaceType == "" || realm.NameSpaceType == "Unknown") {
		return nil, nil
	}
	t := &CloudTenant{Provider: "Microsoft 365 / Entra ID", Domain: domain, TenantID: tenantGUID.FindString(oidc.Issuer),
		Region: oidc.Region, Brand: realm.Brand}
	switch realm.NameSpaceType {
	case "Managed":
		t.Auth = "gérée (Entra ID)"
	case "Federated":
		t.Auth = "fédérée"
		if u, err := url.Parse(realm.AuthURL); err == nil {
			t.IdP = strings.ToLower(u.Hostname())
		}
	}
	t.Domains = autodiscoverDomains(ctx, domain)
	for _, d := range t.Domains {
		if strings.HasSuffix(d, ".onmicrosoft.com") && !strings.HasSuffix(d, ".mail.onmicrosoft.com") {
			t.Name = strings.TrimSuffix(d, ".onmicrosoft.com")
		}
	}
	return t, nil
}

const autodiscoverBody = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Header><a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo></soap:Header>
<soap:Body><GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>%s</Domain></Request></GetFederationInformationRequestMessage></soap:Body></soap:Envelope>`

// autodiscoverDomains lists the domains of the tenant that holds domain (Exchange Online
// GetFederationInformation). Microsoft may answer with fewer domains than the tenant has.
func autodiscoverDomains(ctx context.Context, domain string) []string {
	body := fmt.Sprintf(autodiscoverBody, html.EscapeString(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, msAutodiscover, strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"`)
	req.Header.Set("User-Agent", "AutodiscoverClient")
	resp, err := cloudClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return parseAutodiscover(raw)
}

func parseAutodiscover(raw []byte) []string {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var out []string
	inDomain := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			inDomain = t.Name.Local == "Domain"
		case xml.CharData:
			if d := strings.ToLower(strings.TrimSpace(string(t))); inDomain && d != "" && !containsStr(out, d) {
				out = append(out, d)
			}
		case xml.EndElement:
			inDomain = false
		}
	}
	sort.Strings(out)
	return out
}

// --- Provider IP ranges ------------------------------------------------------------------------

type ipRange struct {
	net               *net.IPNet
	provider, service string
	region            string
}

var (
	rangesOnce sync.Once
	rangesList []ipRange
)

// cachedFetch downloads u, kept for 7 days in the user cache; a stale copy is used when the
// download fails.
func cachedFetch(ctx context.Context, name, u string) ([]byte, error) {
	dir, _ := os.UserCacheDir()
	path := ""
	if dir != "" {
		path = filepath.Join(dir, "netshot", "cloud-ranges", name)
		if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < 7*24*time.Hour {
			return os.ReadFile(path)
		}
	}
	data, err := httpBody(ctx, u, 64<<20)
	if err != nil {
		if path != "" {
			if old, e := os.ReadFile(path); e == nil {
				return old, nil
			}
		}
		return nil, err
	}
	if path != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, data, 0o644)
	}
	return data, nil
}

func httpBody(ctx context.Context, u string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Netshot)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// the link may be JSON-escaped in the page ("https:\/\/download.microsoft.com\/download\/…")
var azureTagsURL = regexp.MustCompile(`https:(?:\\?/){2}download\.microsoft\.com(?:\\?/)download(?:\\?/)[^"'\s<>]+?ServiceTags_Public_\d+\.json`)

// loadRanges downloads (or reads from cache) the ranges of AWS, Azure, Google Cloud and Cloudflare.
func loadRanges(ctx context.Context, logf func(string, ...any)) []ipRange {
	rangesOnce.Do(func() {
		var out []ipRange
		add := func(prefix, provider, service, region string) {
			if _, n, err := net.ParseCIDR(strings.TrimSpace(prefix)); err == nil {
				out = append(out, ipRange{n, provider, service, region})
			}
		}
		if data, err := cachedFetch(ctx, "aws.json", "https://ip-ranges.amazonaws.com/ip-ranges.json"); err == nil {
			var raw struct {
				P4 []map[string]string `json:"prefixes"`
				P6 []map[string]string `json:"ipv6_prefixes"`
			}
			if json.Unmarshal(data, &raw) == nil {
				for _, p := range raw.P4 {
					add(p["ip_prefix"], "AWS", awsService(p["service"]), p["region"])
				}
				for _, p := range raw.P6 {
					add(p["ipv6_prefix"], "AWS", awsService(p["service"]), p["region"])
				}
			}
		} else {
			logf("[cloud] plages AWS indisponibles : %v", err)
		}
		if data, err := cachedFetch(ctx, "gcp.json", "https://www.gstatic.com/ipranges/cloud.json"); err == nil {
			var raw struct {
				Prefixes []map[string]string `json:"prefixes"`
			}
			if json.Unmarshal(data, &raw) == nil {
				for _, p := range raw.Prefixes {
					pre := p["ipv4Prefix"]
					if pre == "" {
						pre = p["ipv6Prefix"]
					}
					add(pre, "Google Cloud", "", p["scope"])
				}
			}
		} else {
			logf("[cloud] plages Google Cloud indisponibles : %v", err)
		}
		for _, v := range []string{"ips-v4", "ips-v6"} {
			if data, err := cachedFetch(ctx, "cloudflare-"+v+".txt", "https://www.cloudflare.com/"+v); err == nil {
				for _, l := range strings.Split(string(data), "\n") {
					add(l, "Cloudflare", "", "")
				}
			}
		}
		if data, err := azureRanges(ctx); err == nil {
			var raw struct {
				Values []struct {
					Name       string `json:"name"`
					Properties struct {
						Region         string   `json:"region"`
						SystemService  string   `json:"systemService"`
						AddressPrefixe []string `json:"addressPrefixes"`
					} `json:"properties"`
				} `json:"values"`
			}
			if json.Unmarshal(data, &raw) == nil {
				for _, v := range raw.Values {
					if v.Properties.SystemService == "" && !strings.HasPrefix(v.Name, "AzureCloud.") {
						continue // aggregates ("AzureCloud" without region, "AzureFrontDoor"…) add nothing
					}
					for _, p := range v.Properties.AddressPrefixe {
						add(p, "Azure", v.Properties.SystemService, v.Properties.Region)
					}
				}
			}
		} else {
			logf("[cloud] plages Azure indisponibles : %v", err)
		}
		rangesList = out
	})
	return rangesList
}

func azureRanges(ctx context.Context) ([]byte, error) {
	dir, _ := os.UserCacheDir()
	if dir != "" {
		path := filepath.Join(dir, "netshot", "cloud-ranges", "azure.json")
		if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < 7*24*time.Hour {
			return os.ReadFile(path)
		}
	}
	page, err := httpBody(ctx, "https://www.microsoft.com/en-us/download/details.aspx?id=56519", 4<<20)
	link := ""
	if err == nil {
		link = strings.ReplaceAll(azureTagsURL.FindString(string(page)), `\/`, "/")
	}
	if link == "" {
		if dir != "" {
			if old, e := os.ReadFile(filepath.Join(dir, "netshot", "cloud-ranges", "azure.json")); e == nil {
				return old, nil // stale copy
			}
		}
		if err == nil {
			err = fmt.Errorf("lien des Service Tags introuvable sur la page de téléchargement Microsoft")
		}
		return nil, err
	}
	return cachedFetch(ctx, "azure.json", link)
}

func awsService(s string) string {
	if s == "AMAZON" {
		return ""
	}
	return s
}

// matchRange returns the most specific range holding ip (a service-specific range wins a tie).
func matchRange(ranges []ipRange, ip net.IP) (ipRange, bool) {
	best, bestLen, found := ipRange{}, -1, false
	for _, r := range ranges {
		if !r.net.Contains(ip) {
			continue
		}
		l, _ := r.net.Mask.Size()
		if l > bestLen || l == bestLen && best.service == "" && r.service != "" {
			best, bestLen, found = r, l, true
		}
	}
	return best, found
}

// --- Discovery ---------------------------------------------------------------------------------

// internalTLDs are never looked up at the providers.
var internalTLDs = map[string]bool{"lan": true, "local": true, "localdomain": true, "internal": true, "intra": true,
	"intranet": true, "corp": true, "home": true, "test": true, "localhost": true, "invalid": true, "example": true}

// cloudDomains: the registrable domains of the scanned names, the most frequent first (max 5).
func cloudDomains(hosts []string) []string {
	count := map[string]int{}
	for _, h := range hosts {
		h = strings.ToLower(strings.Trim(h, "[]."))
		if net.ParseIP(h) != nil || !strings.Contains(h, ".") {
			continue
		}
		d := registrableDomain(h)
		if internalTLDs[d[strings.LastIndex(d, ".")+1:]] {
			continue
		}
		count[d]++
	}
	out := make([]string, 0, len(count))
	for d := range count {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if count[out[i]] != count[out[j]] {
			return count[out[i]] > count[out[j]]
		}
		return out[i] < out[j]
	})
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// standard names queried for their CNAME on each domain (Microsoft 365, Intune, Teams…).
var cloudProbeNames = []string{"autodiscover", "lyncdiscover", "sip", "enterpriseregistration", "enterpriseenrollment", "www"}

func dnsRecords(ctx context.Context, servers []string, name string, qtype uint16) []DNSRecord {
	for _, s := range servers {
		if recs, _, err := dnsQuery(ctx, s, name, qtype, 3*time.Second); err == nil {
			return recs
		}
	}
	return nil
}

// resolves tells whether name has an address (A or AAAA).
func resolves(ctx context.Context, name string) bool {
	lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lctx, name)
	return err == nil && len(addrs) > 0
}

// discoverCloud runs before the scan: tenants and services of the main domains, and the hosts to
// add to the scan (full: all ports; web: 443 only).
func discoverCloud(ctx context.Context, hosts []string, logf func(string, ...any)) (rep *CloudReport, full, web []string) {
	rep = &CloudReport{Domains: cloudDomains(hosts)}
	if len(rep.Domains) == 0 {
		return rep, nil, nil
	}
	logf("[cloud] empreinte cloud et SaaS de %s", strings.Join(rep.Domains, ", "))
	servers := takeoverServers()
	known := map[string]bool{}
	for _, h := range hosts {
		known[strings.ToLower(h)] = true
	}
	own := map[string]bool{} // registrable domains of the organisation
	for _, d := range rep.Domains {
		own[d] = true
	}
	addFull := func(h string) {
		if h = strings.ToLower(h); h != "" && !known[h] && resolves(ctx, h) {
			known[h] = true
			full = append(full, h)
			rep.Added = append(rep.Added, h)
		}
	}
	addWeb := func(h string) {
		if h = strings.ToLower(h); h != "" && !known[h] && resolves(ctx, h) {
			known[h] = true
			web = append(web, h)
			rep.Added = append(rep.Added, h+" (443)")
		}
	}
	seen := map[string]bool{}
	addService := func(s CloudService) {
		k := s.Service + "|" + s.Host + "|" + s.Source
		if !seen[k] {
			seen[k] = true
			rep.Services = append(rep.Services, s)
		}
	}
	for _, d := range rep.Domains {
		if ctx.Err() != nil {
			break
		}
		var recs []DNSRecord
		for _, t := range []uint16{15, 16, 2} { // MX, TXT, NS
			recs = append(recs, dnsRecords(ctx, servers, d, t)...)
		}
		google := false
		for _, s := range recordServices(d, recs) {
			addService(s)
			if s.Service == "Google Workspace" && s.Source == "MX" {
				google = true
			}
		}
		if google {
			rep.Tenants = append(rep.Tenants, CloudTenant{Provider: "Google Workspace", Domain: d, Auth: "messagerie Google (MX)"})
		}
		for _, p := range cloudProbeNames {
			name := p + "." + d
			chain, _ := cnameChain(ctx, name, servers)
			for _, c := range chain {
				if s, ok := matchSig("CNAME", c); ok {
					addService(CloudService{s.service, s.category, "CNAME", name, strings.TrimSuffix(c, ".")})
					break
				}
			}
		}
		t, err := microsoftTenant(ctx, d)
		if err != nil {
			rep.Errors = append(rep.Errors, d+" : "+err.Error())
			continue
		}
		if t == nil {
			continue
		}
		rep.Tenants = append(rep.Tenants, *t)
		logf("[cloud] %s : tenant Microsoft %s, authentification %s%s", d, orDash(t.TenantID), orDash(t.Auth),
			map[bool]string{true: ", fournisseur d'identité " + t.IdP, false: ""}[t.IdP != ""])
		for _, td := range t.Domains {
			if !strings.HasSuffix(td, ".onmicrosoft.com") {
				own[registrableDomain(td)] = true
			}
		}
	}
	// hosts to add: domains of the tenants, federation host, SaaS tenant pages
	for _, t := range rep.Tenants {
		n := 0
		for _, td := range t.Domains {
			if strings.HasSuffix(td, ".onmicrosoft.com") || n >= 25 {
				continue
			}
			n++
			addFull(td)
		}
		if t.IdP != "" {
			if own[registrableDomain(t.IdP)] {
				addFull(t.IdP)
			} else {
				addWeb(t.IdP)
			}
		}
		if t.Name != "" {
			addWeb(t.Name + ".sharepoint.com")
			addWeb(t.Name + "-my.sharepoint.com")
		}
	}
	if len(rep.Added) > 0 {
		logf("[cloud] %d cible(s) ajoutée(s) au scan : %s", len(rep.Added), strings.Join(rep.Added, ", "))
	}
	for d := range own {
		rep.Own = append(rep.Own, d)
	}
	sort.Strings(rep.Own)
	return rep, full, web
}

// finishCloud runs after the scan: CNAME of every scanned name, provider of every public IP,
// dangling CNAMEs.
func finishCloud(ctx context.Context, rep *CloudReport, results []Result, exps []*Exposure, takeovers []Takeover,
	logf func(string, ...any)) {
	if rep == nil {
		return
	}
	seen := map[string]bool{}
	for _, s := range rep.Services {
		seen[s.Service+"|"+s.Host+"|"+s.Source] = true
	}
	var names []string
	nameSeen := map[string]bool{}
	for _, r := range results {
		h := strings.ToLower(r.Host)
		if net.ParseIP(strings.Trim(h, "[]")) != nil || nameSeen[h] || len(names) >= 300 {
			continue
		}
		nameSeen[h] = true
		names = append(names, h)
	}
	servers := takeoverServers()
	chains := make([][]string, len(names))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			chains[i], _ = cnameChain(ctx, n, servers)
		}(i, n)
	}
	wg.Wait()
	for i, n := range names {
		for _, c := range chains[i] {
			if s, ok := matchSig("CNAME", c); ok {
				if k := s.service + "|" + n + "|CNAME"; !seen[k] {
					seen[k] = true
					rep.Services = append(rep.Services, CloudService{s.service, s.category, "CNAME", n, strings.TrimSuffix(c, ".")})
				}
				break
			}
		}
	}
	for _, t := range takeovers {
		rep.Services = append(rep.Services, CloudService{t.Service, "CNAME orphelin", "takeover", t.Host,
			t.CNAME + " - " + t.Reason})
	}
	// IPs
	if exps == nil {
		exps = resolveHosts(ctx, results)
	}
	hostsOf := map[string][]string{}
	for _, x := range exps {
		if !x.Internal {
			hostsOf[x.IP] = appendUnique(hostsOf[x.IP], x.Hosts...)
		}
	}
	for _, r := range results {
		h := strings.Trim(r.Host, "[]")
		if ip := net.ParseIP(h); ip != nil && !isInternalIP(ip) {
			if _, ok := hostsOf[h]; !ok {
				hostsOf[h] = nil
			}
		}
	}
	if len(hostsOf) > 0 && ctx.Err() == nil {
		ranges := loadRanges(ctx, logf)
		for ip, hs := range hostsOf {
			if r, ok := matchRange(ranges, net.ParseIP(ip)); ok {
				rep.IPs = append(rep.IPs, CloudIP{IP: ip, Provider: r.provider, Service: r.service, Region: r.region,
					Prefix: r.net.String(), Hosts: hs})
			}
		}
		sort.Slice(rep.IPs, func(i, j int) bool {
			if rep.IPs[i].Provider != rep.IPs[j].Provider {
				return rep.IPs[i].Provider < rep.IPs[j].Provider
			}
			return rep.IPs[i].IP < rep.IPs[j].IP
		})
	}
	sort.SliceStable(rep.Services, func(i, j int) bool {
		a, b := rep.Services[i], rep.Services[j]
		if (a.Source == "takeover") != (b.Source == "takeover") {
			return a.Source == "takeover"
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Service < b.Service
	})
	byProvider := map[string]int{}
	for _, x := range rep.IPs {
		byProvider[x.Provider]++
	}
	var parts []string
	for p, n := range byProvider {
		parts = append(parts, fmt.Sprintf("%s %d", p, n))
	}
	sort.Strings(parts)
	if len(rep.Domains) == 0 && rep.empty() {
		return
	}
	logf("[cloud] %d tenant(s), %d service(s) reconnu(s), IP chez un fournisseur cloud : %s", len(rep.Tenants),
		len(rep.Services), map[bool]string{true: strings.Join(parts, ", "), false: "aucune"}[len(parts) > 0])
}

// --- Output -----------------------------------------------------------------------------------

func (rep *CloudReport) empty() bool {
	return rep == nil || len(rep.Tenants)+len(rep.Services)+len(rep.IPs)+len(rep.Added) == 0
}

func cloudSection(rep *CloudReport) string {
	if rep == nil || len(rep.Domains) == 0 && rep.empty() {
		return ""
	}
	e := html.EscapeString
	var sb strings.Builder
	scope := strings.Join(rep.Domains, ", ")
	if scope == "" {
		scope = "IP scannées"
	}
	if rep.empty() {
		fmt.Fprintf(&sb, `<p><b>Empreinte cloud et SaaS</b> (%s) : aucun tenant ni service reconnu.</p>`, e(scope))
		return sb.String()
	}
	fmt.Fprintf(&sb, `<details open><summary><b>Empreinte cloud et SaaS</b> - %s : %d tenant(s), %d service(s), %d IP chez un fournisseur cloud</summary>`,
		e(scope), len(rep.Tenants), len(rep.Services), len(rep.IPs))
	if len(rep.Tenants) > 0 {
		sb.WriteString(`<table><tr><th>Fournisseur</th><th>Domaine</th><th>Tenant</th><th>Région</th><th>Authentification</th><th>Fournisseur d'identité</th><th>Autres domaines du tenant</th></tr>`)
		for _, t := range rep.Tenants {
			id := t.TenantID
			if t.Name != "" {
				id = strings.TrimSpace(t.Name + ".onmicrosoft.com " + id)
			}
			fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				e(t.Provider), e(t.Domain), e(id), e(t.Region), e(t.Auth), e(t.IdP), e(strings.Join(t.Domains, ", ")))
		}
		sb.WriteString(`</table>`)
	}
	if len(rep.Added) > 0 {
		fmt.Fprintf(&sb, `<p>Ajouté(s) au scan : %s</p>`, e(strings.Join(rep.Added, ", ")))
	}
	if len(rep.Services) > 0 {
		sb.WriteString(`<table><tr><th>Catégorie</th><th>Service</th><th>Nom</th><th>Indice</th><th>Valeur</th></tr>`)
		for _, s := range rep.Services {
			cat := e(s.Category)
			if s.Source == "takeover" {
				cat = sevBadge("haute") + " " + cat
			}
			fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, cat, e(s.Service), e(s.Host), e(s.Source), e(s.Evidence))
		}
		sb.WriteString(`</table>`)
	}
	if len(rep.IPs) > 0 {
		sb.WriteString(`<table><tr><th>IP</th><th>Fournisseur</th><th>Service</th><th>Région</th><th>Plage</th><th>Noms</th></tr>`)
		for _, x := range rep.IPs {
			fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				e(x.IP), e(x.Provider), e(x.Service), e(x.Region), e(x.Prefix), e(strings.Join(x.Hosts, ", ")))
		}
		sb.WriteString(`</table>`)
	}
	sb.WriteString(`</details>`)
	return sb.String()
}

// cloudRows: one line per finding (cloud.csv and the "Cloud et SaaS" sheet).
func cloudRows(rep *CloudReport) [][]string {
	if rep == nil {
		return nil
	}
	var rows [][]string
	for _, t := range rep.Tenants {
		detail := strings.TrimSpace(strings.Join([]string{"tenant " + t.TenantID, t.Name, "région " + t.Region, "auth " + t.Auth, "IdP " + t.IdP}, " ; "))
		rows = append(rows, []string{"tenant", t.Provider, "", t.Domain, "", detail + " ; domaines " + strings.Join(t.Domains, " ")})
	}
	for _, s := range rep.Services {
		rows = append(rows, []string{"service", s.Service, s.Category, s.Host, s.Source, s.Evidence})
	}
	for _, x := range rep.IPs {
		rows = append(rows, []string{"ip", x.Provider, x.Service, x.IP, x.Region, x.Prefix + " ; " + strings.Join(x.Hosts, " ")})
	}
	for _, a := range rep.Added {
		rows = append(rows, []string{"ajout", a, "", "", "", "ajouté au scan"})
	}
	return rows
}

var cloudHeader = []string{"type", "provider_or_service", "category_or_service", "host_or_ip", "source_or_region", "detail"}

func writeCloudCSV(rep *CloudReport, outdir string) error {
	if rep.empty() {
		return nil
	}
	f, err := os.Create(filepath.Join(outdir, "cloud.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write(cloudHeader)
	for _, r := range cloudRows(rep) {
		w.Write(r)
	}
	w.Flush()
	return w.Error()
}
