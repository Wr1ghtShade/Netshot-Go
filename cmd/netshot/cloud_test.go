package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCloudSignatures(t *testing.T) {
	recs := []DNSRecord{
		{Type: "TXT", Data: `"v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net -all"`},
		{Type: "TXT", Data: `"MS=ms12345678"`},
		{Type: "TXT", Data: `"atlassian-domain-verification=abc"`},
		{Type: "TXT", Data: `"random text"`},
		{Type: "MX", Data: "0 exemple-fr.mail.protection.outlook.com."},
		{Type: "NS", Data: "ns-123.awsdns-45.com."},
	}
	got := map[string]string{}
	for _, s := range recordServices("exemple.fr", recs) {
		got[s.Source+" "+s.Service] = s.Evidence
	}
	for _, want := range []string{"SPF Microsoft 365 (Exchange Online)", "SPF Mailchimp", "TXT Microsoft 365",
		"TXT Atlassian Cloud", "MX Microsoft 365 (Exchange Online)", "NS AWS Route 53"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(got) != 6 {
		t.Errorf("unexpected: %v", got)
	}
	for c, want := range map[string]string{
		"app-prod.azurewebsites.net.":        "Azure App Service",
		"d111.cloudfront.net":                "AWS CloudFront",
		"x.eu-west-3.elb.amazonaws.com":      "AWS Elastic Load Balancing",
		"bucket.s3.amazonaws.com":            "AWS S3",
		"exemple.okta.com":                   "Okta",
		"enterpriseregistration.windows.net": "Entra ID (inscription des appareils)",
		"exemple-fr.atlassian.net":           "Atlassian Cloud",
		"something.example.org":              "",
	} {
		s, ok := matchSig("CNAME", c)
		if ok != (want != "") || s.service != want {
			t.Errorf("%s: %q, want %q", c, s.service, want)
		}
	}
}

func TestAutodiscoverParse(t *testing.T) {
	raw := []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover"><Response><ErrorCode>NoError</ErrorCode><ApplicationUri>outlook.com</ApplicationUri><Domains><Domain>exemple.fr</Domain><Domain>Exemple.onmicrosoft.com</Domain><Domain>filiale.com</Domain><Domain>exemple.fr</Domain></Domains></Response></GetFederationInformationResponseMessage></s:Body></s:Envelope>`)
	got := parseAutodiscover(raw)
	if strings.Join(got, ",") != "exemple.fr,exemple.onmicrosoft.com,filiale.com" {
		t.Errorf("got %v", got)
	}
}

func TestCloudRanges(t *testing.T) {
	mk := func(c, p, s, r string) ipRange {
		_, n, _ := net.ParseCIDR(c)
		return ipRange{n, p, s, r}
	}
	ranges := []ipRange{mk("52.0.0.0/8", "AWS", "", "us-east-1"), mk("52.95.0.0/16", "AWS", "S3", "eu-west-3"),
		mk("52.95.0.0/16", "AWS", "", "eu-west-3"), mk("104.16.0.0/13", "Cloudflare", "", "")}
	r, ok := matchRange(ranges, net.ParseIP("52.95.1.2"))
	if !ok || r.service != "S3" || r.region != "eu-west-3" {
		t.Errorf("most specific: %+v", r)
	}
	if _, ok := matchRange(ranges, net.ParseIP("8.8.8.8")); ok {
		t.Error("8.8.8.8 is in no range")
	}
	if d := cloudDomains([]string{"www.exemple.fr", "mail.exemple.fr", "intranet.demo.lan", "10.0.0.1", "a.filiale.co.uk"}); strings.Join(d, ",") != "exemple.fr,filiale.co.uk" {
		t.Errorf("domains: %v", d)
	}
}

func TestAzureTagsLink(t *testing.T) {
	for _, page := range []string{
		`<a href="https://download.microsoft.com/download/7/1/D/71D8/ServiceTags_Public_20261109.json">`,
		`{"url":"https:\/\/download.microsoft.com\/download\/7\/1\/D\/71D8\/ServiceTags_Public_20261109.json"}`,
	} {
		got := strings.ReplaceAll(azureTagsURL.FindString(page), `\/`, "/")
		if got != "https://download.microsoft.com/download/7/1/D/71D8/ServiceTags_Public_20261109.json" {
			t.Errorf("%q", got)
		}
	}
}

func TestMicrosoftTenant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/exemple.fr/v2.0/.well-known/openid-configuration"):
			w.Write([]byte(`{"issuer":"https://login.microsoftonline.com/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0/v2.0","tenant_region_scope":"EU"}`))
		case strings.HasSuffix(r.URL.Path, "/openid-configuration"):
			w.WriteHeader(400)
		case r.URL.Path == "/getuserrealm.srf" && strings.Contains(r.URL.RawQuery, "exemple.fr"):
			w.Write([]byte(`{"NameSpaceType":"Federated","FederationBrandName":"Exemple","AuthURL":"https://sts.exemple.fr/adfs/ls/?username=x"}`))
		case r.URL.Path == "/getuserrealm.srf":
			w.Write([]byte(`{"NameSpaceType":"Unknown"}`))
		case r.URL.Path == "/autodiscover":
			b, _ := io.ReadAll(r.Body)
			if r.Header.Get("SOAPAction") == "" || !strings.Contains(string(b), "<Domain>exemple.fr</Domain>") {
				w.WriteHeader(400)
				return
			}
			w.Write([]byte(`<s:Envelope xmlns:s="x"><s:Body><R><Domains><Domain>exemple.fr</Domain><Domain>exemple.onmicrosoft.com</Domain><Domain>exemple.mail.onmicrosoft.com</Domain><Domain>filiale.com</Domain></Domains></R></s:Body></s:Envelope>`))
		}
	}))
	defer srv.Close()
	oldL, oldA := msLogin, msAutodiscover
	msLogin, msAutodiscover = srv.URL, srv.URL+"/autodiscover"
	defer func() { msLogin, msAutodiscover = oldL, oldA }()
	tn, err := microsoftTenant(context.Background(), "exemple.fr")
	if err != nil || tn == nil {
		t.Fatalf("tenant: %v %v", tn, err)
	}
	if tn.TenantID != "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" || tn.Region != "EU" || tn.Auth != "fédérée" || tn.IdP != "sts.exemple.fr" ||
		tn.Name != "exemple" || len(tn.Domains) != 4 {
		t.Errorf("%+v", tn)
	}
	if tn, _ := microsoftTenant(context.Background(), "aucun.fr"); tn != nil {
		t.Errorf("no tenant expected: %+v", tn)
	}
}

func TestFinishCloud(t *testing.T) {
	_, n, _ := net.ParseCIDR("52.95.0.0/16")
	rangesOnce.Do(func() {})
	old := rangesList
	rangesList = []ipRange{{n, "AWS", "S3", "eu-west-3"}}
	defer func() { rangesList = old }()
	rep := &CloudReport{Domains: []string{"exemple.fr"}}
	results := []Result{{Host: "52.95.1.2", Port: 443}, {Host: "10.0.0.1", Port: 443}}
	finishCloud(context.Background(), rep, results, nil,
		[]Takeover{{Host: "old.exemple.fr", CNAME: "old.azurewebsites.net", Service: "Azure App Service", Reason: "NXDOMAIN"}}, t.Logf)
	if len(rep.IPs) != 1 || rep.IPs[0].Service != "S3" || len(rep.Services) != 1 || rep.Services[0].Source != "takeover" {
		t.Fatalf("%+v", rep)
	}
	sec := cloudSection(rep)
	for _, want := range []string{"Empreinte cloud et SaaS", "52.95.1.2", "eu-west-3", "CNAME orphelin"} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %q", want)
		}
	}
	if rows := cloudRows(rep); len(rows) != 2 {
		t.Errorf("rows %v", rows)
	}
}

func TestDiscoverCloudBudget(t *testing.T) {
	// a Microsoft endpoint that never answers must not hold the scan longer than the budget
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold the connection open, never answer
		}
	}()
	oldL, oldA, oldB := msLogin, msAutodiscover, cloudBudget
	msLogin, msAutodiscover, cloudBudget = "http://"+ln.Addr().String(), "http://"+ln.Addr().String(), 2*time.Second
	defer func() { msLogin, msAutodiscover, cloudBudget = oldL, oldA, oldB }()
	start := time.Now()
	rep, _, _ := discoverCloud(context.Background(), []string{"www.exemple.invalid.fr"}, t.Logf)
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("discovery took %s", d)
	}
	if len(rep.Errors) == 0 {
		t.Errorf("expected a timeout note: %+v", rep)
	}
}
