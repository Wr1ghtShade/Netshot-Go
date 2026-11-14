package main

import (
	"strings"
	"testing"
	"time"
)

func TestAnalyzeResources(t *testing.T) {
	raw := `{"el":[
	 {"t":"script","u":"https://www.example.com/app.js","i":"","r":""},
	 {"t":"script","u":"https://cdn.jsdelivr.net/npm/lib.js","i":"","r":""},
	 {"t":"script","u":"https://cdn.other.net/ok.js","i":"sha384-abc","r":""},
	 {"t":"link","u":"https://fonts.googleapis.com/css?family=Roboto","i":"","r":"stylesheet"},
	 {"t":"img","u":"http://img.example.com/a.png","i":"","r":""},
	 {"t":"form","u":"http://www.example.com/login","i":"","r":""}],
	 "res":["https://www.google-analytics.com/g/collect?v=2","https://connect.facebook.net/en_US/fbevents.js","https://static.example.com/x.css"]}`
	pc := analyzeResources("https://www.example.com/", raw)
	if len(pc.MixedContent) != 2 || !strings.HasPrefix(pc.MixedContent[1], "formulaire ") {
		t.Errorf("mixed content: %v", pc.MixedContent)
	}
	if len(pc.NoSRI) != 2 || pc.NoSRI[0] != "https://cdn.jsdelivr.net/npm/lib.js" {
		t.Errorf("no SRI: %v", pc.NoSRI)
	}
	want := []string{"Google Analytics (mesure d'audience)", "Google Fonts (polices (IP transmise à Google))", "Meta Pixel (réseau social / publicité)"}
	if strings.Join(pc.Trackers, "|") != strings.Join(want, "|") {
		t.Errorf("trackers: %v", pc.Trackers)
	}
	for _, h := range pc.ThirdParty {
		if strings.HasSuffix(h, "example.com") {
			t.Errorf("same site counted as third party: %s", h)
		}
	}
	if issues := pageIssues(pc); len(issues) != 2 || !strings.Contains(issues[0], "dont 1 formulaire") {
		t.Errorf("issues: %v", issues)
	}
	if pc := analyzeResources("http://www.example.com/", raw); len(pc.MixedContent) != 0 {
		t.Errorf("mixed content on an http page: %v", pc.MixedContent)
	}
}

func TestTrackerFor(t *testing.T) {
	for host, want := range map[string]string{
		"www.googletagmanager.com":     "Google Tag Manager (gestionnaire de balises)",
		"region1.analytics.google.com": "Google Analytics (mesure d'audience)",
		"example.com":                  "",
		"com":                          "",
	} {
		if got := trackerFor(host); got != want {
			t.Errorf("trackerFor(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestDetectWAF(t *testing.T) {
	hs := []Header{{"Server", "cloudflare"}, {"CF-RAY", "8abc-CDG"}, {"Set-Cookie", "incap_ses_123=abc; path=/"},
		{"Set-Cookie", "TS01a2b3c4=0123; Path=/"}}
	got := strings.Join(detectWAF(hs), ", ")
	if got != "Cloudflare, Imperva / Incapsula, F5 BIG-IP ASM" {
		t.Errorf("detectWAF = %q", got)
	}
	if w := detectWAF([]Header{{"Server", "nginx"}}); len(w) != 0 {
		t.Errorf("false positive: %v", w)
	}
}

func TestDKIMFound(t *testing.T) {
	recs := []DNSRecord{
		{Name: "google._domainkey.example.com", Type: "TXT", Data: `"v=DKIM1; k=rsa; p=MIIBIjAN"`},
		{Name: "selector1._domainkey.example.com", Type: "CNAME", Data: "selector1-example-com._domainkey.example.onmicrosoft.com"},
		{Name: "selector1-example-com._domainkey.example.onmicrosoft.com", Type: "TXT", Data: `"v=DKIM1; k=rsa; p=MIGfMA0"`},
		{Name: "s1._domainkey.example.com", Type: "TXT", Data: `"v=DKIM1; p="`},
		{Name: "example.com", Type: "TXT", Data: `"v=spf1 -all"`},
	}
	found, revoked := dkimFound("example.com", recs)
	if strings.Join(found, ",") != "google,selector1" || strings.Join(revoked, ",") != "s1" {
		t.Errorf("found %v revoked %v", found, revoked)
	}
	f := strings.Join(dnsFindings("example.com", recs), "\n")
	if !strings.Contains(f, "DKIM publié (sélecteur(s) : google, selector1)") || !strings.Contains(f, "révoquée") {
		t.Errorf("findings: %s", f)
	}
}

func TestReputationLevel(t *testing.T) {
	r := &Reputation{Blocked: []string{"AdGuard DNS (publicité / traqueurs)"}}
	if l := reputationLevel(r, false); l != "info" {
		t.Errorf("adguard only: %s", l)
	}
	r.Blocked = append(r.Blocked, "Quad9 (malware / phishing)")
	if l := reputationLevel(r, false); l != "haute" {
		t.Errorf("quad9: %s", l)
	}
	r.SafeBrowsing = []string{"SOCIAL_ENGINEERING"}
	if l := reputationLevel(r, false); l != "critique" {
		t.Errorf("safe browsing: %s", l)
	}
	if levelRank("critique") >= levelRank("info") || levelRank("info") >= levelRank("") {
		t.Error("levelRank order")
	}
}

func TestScanFolderName(t *testing.T) {
	now := time.Date(2026, 11, 14, 9, 57, 43, 0, time.UTC)
	for targets, want := range map[string]string{
		"groups.msgr.guifort.ovh\nwww.guifort.ovh\n# commentaire\nguifort.ovh": "scan_guifort.ovh_20261114_095743",
		"https://intranet.demo.lan:8443/\nwiki.demo.lan":                       "scan_demo.lan_20261114_095743",
		"www.service-public.gouv.fr":                                           "scan_service-public.gouv.fr_20261114_095743",
		"10.0.0.0/24":                                                          "scan_10.0.0.0-24_20261114_095743",
		"AS3215":                                                               "scan_AS3215_20261114_095743",
		"a.example.com\nb.other.org":                                           "scan_20261114_095743",
		"192.168.1.1\n192.168.1.2":                                             "scan_20261114_095743",
	} {
		if got := scanFolderName(targets, now); got != want {
			t.Errorf("scanFolderName(%q) = %q, want %q", targets, got, want)
		}
	}
}
