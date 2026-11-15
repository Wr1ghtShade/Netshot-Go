package main

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUDPPackets(t *testing.T) {
	s := snmpDiscovery()
	if s[0] != 0x30 || int(s[1]) != len(s)-2 {
		t.Errorf("snmp: bad outer length % x", s)
	}
	ike := ikePacket()
	if int(binary.BigEndian.Uint32(ike[24:28])) != len(ike) || ike[17] != 0x10 || ike[18] != 2 {
		t.Errorf("ike header % x", ike[:28])
	}
	sa := ike[28:]
	if int(binary.BigEndian.Uint16(sa[2:4])) != len(sa) {
		t.Errorf("ike SA length")
	}
	d := dnsProbePacket()
	if binary.BigEndian.Uint16(d[4:6]) != 1 || !strings.Contains(string(d), "\x07example\x03com\x00") {
		t.Errorf("dns % x", d)
	}
	// open resolver: RA set, rcode 0, 1 answer
	resp := append([]byte{0x13, 0x37, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, d[12:]...)
	if _, sev := udpProbes[0].read(resp); sev != "haute" {
		t.Errorf("open resolver: %s", sev)
	}
	resp[3] = 0x05 // REFUSED, no RA
	resp[7] = 0
	if _, sev := udpProbes[0].read(resp); sev != "info" {
		t.Errorf("refused: %s", sev)
	}
	if det, _ := udpProbes[5].read([]byte("HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0 MiniUPnPd/2.1\r\n\r\n")); !strings.Contains(det, "MiniUPnPd") {
		t.Errorf("ssdp: %s", det)
	}
}

func TestOrgTermsAndSkip(t *testing.T) {
	ext := &Extra{CertOrgs: []string{"Exemple Industries SA"}}
	cloud := &CloudReport{Tenants: []CloudTenant{{Brand: "Groupe Exemple"}}}
	terms := orgTerms(ext, cloud, map[string]bool{"exemple.fr": true, "ab.fr": true})
	want := []string{"exemple", "exempleindustriessa", "groupeexemple"}
	if strings.Join(terms, ",") != strings.Join(want, ",") {
		t.Errorf("terms %v", terms)
	}
	for o, skip := range map[string]bool{"Cloudflare, Inc.": true, "Amazon": true, "ACME": false, "abc": true, "Exemple SA": false} {
		if skipOrg(o) != skip {
			t.Errorf("skipOrg(%q) = %v", o, !skip)
		}
	}
}

func TestGitHubSearch(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer T" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"total_count":1,"items":[{"path":"config/.env","html_url":"https://github.com/x/y/blob/main/config/.env","repository":{"full_name":"x/y"}}]}`))
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()
	ext := &Extra{}
	ctx, cancel := context.WithCancel(context.Background())
	// one domain: the second query waits 7 s; cancel after the first by giving a bad token instead
	searchGitHub(ctx, []string{"exemple.fr"}, "bad", ext, t.Logf)
	cancel()
	if !strings.Contains(ext.GitHubNote, "401") || calls != 1 {
		t.Fatalf("bad token: %q (%d calls)", ext.GitHubNote, calls)
	}
}

func TestRisks(t *testing.T) {
	results := []Result{{Host: "a.exemple.fr", Port: 443, URL: "https://a.exemple.fr/", Tags: []string{"admin", "default"},
		FilesFound: []FileFound{{URL: "https://a.exemple.fr/.env", Path: ".env", Severity: "critique"}}}}
	exps := []*Exposure{{IP: "203.0.113.5", Hosts: []string{"a.exemple.fr"}, Vulns: []Vuln{{CVE: "CVE-2024-1", KEV: true}, {CVE: "CVE-2024-2", EPSS: 0.2}}}}
	ext := &Extra{IPv6: []ParityDiff{{Host: "a.exemple.fr", IPv6: "2001:db8::1", V6Only: []int{22}}},
		UDP: []UDPService{{IP: "203.0.113.5", Port: 53, Service: "DNS", Detail: "résolveur ouvert", Severity: "haute"}}}
	risks := collectRisks(results, exps, []TLSResult{{Target: "a.exemple.fr:443", Grade: "F"}}, nil, nil, nil, ext)
	if len(risks) != 6 || risks[0].Severity != "critique" {
		t.Fatalf("%d risks: %+v", len(risks), risks)
	}
	sec := risksSection(risks)
	for _, w := range []string{"Top risques", "2 critique(s)", "CVE-2024-1", "IPv6 seulement", "administration exposée"} {
		if !strings.Contains(sec, w) {
			t.Errorf("section lacks %q", w)
		}
	}
	if !strings.Contains(risksSection(nil), "aucun constat") {
		t.Error("empty")
	}
	if sec := extraSections(ext); !strings.Contains(sec, "Services UDP") || !strings.Contains(sec, "Parité IPv4 / IPv6") {
		t.Error("extra sections")
	}
}
