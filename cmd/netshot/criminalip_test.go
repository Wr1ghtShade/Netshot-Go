package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCIP mimics the Criminal IP endpoints used by Netshot and records the queried values.
func fakeCIP(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "K" {
			w.Write([]byte(`{"status":401,"message":"invalid key"}`))
			return
		}
		mu.Lock()
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		switch {
		case r.URL.Path == "/v1/feature/ip/suspicious-info":
			if r.URL.Query().Get("ip") == "203.0.113.9" {
				w.Write([]byte(`{"status":200,"score":{"inbound":"Moderate","outbound":"Dangerous"},"issues":{"is_vpn":false,"is_tor":true,"is_scanner":true},"abuse_record_count":2}`))
				return
			}
			w.Write([]byte(`{"status":200,"score":{"inbound":1,"outbound":1},"issues":{},"abuse_record_count":0}`))
		case r.URL.Path == "/v1/domain/lite/scan":
			w.Write([]byte(`{"status":200,"data":{"scan_id":4242}}`))
		case r.URL.Path == "/v1/domain/lite/progress":
			w.Write([]byte(`{"status":200,"data":{"scan_percentage":100}}`))
		case r.URL.Path == "/v1/domain/lite/report/4242":
			w.Write([]byte(`{"status":200,"data":{"domain_score":"80% (Dangerous)","classification":{"domain_type":"phishing","dga_score":2.1},"summary":{"url_phishing_prob":82.5,"fake_https_url":false,"punycode":true,"abuse_record":{"critical":0,"dangerous":1,"moderate":0}}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	return srv, &seen
}

func TestCriminalIP(t *testing.T) {
	srv, seen := fakeCIP(t)
	defer srv.Close()
	old := cipBase
	cipBase = srv.URL
	defer func() { cipBase = old }()
	ctx := context.Background()

	s, l, err := cipIP(ctx, "203.0.113.9", "K")
	if err != nil || l != "haute" || !strings.Contains(s, "tor") || !strings.Contains(s, "2 signalement") {
		t.Fatalf("cipIP: %q %q %v", s, l, err)
	}
	if _, l, _ := cipIP(ctx, "198.51.100.1", "K"); l != "" {
		t.Errorf("safe ip: %q", l)
	}
	s, l, err = cipDomain(ctx, "exemple.fr", "K")
	if err != nil || l != "critique" || !strings.Contains(s, "82 %") || !strings.Contains(s, "punycode") {
		t.Fatalf("cipDomain: %q %q %v", s, l, err)
	}
	if _, _, err := cipIP(ctx, "203.0.113.9", "bad"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("bad key: %v", err)
	}

	// limits, priority and internal IPs never sent
	*seen = nil
	exps := []*Exposure{
		{IP: "203.0.113.9", Hosts: []string{"www.exemple.fr"}},
		{IP: "198.51.100.1", Hosts: []string{"mail.exemple.fr"}},
		{IP: "10.0.0.5", Hosts: []string{"intra.exemple.fr"}, Internal: true},
	}
	results := []Result{{Host: "www.exemple.fr", Port: 443}, {Host: "www.exemple.fr", Port: 80}, {Host: "mail.exemple.fr", Port: 443}}
	reps := []*Reputation{{Host: "www.exemple.fr"}, {Host: "mail.exemple.fr"}}
	reps = checkCriminalIP(ctx, reps, []string{"mail.exemple.fr", "www.exemple.fr"}, exps, results, "K", CIPLimits{IPs: 1, Domains: 1}, t.Logf)
	reps = finishReputation(reps, nil, t.Logf)
	for _, q := range *seen {
		if strings.Contains(q, "10.0.0.5") || strings.Contains(q, "198.51.100.1") {
			t.Errorf("unexpected lookup %s", q)
		}
	}
	if len(reps) != 4 || reps[0].Host != "exemple.fr" || reps[0].Level != "critique" {
		t.Fatalf("rows: %+v", reps[0])
	}
	var ipRow *Reputation
	for _, r := range reps {
		if r.Host == "203.0.113.9" {
			ipRow = r
		}
	}
	if ipRow == nil || ipRow.Level != "haute" || len(ipRow.Names) != 1 {
		t.Errorf("ip row: %+v", ipRow)
	}
	if got := checkCriminalIP(ctx, nil, nil, exps, results, "", CIPLimits{IPs: 5, Domains: 1}, t.Logf); got != nil {
		t.Error("no key: no lookup")
	}
}
