package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefectDojo(t *testing.T) {
	results := []Result{{Host: "a.exemple.fr", Port: 443, URL: "https://a.exemple.fr/", Tags: []string{"admin"},
		FilesFound: []FileFound{{URL: "https://a.exemple.fr/.env", Path: ".env", Severity: "critique"},
			{URL: "https://a.exemple.fr/robots.txt", Path: "robots.txt", Severity: "info", Size: 12}}}}
	exps := []*Exposure{{IP: "203.0.113.5", Hosts: []string{"a.exemple.fr"}, Vulns: []Vuln{{CVE: "CVE-2024-1", KEV: true}, {CVE: "CVE-2024-2", CVSS: 5.3}}}}
	inv := []*TechEntry{{Tech: Tech{Name: "nginx", Version: "1.18.0"}, URLs: []string{"https://a.exemple.fr/"}, Vulns: []Vuln{{CVE: "CVE-2021-23017", CVSS: 7.7}}}}
	ext := &Extra{IPv6: []ParityDiff{{Host: "a.exemple.fr", IPv6: "2001:db8::1", V6Only: []int{22}}}}
	f := buildDefectDojo(results, exps, nil, inv, nil, nil, nil, ext, time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC))
	sev := map[string]string{}
	for _, x := range f {
		sev[x.Title] = x.Severity
		if x.Date != "2026-11-18" || !x.Active || x.UniqueIDFromTool == "" || x.Description == "" {
			t.Errorf("incomplete %+v", x)
		}
		for _, e := range x.Endpoints {
			if strings.Contains(e, " ") || strings.Count(e, ":") > 1 && !strings.HasPrefix(e, "[") && !strings.Contains(e, "://") {
				t.Errorf("bad endpoint %q", e)
			}
		}
	}
	want := map[string]string{"CVE-2024-1 sur 203.0.113.5": "Critical", "CVE-2024-2 sur 203.0.113.5": "Medium",
		"CVE-2021-23017 dans nginx 1.18.0": "High", "Fichier sensible exposé : /.env": "Critical",
		"Interface d'administration exposée": "Medium", "Fichier exposé : /robots.txt": "Info"}
	for title, s := range want {
		if sev[title] != s {
			t.Errorf("%s: %q, want %q (%v)", title, sev[title], s, sev)
		}
	}
	if f[0].Severity != "Critical" {
		t.Error("not sorted")
	}
	// same scan twice: same ids (DefectDojo reimport closes what disappeared)
	g := buildDefectDojo(results, exps, nil, inv, nil, nil, nil, ext, time.Now())
	if g[0].UniqueIDFromTool != f[0].UniqueIDFromTool {
		t.Error("ids not stable")
	}
	dir := t.TempDir()
	if err := writeDefectDojo(dir, f); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "defectdojo.json"))
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil || doc["type"] != "NetShot" || len(doc["findings"].([]any)) != len(f) {
		t.Errorf("bad file %s", raw)
	}
	if out := os.Getenv("DD_SAMPLE"); out != "" {
		os.WriteFile(out, raw, 0o644)
	}
}
