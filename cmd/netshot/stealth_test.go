package main

import (
	"testing"
	"time"
)

func TestStealth(t *testing.T) {
	d, err := parseStealthDelay("2-5")
	if err != nil || d.Min != 2*time.Second || d.Max != 5*time.Second {
		t.Fatalf("%v %v", d, err)
	}
	fixed, _ := parseStealthDelay("4")
	if fixed.Min != fixed.Max || fixed.Min != 4*time.Second {
		t.Errorf("single value: %v", fixed)
	}
	for _, bad := range []string{"5-2", "a-b", "-1"} {
		if _, err := parseStealthDelay(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for i := 0; i < 50; i++ {
		if p := fixed.pick(); p != 4*time.Second {
			t.Fatal("fixed delay")
		}
	}
	r := StealthDelay{time.Second, 2 * time.Second}
	for i := 0; i < 50; i++ {
		if p := r.pick(); p < time.Second || p >= 2*time.Second {
			t.Fatalf("pick %s", p)
		}
	}
	opt := Options{Concurrency: 10, Dirs: []string{"x"}, Files: []FileRule{{}}, WAFProbe: true, UDP: true, TLS: true,
		IPv6Parity: true, UAs: []UA{{Name: "nmap", Value: "Nmap"}}, StealthDelay: r, Enrich: true, Cloud: true}
	var logs []string
	applyStealth(&opt, func(f string, a ...any) { logs = append(logs, f) })
	if opt.Concurrency != 1 || opt.Dirs != nil || opt.Files != nil || opt.WAFProbe || opt.UDP || opt.TLS || opt.IPv6Parity ||
		opt.Delay != 2*time.Second || len(opt.UAs) != 1 || opt.UAs[0].Value != browserUAs[0].Value || opt.UAs[0].Name != "default" {
		t.Errorf("%+v", opt)
	}
	if !opt.Enrich || !opt.Cloud {
		t.Error("passive lookups must stay on")
	}
	if len(logs) != 1 {
		t.Errorf("logs %v", logs)
	}
}
