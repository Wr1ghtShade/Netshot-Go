package main

import (
	"strings"
	"testing"
)

func TestMMH3(t *testing.T) {
	// Same values as the mmh3 Python package (and the Python version of netshot)
	for in, want := range map[string]int32{"foo": -156908512, "hello": 613153351, "": 0, "abcde": -392455434} {
		if got := mmh3([]byte(in)); got != want {
			t.Errorf("mmh3(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestDetectTech(t *testing.T) {
	hs := []Header{{"Server", "Apache/2.4.59 (Ubuntu) OpenSSL/1.1.1f"}, {"X-Powered-By", "PHP/8.1.2"}, {"Set-Cookie", "PHPSESSID=x; path=/"}}
	got := map[string]string{}
	for _, tc := range detectTech(hs, `<script src="/js/jquery-3.6.0.min.js"></script>`, "Home") {
		got[tc.Name] = tc.Version
	}
	for name, ver := range map[string]string{"Apache httpd": "2.4.59", "OpenSSL": "1.1.1f", "PHP": "8.1.2", "jQuery": "3.6.0"} {
		if got[name] != ver {
			t.Errorf("%s: got %q, want %q (all: %v)", name, got[name], ver, got)
		}
	}
	for _, tc := range detectTech([]Header{{"Server", "Apache-Coyote/1.1"}}, "", "") {
		if tc.Name == "Apache httpd" {
			t.Error("Apache-Coyote taken for Apache httpd")
		}
	}
}

func TestPagesAndPorts(t *testing.T) {
	if !isIndexPage(`<html><head><title>Index of /backup</title></head>`) || isIndexPage(`<title>Accueil</title>`) {
		t.Error("isIndexPage")
	}
	tags := pageTags("Directory listing for /", "", "http://x/", 200, nil, nil)
	if len(tags) == 0 || tags[0] != "index-of" {
		t.Errorf("tags = %v", tags)
	}
	ports, err := parsePorts("web,services,8443")
	if err != nil || len(ports) < 110 {
		t.Errorf("presets: %d ports, %v", len(ports), err)
	}
	if n := len(fileRules(nil)); n != 65 {
		t.Errorf("files.txt: %d rules compiled, want 65 (a signature RE2 cannot read?)", n)
	}
	if n := len(dirWords(nil)); n != 95 {
		t.Errorf("dirs.txt: %d folders, want 95", n)
	}
}

func TestExclusionsAndSecrets(t *testing.T) {
	x := newExclusions([]string{"10.9.9.0/24", "*.partner.com", "db.local"})
	for host, out := range map[string]bool{"10.9.9.9": true, "10.9.8.1": false, "a.partner.com": true, "partner.com": true, "db.local": true, "web.local": false} {
		if (x.reason(host) != "") != out {
			t.Errorf("%s excluded = %v, want %v", host, !out, out)
		}
	}
	fake := "AKIA" + "IOSFODNN7EXAMPLE" // AWS documentation example, split so no scanner takes it for a key
	js := analyzeJS([]jsSource{{"app.js", `const k = "` + fake + `"; fetch("/api/v1/users"); var client_secret = "s3cr3tValue_9876543210"; u="http://intranet.corp:8080/x"`}})
	if js == nil || len(js.Secrets) != 2 || len(js.Endpoints) != 1 || len(js.InternalURLs) != 1 {
		t.Fatalf("js = %+v", js)
	}
	for _, s := range js.Secrets {
		if strings.Contains(s.Value, "IOSFODNN") || strings.Contains(s.Value, "Value_98") {
			t.Errorf("secret not masked: %s", s.Value)
		}
	}
	if name, ver, _ := parseBanner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"); name != "OpenSSH" || ver != "8.2p1" {
		t.Errorf("banner: %s %s", name, ver)
	}
}
