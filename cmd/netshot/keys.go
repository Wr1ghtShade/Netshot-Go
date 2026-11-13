package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// API keys for the free services that need one, by source name.
//
// Stored in keys.json next to the exe (created at startup when missing). Do not share the
// folder with its keys.
// An environment variable NETSHOT_KEY_<SOURCE> overrides the file.
type Keys map[string]string

// keySources lists the services that accept a key, with where to get one.
var keySources = []struct {
	Name, Label, URL string
}{
	{"certspotter", "Cert Spotter", "https://sslmate.com/signup?for=ct_search_api"},
	{"hackertarget", "HackerTarget", "https://hackertarget.com/scan-membership/"},
	{"urlscan", "urlscan.io", "https://urlscan.io/user/signup"},
	{"virustotal", "VirusTotal", "https://www.virustotal.com/gui/join-us"},
	{"dnsdumpster", "DNSDumpster", "https://dnsdumpster.com/"},
	{"domscan", "DomScan", "https://domscan.net/pricing"},
	{"viewdns", "ViewDNS", "https://viewdns.info/api/pricing/"},
	{"leakix", "LeakIX", "https://leakix.net/"},
	{"shodan", "Shodan", "https://account.shodan.io/"},
	{"leakcheck", "LeakCheck", "https://leakcheck.io/"},
	{"nvd", "NVD (NIST)", "https://nvd.nist.gov/developers/request-an-api-key"},
	{"abusech", "abuse.ch (URLhaus)", "https://auth.abuse.ch/"},
	{"safebrowsing", "Google Safe Browsing", "https://developers.google.com/safe-browsing/v4/get-started"},
}

// keysPath is keys.json next to the exe (in the current folder if the exe path is unknown).
// A variable for tests.
var keysPath = func() string {
	exe, err := os.Executable()
	if err != nil {
		return "keys.json"
	}
	return filepath.Join(filepath.Dir(exe), "keys.json")
}

// ensureKeysFile creates an empty keys.json template next to the exe when it is missing.
// Exclusive creation (O_EXCL): an existing keys.json is never overwritten. Errors (read-only folder,
// file created meanwhile) are ignored: the program then runs without file.
func ensureKeysFile() {
	path := keysPath()
	if _, err := os.Stat(path); err == nil {
		return
	}
	template := Keys{}
	for _, s := range keySources {
		template[s.Name] = ""
	}
	data, _ := json.MarshalIndent(template, "", "  ")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return
	}
	f.Write(data)
	f.Close()
}

// loadKeys reads the saved keys, then applies environment overrides.
func loadKeys() Keys {
	ensureKeysFile()
	k := Keys{}
	if data, err := os.ReadFile(keysPath()); err == nil {
		json.Unmarshal(data, &k)
	}
	if v := os.Getenv("CERTSPOTTER_API_KEY"); v != "" { // kept for compatibility
		k["certspotter"] = v
	}
	for _, s := range keySources {
		if v := os.Getenv("NETSHOT_KEY_" + strings.ToUpper(s.Name)); v != "" {
			k[s.Name] = v
		}
	}
	return k
}

// updateKeys applies changes to keys.json as it is on disk now: a value sets the key, an empty value
// removes it. Keys not named in changes are kept as in the file (never replaced by a copy held in
// memory, nor by environment variables). An unreadable file is never rewritten. The previous file is
// kept as keys.json.bak, and the new one replaces it in one step (no half-written file).
func updateKeys(changes Keys) error {
	path := keysPath()
	current := Keys{}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &current); err != nil {
			return fmt.Errorf("%s is not valid JSON, fix it before saving: %v", path, err)
		}
		if current == nil {
			current = Keys{}
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "keys.json.bak"), data, 0o600); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for name, v := range changes {
		if v = strings.TrimSpace(v); v != "" {
			current[name] = v
		} else {
			delete(current, name)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(current, "", "  ")
	tmp := filepath.Join(filepath.Dir(path), "keys.json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (k Keys) get(name string) string { return k[name] }
