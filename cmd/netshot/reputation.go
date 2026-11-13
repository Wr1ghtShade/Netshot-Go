package main

// Reputation of the host names found (checks inspired by web-check: "Block Detection" and
// "Malware & Phishing"), run with the enrichment (-no-enrich turns it off):
//   - filtering DNS resolvers: Quad9 (threats), Cloudflare 1.1.1.2 (malware), OpenDNS (phishing),
//     AdGuard DNS (ads and trackers), each compared with an unfiltered answer. No key.
//   - URLhaus (abuse.ch, free key "abusech"): malicious URLs known on the host, Spamhaus DBL / SURBL
//   - VirusTotal (key "virustotal", already used for the subdomains): engines flagging the domain
//   - Google Safe Browsing (free key "safebrowsing"): malware, phishing, unwanted software
// Only public host names are sent: a name that resolves to an internal IP never leaves the machine.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Reputation struct {
	Host         string   `json:"host"`
	Level        string   `json:"level"`                   // critique, haute, moyenne, info, "" (rien)
	Blocked      []string `json:"blocked_by,omitempty"`    // filtering resolvers that block the name
	URLhaus      string   `json:"urlhaus,omitempty"`       // summary of the URLhaus answer
	VirusTotal   string   `json:"virustotal,omitempty"`    // "3 malveillant(s), 1 suspect(s) / 94 moteurs"
	VTMalicious  int      `json:"vt_malicious,omitempty"`  // engines saying malicious
	SafeBrowsing []string `json:"safe_browsing,omitempty"` // threat types
	Errors       []string `json:"errors,omitempty"`
}

// dnsFilter is a filtering resolver and what it blocks.
type dnsFilter struct {
	Name, Server, Blocks string
	Sinkholes            []string // answers that mean "blocked", besides NXDOMAIN and 0.0.0.0
	Security             bool     // blocks threats (malware, phishing), not only ads
}

var dnsFilters = []dnsFilter{
	{Name: "Quad9", Server: "9.9.9.9:53", Blocks: "malware / phishing", Security: true},
	{Name: "Cloudflare 1.1.1.2", Server: "1.1.1.2:53", Blocks: "malware", Security: true},
	{Name: "OpenDNS", Server: "208.67.222.222:53", Blocks: "phishing",
		Sinkholes: []string{"146.112.61.104", "146.112.61.105", "146.112.61.106", "146.112.61.107", "146.112.61.108", "146.112.61.110"}, Security: true},
	{Name: "AdGuard DNS", Server: "94.140.14.14:53", Blocks: "publicité / traqueurs", Sinkholes: []string{"94.140.14.33", "94.140.14.35"}},
}

const dnsUnreachable = "résolveurs DNS publics injoignables (port 53 sortant filtré ?)"

// unfiltered resolvers give the reference answer.
var unfilteredDNS = []string{"1.1.1.1:53", "9.9.9.10:53"}

// aRecords asks the A records of name; NXDOMAIN gives rcode 3.
func aRecords(ctx context.Context, server, name string) ([]string, int, error) {
	recs, rcode, err := dnsQuery(ctx, server, name, 1, 3*time.Second)
	if err != nil {
		return nil, 0, err
	}
	var ips []string
	for _, r := range recs {
		if r.Type == "A" {
			ips = append(ips, r.Data)
		}
	}
	return ips, rcode, nil
}

// dnsBlocks returns the filtering resolvers that block name, and the resolvers that did not answer.
func dnsBlocks(ctx context.Context, name string) (blocked, errs []string) {
	var ref []string
	ok, answered := false, false
	for _, s := range unfilteredDNS {
		ips, rcode, err := aRecords(ctx, s, name)
		if err == nil {
			ref, ok, answered = ips, rcode == 0, true
			break
		}
	}
	if !answered {
		return nil, []string{dnsUnreachable}
	}
	if !ok || len(ref) == 0 {
		return nil, nil // the name does not resolve: nothing to compare
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, f := range dnsFilters {
		wg.Add(1)
		go func(f dnsFilter) {
			defer wg.Done()
			ips, rcode, err := aRecords(ctx, f.Server, name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, f.Name+" injoignable")
				return
			}
			isBlock := rcode == 3
			for _, ip := range ips {
				if ip == "0.0.0.0" || ip == "127.0.0.1" || containsStr(f.Sinkholes, ip) {
					isBlock = true
				}
			}
			if isBlock {
				blocked = append(blocked, f.Name+" ("+f.Blocks+")")
			}
		}(f)
	}
	wg.Wait()
	sort.Strings(blocked)
	sort.Strings(errs)
	return blocked, errs
}

var repClient = &http.Client{Timeout: 20 * time.Second}

// urlhausHost asks URLhaus what it knows about host.
func urlhausHost(ctx context.Context, host, key string) (string, bool, error) {
	form := url.Values{"host": {host}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://urlhaus-api.abuse.ch/v1/host/", strings.NewReader(form.Encode()))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", key)
	resp, err := repClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return "", false, fmt.Errorf("URLhaus HTTP %d", resp.StatusCode)
	}
	var data struct {
		Status     string            `json:"query_status"`
		Blacklists map[string]string `json:"blacklists"`
		URLs       []struct {
			Status string `json:"url_status"`
			Threat string `json:"threat"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", false, err
	}
	if data.Status != "ok" {
		if data.Status == "no_results" || data.Status == "invalid_host" {
			return "", false, nil
		}
		return "", false, fmt.Errorf("URLhaus : %s", data.Status)
	}
	online := 0
	threats := map[string]bool{}
	for _, u := range data.URLs {
		if u.Status == "online" {
			online++
		}
		if u.Threat != "" {
			threats[u.Threat] = true
		}
	}
	var parts []string
	if len(data.URLs) > 0 {
		s := fmt.Sprintf("%d URL malveillante(s) dont %d en ligne", len(data.URLs), online)
		if len(threats) > 0 {
			s += " (" + strings.Join(sortedKeys(threats), ", ") + ")"
		}
		parts = append(parts, s)
	}
	for _, k := range []string{"spamhaus_dbl", "surbl"} {
		if v := data.Blacklists[k]; v != "" && v != "not listed" {
			parts = append(parts, k+" : "+v)
		}
	}
	return strings.Join(parts, " ; "), online > 0, nil
}

// virusTotalDomain returns the engines that flag the domain.
func virusTotalDomain(ctx context.Context, domain, key string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/domains/"+url.PathEscape(domain), nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("x-apikey", key)
	resp, err := repClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", 0, nil
	}
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("VirusTotal HTTP %d", resp.StatusCode)
	}
	var data struct {
		Data struct {
			Attributes struct {
				Stats map[string]int `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&data); err != nil {
		return "", 0, err
	}
	st := data.Data.Attributes.Stats
	total := 0
	for _, n := range st {
		total += n
	}
	if st["malicious"] == 0 && st["suspicious"] == 0 {
		return "", 0, nil
	}
	return fmt.Sprintf("%d malveillant(s), %d suspect(s) / %d moteurs", st["malicious"], st["suspicious"], total), st["malicious"], nil
}

// safeBrowsing checks URLs in one request (Lookup API v4): url -> threat types.
func safeBrowsing(ctx context.Context, urls []string, key string) (map[string][]string, error) {
	type entry struct {
		URL string `json:"url"`
	}
	var entries []entry
	for _, u := range urls {
		entries = append(entries, entry{u})
	}
	body, _ := json.Marshal(map[string]any{
		"client": map[string]string{"clientId": "netshot", "clientVersion": version},
		"threatInfo": map[string]any{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    entries,
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+url.QueryEscape(key), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := repClient.Do(req)
	if err != nil {
		return nil, redactURLError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Safe Browsing HTTP %d", resp.StatusCode)
	}
	var data struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
			Threat     struct {
				URL string `json:"url"`
			} `json:"threat"`
		} `json:"matches"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&data); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, m := range data.Matches {
		if !containsStr(out[m.Threat.URL], m.ThreatType) {
			out[m.Threat.URL] = append(out[m.Threat.URL], m.ThreatType)
		}
	}
	return out, nil
}

// reputationLevel ranks what was found.
func reputationLevel(r *Reputation, urlhausOnline bool) string {
	security := false
	for _, b := range r.Blocked {
		for _, f := range dnsFilters {
			if f.Security && strings.HasPrefix(b, f.Name+" ") {
				security = true
			}
		}
	}
	switch {
	case len(r.SafeBrowsing) > 0 || urlhausOnline || r.VTMalicious >= 3:
		return "critique"
	case security || r.URLhaus != "" || r.VTMalicious > 0:
		return "haute"
	case r.VirusTotal != "":
		return "moyenne"
	case len(r.Blocked) > 0:
		return "info"
	}
	return ""
}

// maxVirusTotal caps the VirusTotal lookups (free API: 4 requests per minute).
const maxVirusTotal = 8

// checkReputation looks up the public host names of the scan. Names of internal IPs are skipped.
func checkReputation(ctx context.Context, results []Result, exps []*Exposure, keys Keys, logf func(string, ...any)) []*Reputation {
	if exps == nil {
		exps = resolveHosts(ctx, results)
	}
	internal := map[string]bool{}
	public := map[string]bool{}
	for _, x := range exps {
		for _, h := range x.Hosts {
			if x.Internal {
				internal[h] = true
			} else {
				public[h] = true
			}
		}
	}
	var names []string
	urlsByHost := map[string][]string{}
	for _, r := range results {
		h := strings.ToLower(r.Host)
		if net.ParseIP(strings.Trim(h, "[]")) != nil || internal[r.Host] || !public[r.Host] {
			continue
		}
		if _, ok := urlsByHost[h]; !ok {
			names = append(names, h)
		}
		for _, u := range []string{r.URL, r.FinalURL} {
			if u != "" && !containsStr(urlsByHost[h], u) {
				urlsByHost[h] = append(urlsByHost[h], u)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	abusech, vt, sb := keys.get("abusech"), keys.get("virustotal"), keys.get("safebrowsing")
	srcs := []string{"résolveurs filtrants (Quad9, Cloudflare, OpenDNS, AdGuard)"}
	if abusech != "" {
		srcs = append(srcs, "URLhaus")
	}
	if vt != "" {
		srcs = append(srcs, "VirusTotal")
	}
	if sb != "" {
		srcs = append(srcs, "Safe Browsing")
	}
	logf("[réputation] %d nom(s) public(s) : %s", len(names), strings.Join(srcs, ", "))

	reps := make([]*Reputation, len(names))
	online := make([]bool, len(names))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, n := range names {
		reps[i] = &Reputation{Host: n}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, n string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := reps[i]
			r.Blocked, r.Errors = dnsBlocks(ctx, n)
			if abusech != "" && ctx.Err() == nil {
				s, on, err := urlhausHost(ctx, n, abusech)
				if err != nil {
					r.Errors = append(r.Errors, err.Error())
				}
				r.URLhaus, online[i] = s, on
			}
		}(i, n)
	}
	wg.Wait()
	if vt != "" {
		for i, n := range names {
			if i == maxVirusTotal || ctx.Err() != nil {
				if i == maxVirusTotal {
					logf("[réputation] VirusTotal limité aux %d premiers noms (API gratuite : 4 requêtes / minute)", maxVirusTotal)
				}
				break
			}
			if i > 0 {
				select {
				case <-time.After(15 * time.Second):
				case <-ctx.Done():
				}
			}
			s, mal, err := virusTotalDomain(ctx, n, vt)
			if err != nil {
				reps[i].Errors = append(reps[i].Errors, err.Error())
			}
			reps[i].VirusTotal, reps[i].VTMalicious = s, mal
		}
	}
	if sb != "" && ctx.Err() == nil {
		var all []string
		for _, n := range names {
			all = append(all, urlsByHost[n]...)
		}
		for start := 0; start < len(all); start += 500 {
			matches, err := safeBrowsing(ctx, all[start:min(len(all), start+500)], sb)
			if err != nil {
				logf("[réputation] Safe Browsing : %v", err)
				break
			}
			for i, n := range names {
				for _, u := range urlsByHost[n] {
					for _, t := range matches[u] {
						if !containsStr(reps[i].SafeBrowsing, t) {
							reps[i].SafeBrowsing = append(reps[i].SafeBrowsing, t)
						}
					}
				}
			}
		}
	}
	unreachable := true
	for _, r := range reps {
		unreachable = unreachable && containsStr(r.Errors, dnsUnreachable)
	}
	if unreachable {
		logf("[réputation] listes de blocage non vérifiées : %s", dnsUnreachable)
	}
	var out []*Reputation
	for i, r := range reps {
		r.Level = reputationLevel(r, online[i])
		if r.Level != "" {
			logf("[réputation] %s  %s  %s", r.Host, r.Level, reputationSummary(r))
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return levelRank(out[i].Level) < levelRank(out[j].Level) })
	return out
}

// resolveHosts gives, without any third-party lookup, the IPs of the host names scanned (used when
// the enrichment is off): only their Internal flag and Hosts are filled.
func resolveHosts(ctx context.Context, results []Result) []*Exposure {
	seen := map[string]bool{}
	var out []*Exposure
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, r := range results {
		h := r.Host
		if seen[h] || net.ParseIP(strings.Trim(h, "[]")) != nil {
			continue
		}
		seen[h] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			addrs, _ := net.DefaultResolver.LookupIPAddr(lctx, h)
			cancel()
			mu.Lock()
			defer mu.Unlock()
			for _, a := range addrs {
				out = append(out, &Exposure{IP: a.IP.String(), Internal: isInternalIP(a.IP), Hosts: []string{h}})
			}
		}(h)
	}
	wg.Wait()
	return out
}

// levelRank orders critique < haute < moyenne < info < nothing found.
func levelRank(l string) int {
	if n, ok := severityRank[l]; ok {
		return n
	}
	return len(severityRank)
}

func reputationSummary(r *Reputation) string {
	var parts []string
	if len(r.Blocked) > 0 {
		parts = append(parts, "bloqué par "+strings.Join(r.Blocked, ", "))
	}
	if r.URLhaus != "" {
		parts = append(parts, "URLhaus : "+r.URLhaus)
	}
	if r.VirusTotal != "" {
		parts = append(parts, "VirusTotal : "+r.VirusTotal)
	}
	if len(r.SafeBrowsing) > 0 {
		parts = append(parts, "Safe Browsing : "+strings.Join(r.SafeBrowsing, ", "))
	}
	return strings.Join(parts, " ; ")
}

func writeReputationCSV(reps []*Reputation, outdir string) error {
	if len(reps) == 0 {
		return nil
	}
	f, err := os.Create(filepath.Join(outdir, "reputation.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"host", "level", "blocked_by", "urlhaus", "virustotal", "vt_malicious", "safe_browsing", "errors"})
	for _, r := range reps {
		w.Write([]string{r.Host, r.Level, strings.Join(r.Blocked, "; "), r.URLhaus, r.VirusTotal, strconv.Itoa(r.VTMalicious),
			strings.Join(r.SafeBrowsing, " "), strings.Join(r.Errors, "; ")})
	}
	w.Flush()
	return w.Error()
}

func reputationSection(reps []*Reputation) string {
	if len(reps) == 0 {
		return ""
	}
	e := html.EscapeString
	var rows []string
	for _, r := range reps {
		if r.Level == "" {
			continue
		}
		rows = append(rows, fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`, sevBadge(r.Level), e(r.Host), e(reputationSummary(r))))
	}
	if len(rows) == 0 {
		return fmt.Sprintf(`<p><b>Réputation</b> : %d nom(s) vérifié(s), aucun sur une liste de blocage ou de menaces.</p>`, len(reps))
	}
	return fmt.Sprintf(`<details open><summary><b>Réputation (listes de blocage, malware, phishing)</b> - %d nom(s) signalé(s) sur %d</summary>`+
		`<table><tr><th>Niveau</th><th>Nom</th><th>Constat</th></tr>%s</table></details>`, len(rows), len(reps), strings.Join(rows, ""))
}
