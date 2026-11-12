package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Passive sources used to find hostnames under a domain: Certificate Transparency
// indexes, passive DNS and web crawl archives. Only the domain name is sent to these
// services: nothing is sent to the scanned hosts.

type subSource struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Key     string `json:"key"`     // "" = no key, "optional" or "required"
	Default bool   `json:"default"` // queried when no source is chosen explicitly
	Slow    bool   `json:"slow"`    // shown as such in the interface
	Help    string `json:"help"`
	fetch   func(ctx context.Context, domain, key string) ([]string, error)
}

var subSources = []subSource{
	{"crtname", "crt.name", "", true, false, "Index CT le plus complet. 100 requêtes/jour/IP", fetchCrtName},
	{"certspotter", "Cert Spotter", "optional", true, false, "Logs CT. Petit quota sans clé", fetchCertSpotter},
	{"hackertarget", "HackerTarget", "optional", true, false, "DNS passif. 50 requêtes/jour sans clé", fetchHackerTarget},
	{"urlscan", "urlscan.io", "optional", true, false, "Sites scannés par urlscan", fetchURLScan},
	{"virustotal", "VirusTotal", "required", true, false, "DNS passif. 4 requêtes/minute", fetchVirusTotal},
	{"dnsdumpster", "DNSDumpster", "required", true, false, "Enregistrements DNS", fetchDNSDumpster},
	{"domscan", "DomScan", "required", true, false, "Logs CT. 1 000 crédits/mois gratuits (4-5 par page)", fetchDomScan},
	{"viewdns", "ViewDNS", "required", true, false, "Index ViewDNS. 250 requêtes d'essai puis payant (1 par page)", fetchViewDNS},
	{"shodan", "Shodan", "required", true, false, "Noms vus par les scans Shodan. 1 crédit de requête par domaine", fetchShodanDNS},
	{"wordlist", "Dictionnaire DNS", "", false, false, "Force brute DNS : 1 000 noms courants (ou -wordlist), avec détection des wildcards", fetchWordlist},
	{"crtsh", "crt.sh", "", false, true, "Logs CT. Souvent lent ou surchargé", fetchCrtSh},
	{"wayback", "Wayback Machine", "", false, true, "URL archivées : anciens noms. Lent", fetchWayback},
}

func findSubSource(name string) (subSource, bool) {
	for _, s := range subSources {
		if s.Name == name {
			return s, true
		}
	}
	return subSource{}, false
}

func subSourceNames() []string {
	var names []string
	for _, s := range subSources {
		names = append(names, s.Name)
	}
	return names
}

// resolveSourceNames turns "default", "all" or a comma list into source names.
// "default" keeps the default sources, minus the keyed ones without a key.
func resolveSourceNames(list []string, keys Keys) []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, item := range list {
		item = strings.TrimSpace(item)
		switch item {
		case "":
		case "default":
			for _, s := range subSources {
				if s.Default && (s.Key != "required" || keys.get(s.Name) != "") {
					add(s.Name)
				}
			}
		case "all":
			for _, s := range subSources {
				if s.Key != "required" || keys.get(s.Name) != "" {
					add(s.Name)
				}
			}
		default:
			add(item)
		}
	}
	return out
}

var ctClient = &http.Client{Timeout: 90 * time.Second}

// normalizeDomain turns "https://*.Example.com/" into "example.com".
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if u, err := url.Parse(d); err == nil && u.Host != "" {
		d = u.Host
	}
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, "./")
	return d
}

// cleanCTName keeps a name only if it is a plain hostname under domain.
func cleanCTName(name, domain string) (string, bool) {
	name = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*."), ".")
	if name == "" || strings.ContainsAny(name, " @*/:") {
		return "", false
	}
	if name != domain && !strings.HasSuffix(name, "."+domain) {
		return "", false
	}
	return name, true
}

// ctGet sends a GET with optional extra headers and returns body and status.
func ctGet(ctx context.Context, rawURL string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, redactURLError(err)
	}
	req.Header.Set("User-Agent", "netshot")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ctClient.Do(req)
	if err != nil {
		return nil, 0, redactURLError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	return body, resp.StatusCode, redactURLError(err)
}

// secretParams are the query parameters that carry an API key in the source URLs.
var secretParams = []string{"key", "apikey", "api_key"}

// redactURLError hides API keys passed in the query string: net/http puts the full
// URL in its errors, which end up in the log, the GUI and exposure.csv.
func redactURLError(err error) error {
	var ue *url.Error
	if err == nil || !errors.As(err, &ue) {
		return err
	}
	u, perr := url.Parse(ue.URL)
	if perr != nil {
		ue.URL = "(URL hidden)"
		return err
	}
	q := u.Query()
	changed := false
	for _, p := range secretParams {
		if q.Has(p) {
			q.Set(p, "REDACTED")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
		ue.URL = u.String()
	}
	return err
}

// getJSON fetches rawURL and decodes JSON into v, turning HTTP errors into readable ones.
func getJSON(ctx context.Context, source, rawURL string, headers map[string]string, v any) error {
	body, status, err := ctGet(ctx, rawURL, headers)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	switch {
	case status == http.StatusTooManyRequests:
		return fmt.Errorf("%s: quota or rate limit reached", source)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%s: key refused or missing (HTTP %d)", source, status)
	case status != http.StatusOK:
		return fmt.Errorf("%s: HTTP %d: %s", source, status, truncate(strings.TrimSpace(string(body)), 150))
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%s: unexpected answer: %w", source, err)
	}
	return nil
}

func requireKey(source, key string) error {
	if key == "" {
		return fmt.Errorf("%s: API key required (free account)", source)
	}
	return nil
}

// fetchCrtName queries the crt.name index (CT logs plus other public sources).
// The domain must be an apex (eTLD+1).
func fetchCrtName(ctx context.Context, domain, _ string) ([]string, error) {
	var rows []struct {
		Sub string `json:"sub"`
	}
	if err := getJSON(ctx, "crt.name", "https://crt.name/v1/search?format=json&apex="+url.QueryEscape(domain), nil, &rows); err != nil {
		return nil, err
	}
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Sub
	}
	return names, nil
}

// fetchCrtSh queries crt.sh, which is often slow or overloaded: short timeout, one retry.
func fetchCrtSh(ctx context.Context, domain, _ string) ([]string, error) {
	u := "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		actx, cancel := context.WithTimeout(ctx, 30*time.Second)
		var rows []struct {
			NameValue  string `json:"name_value"`
			CommonName string `json:"common_name"`
		}
		err := getJSON(actx, "crt.sh", u, nil, &rows)
		cancel()
		if err == nil {
			var names []string
			for _, r := range rows {
				names = append(names, strings.Split(r.NameValue, "\n")...)
				names = append(names, r.CommonName)
			}
			return names, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt < 2 {
			time.Sleep(2 * time.Second)
		}
	}
	if errors.Is(lastErr, context.DeadlineExceeded) {
		lastErr = errors.New("crt.sh: no answer after 30 s (server overloaded)")
	}
	return nil, lastErr
}

// fetchCertSpotter queries the SSLMate Cert Spotter API, following pagination.
func fetchCertSpotter(ctx context.Context, domain, key string) ([]string, error) {
	var headers map[string]string
	if key != "" {
		headers = map[string]string{"Authorization": "Bearer " + key}
	}
	var names []string
	after := ""
	for page := 0; page < 50; page++ {
		u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) +
			"&include_subdomains=true&expand=dns_names"
		if after != "" {
			u += "&after=" + url.QueryEscape(after)
		}
		var rows []struct {
			ID       string   `json:"id"`
			DNSNames []string `json:"dns_names"`
		}
		if err := getJSON(ctx, "certspotter", u, headers, &rows); err != nil {
			return names, err
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			names = append(names, r.DNSNames...)
		}
		after = rows[len(rows)-1].ID
	}
	return names, nil
}

// fetchHackerTarget queries the HackerTarget host search (plain text "host,ip" lines).
func fetchHackerTarget(ctx context.Context, domain, key string) ([]string, error) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(domain)
	if key != "" {
		u += "&apikey=" + url.QueryEscape(key)
	}
	body, status, err := ctGet(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("hackertarget: %w", err)
	}
	text := strings.TrimSpace(string(body))
	if status != http.StatusOK || strings.HasPrefix(text, "error") || strings.Contains(text, "API count exceeded") {
		return nil, fmt.Errorf("hackertarget: %s", truncate(text, 150))
	}
	var names []string
	for _, line := range strings.Split(text, "\n") {
		host, _, _ := strings.Cut(line, ",")
		names = append(names, host)
	}
	return names, nil
}

// fetchURLScan searches urlscan.io for pages on the domain, following pagination.
func fetchURLScan(ctx context.Context, domain, key string) ([]string, error) {
	var headers map[string]string
	size := 100
	if key != "" {
		headers = map[string]string{"API-Key": key}
		size = 1000
	}
	var names []string
	after := ""
	for page := 0; page < 5; page++ {
		u := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=%s&size=%d", url.QueryEscape("domain:"+domain), size)
		if after != "" {
			u += "&search_after=" + url.QueryEscape(after)
		}
		var res struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
				Task struct {
					Domain string `json:"domain"`
				} `json:"task"`
				Sort []any `json:"sort"`
			} `json:"results"`
			HasMore bool `json:"has_more"`
		}
		if err := getJSON(ctx, "urlscan", u, headers, &res); err != nil {
			return names, err
		}
		for _, r := range res.Results {
			names = append(names, r.Page.Domain, r.Task.Domain)
		}
		if !res.HasMore || len(res.Results) == 0 {
			break
		}
		var parts []string
		for _, v := range res.Results[len(res.Results)-1].Sort {
			parts = append(parts, fmt.Sprint(v))
		}
		after = strings.Join(parts, ",")
	}
	return names, nil
}

// fetchWayback lists the hostnames of the URLs archived by the Wayback Machine.
// The archive is slow: the answer is capped at 6000 URLs (about 20 s), so the
// result is partial on large domains.
func fetchWayback(ctx context.Context, domain, _ string) ([]string, error) {
	u := "https://web.archive.org/cdx/search/cdx?url=" + url.QueryEscape(domain) +
		"&matchType=domain&fl=original&collapse=urlkey&output=json&limit=6000"
	actx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var rows [][]string
	if err := getJSON(actx, "wayback", u, nil, &rows); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || actx.Err() != nil {
			return nil, errors.New("wayback: no answer after 60 s (archive overloaded)")
		}
		return nil, err
	}
	var names []string
	for i, r := range rows {
		if i == 0 || len(r) == 0 { // header row
			continue
		}
		names = append(names, urlHost(r[0]))
	}
	return names, nil
}

// urlHost extracts the host from a possibly malformed archived URL.
func urlHost(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.LastIndex(raw, "@"); i >= 0 {
		raw = raw[i+1:]
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	return raw
}

// fetchVirusTotal lists the subdomains known to VirusTotal. The free API allows
// 4 requests per minute, so pages are spaced out and limited.
func fetchVirusTotal(ctx context.Context, domain, key string) ([]string, error) {
	if err := requireKey("virustotal", key); err != nil {
		return nil, err
	}
	var names []string
	u := "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(domain) + "/subdomains?limit=40"
	for page := 0; page < 4 && u != ""; page++ {
		if page > 0 {
			select {
			case <-time.After(16 * time.Second):
			case <-ctx.Done():
				return names, ctx.Err()
			}
		}
		var res struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if err := getJSON(ctx, "virustotal", u, map[string]string{"x-apikey": key}, &res); err != nil {
			return names, err
		}
		for _, d := range res.Data {
			names = append(names, d.ID)
		}
		u = res.Links.Next
	}
	return names, nil
}

// fetchDNSDumpster reads the DNS records found by DNSDumpster. Every "host" field in
// the answer is taken, whatever the record type.
func fetchDNSDumpster(ctx context.Context, domain, key string) ([]string, error) {
	if err := requireKey("dnsdumpster", key); err != nil {
		return nil, err
	}
	var res any
	u := "https://api.dnsdumpster.com/domain/" + url.PathEscape(domain)
	if err := getJSON(ctx, "dnsdumpster", u, map[string]string{"X-API-Key": key}, &res); err != nil {
		return nil, err
	}
	var names []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				if s, ok := x.(string); ok && k == "host" {
					names = append(names, s)
				} else {
					walk(x)
				}
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	walk(res)
	return names, nil
}

// fetchDomScan reads the DomScan subdomain finder. Each page costs 4-5 of the 1,000 free
// monthly credits, so at most 3 pages of 500 names are read. A 202 answer means the
// lookup is still running: it is retried a few times.
func fetchDomScan(ctx context.Context, domain, key string) ([]string, error) {
	if err := requireKey("domscan", key); err != nil {
		return nil, err
	}
	headers := map[string]string{"X-API-Key": key}
	var names []string
	cursor := ""
	for page := 0; page < 3; page++ {
		u := "https://domscan.net/v1/subdomains?limit=500&domain=" + url.QueryEscape(domain)
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		var body []byte
		var status int
		var err error
		for attempt := 0; attempt < 4; attempt++ {
			body, status, err = ctGet(ctx, u, headers)
			if err != nil || status != http.StatusAccepted {
				break
			}
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return names, ctx.Err()
			}
		}
		switch {
		case err != nil:
			return names, fmt.Errorf("domscan: %w", err)
		case status == http.StatusPaymentRequired:
			return names, errors.New("domscan: plus de crédits ce mois-ci (1 000 gratuits/mois)")
		case status == http.StatusTooManyRequests:
			return names, errors.New("domscan: rate limit reached")
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			return names, fmt.Errorf("domscan: key refused (HTTP %d)", status)
		case status == http.StatusAccepted:
			return names, errors.New("domscan: lookup still running, try again in a minute")
		case status != http.StatusOK:
			return names, fmt.Errorf("domscan: HTTP %d: %s", status, truncate(strings.TrimSpace(string(body)), 150))
		}
		var res struct {
			Subdomains []struct {
				Name string `json:"name"`
			} `json:"subdomains"`
			HasMore    bool   `json:"has_more"`
			NextCursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return names, fmt.Errorf("domscan: unexpected answer: %w", err)
		}
		for _, s := range res.Subdomains {
			names = append(names, s.Name)
		}
		if !res.HasMore || res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	return names, nil
}

// fetchViewDNS reads the ViewDNS subdomain discovery API (1,000 names per page, one query
// each). At most 2 pages are read so the trial quota lasts.
func fetchViewDNS(ctx context.Context, domain, key string) ([]string, error) {
	if err := requireKey("viewdns", key); err != nil {
		return nil, err
	}
	var names []string
	for page := 1; page <= 2; page++ {
		u := fmt.Sprintf("https://api.viewdns.info/subdomains/?output=json&page=%d&domain=%s&apikey=%s",
			page, url.QueryEscape(domain), url.QueryEscape(key))
		var res struct {
			Response struct {
				Error      string `json:"error"`
				TotalPages string `json:"total_pages"`
				Subdomains []struct {
					Name string `json:"name"`
				} `json:"subdomains"`
			} `json:"response"`
		}
		if err := getJSON(ctx, "viewdns", u, nil, &res); err != nil {
			return names, err
		}
		if res.Response.Error != "" {
			return names, errors.New("viewdns: " + res.Response.Error)
		}
		for _, s := range res.Response.Subdomains {
			names = append(names, s.Name)
		}
		if total, _ := strconv.Atoi(res.Response.TotalPages); page >= total {
			break
		}
	}
	return names, nil
}

// fetchShodanDNS lists the subdomains Shodan knows for the domain (key required,
// 1 query credit). The API returns labels, "" being the domain itself.
func fetchShodanDNS(ctx context.Context, domain, key string) ([]string, error) {
	if err := requireKey("shodan", key); err != nil {
		return nil, err
	}
	var res struct {
		Subdomains []string `json:"subdomains"`
	}
	u := "https://api.shodan.io/dns/domain/" + url.PathEscape(domain) + "?key=" + url.QueryEscape(key)
	if err := getJSON(ctx, "shodan", u, nil, &res); err != nil {
		return nil, err
	}
	names := []string{domain}
	for _, s := range res.Subdomains {
		if s != "" {
			names = append(names, s+"."+domain)
		}
	}
	return names, nil
}

type ctOptions struct {
	Sources     []string
	Keys        Keys
	Resolve     bool // keep only names that resolve in DNS
	PrivateOnly bool // keep only names that resolve to private / internal IPs
}

// ctLookup returns the unique hostnames found by the passive sources for the given domains.
func ctLookup(ctx context.Context, domains []string, opt ctOptions, logf func(string, ...any)) []string {
	set := map[string]bool{}
	for _, raw := range domains {
		domain := normalizeDomain(raw)
		if domain == "" {
			continue
		}
		// Sources are queried in parallel: a slow one does not delay the others
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, name := range opt.Sources {
			src, ok := findSubSource(strings.TrimSpace(name))
			if !ok {
				logf("[src] unknown source %q (available: %s)", name, strings.Join(subSourceNames(), ", "))
				continue
			}
			logf("[src] %s: querying %s...", domain, src.Name)
			wg.Add(1)
			go func(src subSource) {
				defer wg.Done()
				start := time.Now()
				names, err := src.fetch(ctx, domain, opt.Keys.get(src.Name))
				mu.Lock()
				defer mu.Unlock()
				seen := map[string]bool{}
				kept := 0
				for _, n := range names {
					if h, ok := cleanCTName(n, domain); ok && !seen[h] {
						seen[h] = true
						if !set[h] {
							set[h] = true
							kept++
						}
					}
				}
				if err != nil {
					logf("[src] %s: %v", domain, err) // errors already name their source
				}
				logf("[src] %s: %s -> %d names (%d new) in %.0f s", domain, src.Name, len(seen), kept, time.Since(start).Seconds())
			}(src)
		}
		wg.Wait()
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)

	if opt.Resolve || opt.PrivateOnly {
		before := len(names)
		names = filterResolving(ctx, names, opt.PrivateOnly)
		what := "resolve in DNS"
		if opt.PrivateOnly {
			what = "resolve to a private IP"
		}
		logf("[src] %d/%d names %s", len(names), before, what)
	}
	return names
}

// filterResolving keeps names that resolve (to a private address if privateOnly).
func filterResolving(ctx context.Context, names []string, privateOnly bool) []string {
	keep := make([]bool, len(names))
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, n string) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			addrs, err := net.DefaultResolver.LookupIPAddr(lctx, n)
			if err != nil {
				return
			}
			for _, a := range addrs {
				if !privateOnly || isInternalIP(a.IP) {
					keep[i] = true
					return
				}
			}
		}(i, n)
	}
	wg.Wait()
	var out []string
	for i, n := range names {
		if keep[i] {
			out = append(out, n)
		}
	}
	return out
}

func isInternalIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
