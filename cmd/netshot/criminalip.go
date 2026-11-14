package main

// Criminal IP (key "criminalip", free account: 50 IP lookups and 100 URL scans per month), run with the
// reputation of the host names. Credits are scarce, so each scan spends little:
//   - IP: /v1/feature/ip/suspicious-info on the first -criminalip-ips public IPs (default 5), those that
//     carry the most services first: inbound / outbound score, VPN / Tor / proxy / scanner / Snort tags,
//     abuse records.
//   - domain: one "lite" scan (/v1/domain/lite/scan, then progress, then report) on the first
//     -criminalip-domains registrable domains (default 1), the most scanned first: domain score,
//     phishing probability, malware / phishing classification, punycode, fake https.
// Internal IPs and names that resolve to internal IPs are never sent.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CIPLimits caps the Criminal IP lookups of one scan (0 = none of that kind).
type CIPLimits struct {
	IPs, Domains int
}

var cipBase = "https://api.criminalip.io"

// Default caps, fitted to the free account (50 IP lookups, 100 domain scans per month).
const (
	defaultCIPIPs     = 5
	defaultCIPDomains = 1
)

// cipGet calls the Criminal IP API and decodes the answer. The API also returns its own "status".
func cipGet(ctx context.Context, path string, q url.Values, key string, out any) error {
	u := cipBase + path
	if q != nil {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := repClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var st struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &st)
	code := resp.StatusCode
	if code == 200 && st.Status != 0 {
		code = st.Status
	}
	switch {
	case code == 200:
	case code == 401:
		return fmt.Errorf("Criminal IP : clé refusée (HTTP 401)")
	case code == 403 || code == 429:
		return fmt.Errorf("Criminal IP : crédits épuisés ou limite atteinte (HTTP %d)", code)
	default:
		msg := strings.TrimSpace(st.Message)
		if msg == "" {
			msg = "HTTP " + strconv.Itoa(code)
		}
		return fmt.Errorf("Criminal IP : %s", msg)
	}
	return json.Unmarshal(body, out)
}

// cipScore reads a score given as a word ("Dangerous") or a number (1 safe ... 5 critical).
func cipScore(v any) string {
	switch s := v.(type) {
	case string:
		if n, err := strconv.Atoi(s); err == nil {
			return cipScore(float64(n))
		}
		return strings.ToLower(strings.TrimSpace(s))
	case float64:
		return map[int]string{1: "safe", 2: "low", 3: "moderate", 4: "dangerous", 5: "critical"}[int(s)]
	}
	return ""
}

// cipLevel maps a Criminal IP score to the Netshot levels.
func cipLevel(score string) string {
	switch {
	case strings.Contains(score, "critical"):
		return "critique"
	case strings.Contains(score, "dangerous"):
		return "haute"
	case strings.Contains(score, "moderate"):
		return "moyenne"
	}
	return ""
}

// worse returns the more severe of two levels.
func worse(a, b string) string {
	if levelRank(b) < levelRank(a) {
		return b
	}
	return a
}

// cipIP looks up one IP: summary and level (from the outbound score, what the IP does to others,
// and the inbound score, what is aimed at it).
func cipIP(ctx context.Context, ip, key string) (string, string, error) {
	var res struct {
		Score struct {
			Inbound  any `json:"inbound"`
			Outbound any `json:"outbound"`
		} `json:"score"`
		Issues      map[string]any `json:"issues"`
		AbuseCount  int            `json:"abuse_record_count"`
		Representat string         `json:"representative_domain"`
	}
	if err := cipGet(ctx, "/v1/feature/ip/suspicious-info", url.Values{"ip": {ip}}, key, &res); err != nil {
		return "", "", err
	}
	in, out := cipScore(res.Score.Inbound), cipScore(res.Score.Outbound)
	var tags []string
	for k, v := range res.Issues {
		if b, ok := v.(bool); ok && b {
			tags = append(tags, strings.TrimPrefix(k, "is_"))
		}
	}
	sort.Strings(tags)
	parts := []string{"score entrant " + orDash(in) + ", sortant " + orDash(out)}
	if len(tags) > 0 {
		parts = append(parts, strings.Join(tags, ", "))
	}
	if res.AbuseCount > 0 {
		parts = append(parts, fmt.Sprintf("%d signalement(s) d'abus", res.AbuseCount))
	}
	return strings.Join(parts, " ; "), worse(cipLevel(out), cipLevel(in)), nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// cipDomain runs a lite scan of a domain and reads its report (about 10 to 60 s).
func cipDomain(ctx context.Context, domain, key string) (string, string, error) {
	var scan struct {
		Data struct {
			ScanID any `json:"scan_id"`
		} `json:"data"`
	}
	if err := cipGet(ctx, "/v1/domain/lite/scan", url.Values{"query": {domain}}, key, &scan); err != nil {
		return "", "", err
	}
	id := fmt.Sprint(scan.Data.ScanID)
	if scan.Data.ScanID == nil || id == "" {
		return "", "", fmt.Errorf("Criminal IP : pas d'identifiant d'analyse pour %s", domain)
	}
	if f, ok := scan.Data.ScanID.(float64); ok {
		id = strconv.FormatInt(int64(f), 10)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		var prog struct {
			Data struct {
				Pct float64 `json:"scan_percentage"`
			} `json:"data"`
		}
		if err := cipGet(ctx, "/v1/domain/lite/progress", url.Values{"scan_id": {id}}, key, &prog); err != nil {
			return "", "", err
		}
		if prog.Data.Pct >= 100 {
			break
		}
		if prog.Data.Pct < 0 {
			return "", "", fmt.Errorf("Criminal IP : analyse de %s en échec", domain)
		}
		if time.Now().After(deadline) {
			return "", "", fmt.Errorf("Criminal IP : analyse de %s trop longue (abandon après 3 min)", domain)
		}
		select {
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
			return "", "", ctx.Err()
		}
	}
	var rep struct {
		Data struct {
			DomainScore    string `json:"domain_score"`
			Classification struct {
				DomainType any     `json:"domain_type"`
				DGAScore   float64 `json:"dga_score"`
			} `json:"classification"`
			Summary struct {
				PhishingProb float64 `json:"url_phishing_prob"`
				FakeHTTPS    bool    `json:"fake_https_url"`
				Punycode     bool    `json:"punycode"`
				Overlong     bool    `json:"overlong_domain"`
				SymbolURL    bool    `json:"symbol_url"`
				Abuse        struct {
					Critical  int `json:"critical"`
					Dangerous int `json:"dangerous"`
					Moderate  int `json:"moderate"`
				} `json:"abuse_record"`
			} `json:"summary"`
		} `json:"data"`
	}
	if err := cipGet(ctx, "/v1/domain/lite/report/"+url.PathEscape(id), nil, key, &rep); err != nil {
		return "", "", err
	}
	d := rep.Data
	score := strings.ToLower(d.DomainScore)
	level := cipLevel(score)
	parts := []string{"score du domaine " + orDash(d.DomainScore)}
	types := cipTypes(d.Classification.DomainType)
	for _, t := range types {
		if t == "malware" || t == "phishing" {
			level = worse(level, "critique")
		}
	}
	if len(types) > 0 {
		parts = append(parts, "catégorie "+strings.Join(types, ", "))
	}
	if p := d.Summary.PhishingProb; p > 0 {
		parts = append(parts, fmt.Sprintf("probabilité de phishing %.0f %%", p))
		if p >= 70 {
			level = worse(level, "haute")
		}
	}
	if d.Summary.FakeHTTPS {
		parts, level = append(parts, "faux lien https"), worse(level, "haute")
	}
	if d.Summary.Punycode {
		parts = append(parts, "punycode")
	}
	if a := d.Summary.Abuse; a.Critical+a.Dangerous+a.Moderate > 0 {
		parts = append(parts, fmt.Sprintf("IP liées signalées : %d critique(s), %d dangereuse(s), %d modérée(s)", a.Critical, a.Dangerous, a.Moderate))
	}
	return strings.Join(parts, " ; "), level, nil
}

// cipTypes reads domain_type, given as a string or a list.
func cipTypes(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		for _, s := range strings.Split(t, ",") {
			if s = strings.ToLower(strings.TrimSpace(s)); s != "" && s != "none" {
				out = append(out, s)
			}
		}
	case []any:
		for _, x := range t {
			out = append(out, cipTypes(fmt.Sprint(x))...)
		}
	}
	return out
}

// checkCriminalIP adds the Criminal IP findings to the reputation rows: the domain report on the row
// of that domain (created when the domain itself was not scanned), one row per IP looked up.
func checkCriminalIP(ctx context.Context, reps []*Reputation, names []string, exps []*Exposure, results []Result,
	key string, lim CIPLimits, logf func(string, ...any)) []*Reputation {
	if key == "" || (lim.IPs <= 0 && lim.Domains <= 0) {
		return reps
	}
	byHost := map[string]*Reputation{}
	for _, r := range reps {
		byHost[r.Host] = r
	}
	// domains: the registrable domains of the public names, the most frequent first
	count := map[string]int{}
	for _, n := range names {
		if d := registrableDomain(n); d != "" {
			count[d]++
		}
	}
	domains := make([]string, 0, len(count))
	for d := range count {
		domains = append(domains, d)
	}
	sort.Slice(domains, func(i, j int) bool {
		if count[domains[i]] != count[domains[j]] {
			return count[domains[i]] > count[domains[j]]
		}
		return domains[i] < domains[j]
	})
	if len(domains) > lim.Domains {
		domains = domains[:max(0, lim.Domains)]
	}
	// IPs: public ones, those with the most services first
	services := map[string]int{}
	hostsOf := map[string][]string{}
	for _, x := range exps {
		ip := net.ParseIP(x.IP)
		if x.Internal || ip == nil || isInternalIP(ip) {
			continue
		}
		hostsOf[x.IP] = appendUnique(hostsOf[x.IP], x.Hosts...)
	}
	for _, r := range results {
		h := strings.Trim(r.Host, "[]")
		if ip := net.ParseIP(h); ip != nil && !isInternalIP(ip) {
			if _, ok := hostsOf[h]; !ok {
				hostsOf[h] = nil
			}
			services[h]++
			continue
		}
		for ip, hs := range hostsOf {
			if containsStr(hs, r.Host) {
				services[ip]++
			}
		}
	}
	ips := make([]string, 0, len(hostsOf))
	for ip := range hostsOf {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		if services[ips[i]] != services[ips[j]] {
			return services[ips[i]] > services[ips[j]]
		}
		return ips[i] < ips[j]
	})
	skipped := 0
	if len(ips) > lim.IPs {
		skipped = len(ips) - max(0, lim.IPs)
		ips = ips[:max(0, lim.IPs)]
	}
	if len(domains)+len(ips) == 0 {
		return reps
	}
	logf("[criminalip] %d domaine(s), %d IP (offre gratuite : 100 analyses de domaine et 50 IP par mois)", len(domains), len(ips))
	if skipped > 0 {
		logf("[criminalip] %d autre(s) IP publique(s) non vérifiée(s) (limite -criminalip-ips %d)", skipped, lim.IPs)
	}
	stop := false
	for _, d := range domains {
		if ctx.Err() != nil || stop {
			break
		}
		s, level, err := cipDomain(ctx, d, key)
		r := byHost[d]
		if r == nil {
			r = &Reputation{Host: d}
			byHost[d] = r
			reps = append(reps, r)
		}
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
			logf("[criminalip] %s : %v", d, err)
			stop = strings.Contains(err.Error(), "crédits") || strings.Contains(err.Error(), "401")
			continue
		}
		r.CriminalIP, r.CIPLevel = s, level
	}
	for _, ip := range ips {
		if ctx.Err() != nil || stop {
			break
		}
		s, level, err := cipIP(ctx, ip, key)
		r := &Reputation{Host: ip, Names: hostsOf[ip]}
		if err != nil {
			logf("[criminalip] %s : %v", ip, err)
			stop = strings.Contains(err.Error(), "crédits") || strings.Contains(err.Error(), "401")
			continue
		}
		r.CriminalIP, r.CIPLevel = s, level
		reps = append(reps, r)
	}
	return reps
}

func appendUnique(list []string, items ...string) []string {
	for _, s := range items {
		if !containsStr(list, s) {
			list = append(list, s)
		}
	}
	return list
}
