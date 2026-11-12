package main

// Deeper reconnaissance on the services found:
//   - sensitive files exposed (-files, active, list in files.txt, each answer checked against a
//     signature so a custom 404 page is not taken for a find)
//   - JavaScript of the pages (scripts already downloaded by the browser, no extra request):
//     API paths, internal URLs, secrets (masked in every output)
//   - robots.txt, sitemap.xml, security.txt (3 light requests per service)
//   - subdomain takeover: CNAME towards a cloud service that no longer exists
//   - banners of non-web services (SSH, FTP, SMTP, POP, IMAP, MySQL, Redis, VNC, RDP...)
//   - known default credentials (a list to check by hand, nothing is tried)
//   - port presets: web, services

import (
	"context"
	_ "embed"
	"fmt"
	"html"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// --- Port presets ----------------------------------------------------------------------------

var portPresets = map[string][]int{
	"web": {80, 81, 82, 88, 280, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2083, 2086, 2087, 2095,
		2096, 2480, 3000, 3001, 3128, 3333, 4000, 4001, 4002, 4100, 4243, 4443, 4567, 4711, 4712, 4848,
		4993, 5000, 5001, 5104, 5108, 5601, 5800, 5985, 6543, 7000, 7001, 7002, 7396, 7443, 7474, 8000,
		8001, 8008, 8009, 8014, 8042, 8069, 8080, 8081, 8082, 8083, 8088, 8090, 8091, 8118, 8123, 8172,
		8181, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9001, 9043, 9060,
		9080, 9090, 9091, 9200, 9443, 9800, 9981, 10000, 10443, 12443, 15672, 16080, 18091, 18092,
		20720, 28017},
	"services": {21, 22, 23, 25, 110, 143, 389, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389,
		5432, 5900, 6379, 9042, 11211, 27017},
}

// --- Default credentials (hints only, never tried) ------------------------------------------

var defaultCreds = map[string]string{
	"Apache Tomcat":           "manager : tomcat/tomcat, admin/admin, tomcat/s3cret",
	"Grafana":                 "admin/admin",
	"RabbitMQ":                "guest/guest (accepté seulement depuis localhost par défaut)",
	"phpMyAdmin":              "root/(vide), root/root",
	"Webmin":                  "root avec le mot de passe système",
	"Kibana":                  "elastic/changeme (anciennes versions)",
	"SonarQube":               "admin/admin",
	"Nexus Repository":        "admin/admin123 (anciennes versions)",
	"Jenkins":                 "pas de défaut : mot de passe initial dans secrets/initialAdminPassword",
	"Portainer":               "compte admin créé à la première connexion : vérifier que l'assistant n'est pas ouvert",
	"Prometheus":              "aucune authentification par défaut",
	"Fortinet FortiGate":      "admin/(vide) (anciennes versions)",
	"Citrix NetScaler":        "nsroot/nsroot",
	"F5 BIG-IP":               "admin/admin, root/default",
	"Palo Alto GlobalProtect": "admin/admin (interface d'administration)",
	"GitLab":                  "root défini à l'installation (initial_root_password)",
	"WordPress":               "pas de défaut ; énumération des comptes via /wp-json/wp/v2/users",
	"Keycloak":                "admin défini à l'installation",
	"Redis":                   "aucune authentification par défaut",
	"MySQL":                   "root/(vide) sur les anciennes installations",
	"Zimbra":                  "pas de défaut",
}

const maxRead = 65536

func maskSecret(s string) string {
	r := []rune(s)
	if len(r) > 12 {
		return string(r[:4]) + "…" + string(r[len(r)-4:])
	}
	return string(r[:min(2, len(r))]) + "…"
}

func joinURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return base + ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return base + ref
	}
	return b.ResolveReference(r).String()
}

// --- Common folders (-dirs) and sensitive files (-files) --------------------------------------

//go:embed dirs.txt
var builtinDirs string

//go:embed files.txt
var builtinFiles string

func dirWords(custom []string) []string {
	lines := custom
	if lines == nil {
		lines = strings.Split(strings.ReplaceAll(builtinDirs, "\r", ""), "\n")
	}
	var out []string
	seen := map[string]bool{}
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		w := strings.Trim(strings.TrimSpace(strings.SplitN(l, "#", 2)[0]), "/")
		if w != "" && !seen[w] {
			seen[w] = true
			out = append(out, w+"/")
		}
	}
	return out
}

type FileRule struct {
	Path, Severity string
	rx             *regexp.Regexp
}

var severityRank = map[string]int{"critique": 0, "haute": 1, "moyenne": 2, "info": 3}

func fileRules(custom []string) []FileRule {
	lines := custom
	if lines == nil {
		lines = strings.Split(strings.ReplaceAll(builtinFiles, "\r", ""), "\n")
	}
	var out []FileRule
	for _, l := range lines {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		parts := strings.Split(l, "\t")
		path := strings.TrimLeft(strings.TrimSpace(parts[0]), "/")
		sev := "moyenne"
		if len(parts) > 1 {
			if s := strings.ToLower(strings.TrimSpace(parts[1])); severityRank[s] > 0 || s == "critique" {
				sev = s
			}
		}
		var rx *regexp.Regexp
		if len(parts) > 2 && parts[2] != "" {
			var err error
			if rx, err = regexp.Compile(parts[2]); err != nil {
				continue // invalid signature (or a construct RE2 does not support): skip the line
			}
		}
		if path != "" {
			out = append(out, FileRule{Path: path, Severity: sev, rx: rx})
		}
	}
	return out
}

// latin1 maps every byte to one rune, so signatures like ^PK\x03\x04 match binary files.
func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

type FileFound struct {
	URL      string `json:"url"`
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Size     int    `json:"size"`
}

func (w *webState) probeFiles(ctx context.Context, base, ua string, rules []FileRule, limiter *rateLimiter) []FileFound {
	rnd := fmt.Sprintf("netshot-%d.txt", rand.Int63())
	baseLen := -1
	if st, _, body, err := w.get(ctx, joinURL(base, rnd), ua, 2, maxRead); err == nil && (st == 200 || st == 206) {
		baseLen = len(body)
	}
	var mu sync.Mutex
	var found []FileFound
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, rule := range rules {
		wg.Add(1)
		go func(rule FileRule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if limiter.wait(ctx) != nil {
				return
			}
			u := joinURL(base, rule.Path)
			st, _, body, err := w.get(ctx, u, ua, 0, maxRead)
			if err != nil || (st != 200 && st != 206) {
				return
			}
			ok := false
			if rule.rx != nil {
				ok = rule.rx.MatchString(latin1(body))
			} else {
				ok = len(strings.TrimSpace(string(body))) > 0 && (baseLen < 0 || abs(len(body)-baseLen) > 64)
			}
			if ok {
				mu.Lock()
				found = append(found, FileFound{URL: u, Path: rule.Path, Severity: rule.Severity, Size: len(body)})
				mu.Unlock()
			}
		}(rule)
	}
	wg.Wait()
	sort.Slice(found, func(i, j int) bool {
		if severityRank[found[i].Severity] != severityRank[found[j].Severity] {
			return severityRank[found[i].Severity] < severityRank[found[j].Severity]
		}
		return found[i].Path < found[j].Path
	})
	return found
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// probeDirs returns the folders that answer with a directory listing.
func (w *webState) probeDirs(ctx context.Context, base, ua string, words []string, limiter *rateLimiter) []string {
	var mu sync.Mutex
	var found []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, word := range words {
		wg.Add(1)
		go func(word string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if limiter.wait(ctx) != nil {
				return
			}
			u := joinURL(base, word)
			st, ctype, body, err := w.get(ctx, u, ua, 2, 200000)
			if err == nil && st == 200 && (ctype == "" || strings.Contains(ctype, "html")) && isIndexPage(string(body)) {
				mu.Lock()
				found = append(found, u)
				mu.Unlock()
			}
		}(word)
	}
	wg.Wait()
	sort.Strings(found)
	return found
}

// --- robots.txt, sitemap.xml, security.txt ------------------------------------------------------

type WellKnown struct {
	Robots        []string            `json:"robots,omitempty"`
	Sitemaps      []string            `json:"sitemaps,omitempty"`
	SitemapURLs   int                 `json:"sitemap_urls,omitempty"`
	SitemapSample []string            `json:"sitemap_sample,omitempty"`
	Security      map[string][]string `json:"security,omitempty"`
}

func (k *WellKnown) empty() bool {
	return k == nil || (len(k.Robots) == 0 && len(k.Sitemaps) == 0 && k.SitemapURLs == 0 && len(k.Security) == 0)
}

var (
	robotsRx  = regexp.MustCompile(`(?im)^(user-agent|disallow|allow|sitemap)\s*:`)
	locRx     = regexp.MustCompile(`<loc>\s*([^<\s]+)\s*</loc>`)
	contactRx = regexp.MustCompile(`(?im)^contact\s*:`)
)

func (w *webState) wellKnown(ctx context.Context, base, ua string) *WellKnown {
	out := &WellKnown{}
	if st, ctype, body, err := w.get(ctx, joinURL(base, "robots.txt"), ua, 2, maxRead); err == nil && (st == 200 || st == 206) &&
		!strings.Contains(ctype, "html") && robotsRx.Match(body) {
		for _, line := range strings.Split(string(body), "\n") {
			k, v, _ := strings.Cut(line, ":")
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.TrimSpace(strings.SplitN(v, "#", 2)[0])
			switch {
			case (k == "disallow" || k == "allow") && v != "" && v != "/" && !containsStr(out.Robots, v) && len(out.Robots) < 200:
				out.Robots = append(out.Robots, v)
			case k == "sitemap" && v != "" && len(out.Sitemaps) < 20:
				out.Sitemaps = append(out.Sitemaps, joinURL(base, v))
			}
		}
	}
	sm := joinURL(base, "sitemap.xml")
	if len(out.Sitemaps) > 0 {
		sm = out.Sitemaps[0]
	}
	if st, _, body, err := w.get(ctx, sm, ua, 2, maxRead); err == nil && (st == 200 || st == 206) && strings.Contains(string(body), "<loc>") {
		locs := locRx.FindAllStringSubmatch(string(body), -1)
		out.SitemapURLs = len(locs)
		for i, m := range locs {
			if i == 15 {
				break
			}
			out.SitemapSample = append(out.SitemapSample, m[1])
		}
	}
	for _, p := range []string{".well-known/security.txt", "security.txt"} {
		u := joinURL(base, p)
		st, _, body, err := w.get(ctx, u, ua, 2, maxRead)
		if err != nil || (st != 200 && st != 206) || !contactRx.Match(body) {
			continue
		}
		out.Security = map[string][]string{"url": {u}}
		for _, line := range strings.Split(string(body), "\n") {
			k, v, _ := strings.Cut(line, ":")
			k = strings.ToLower(strings.TrimSpace(k))
			if v = strings.TrimSpace(v); v != "" && (k == "contact" || k == "expires" || k == "policy" || k == "encryption" || k == "hiring") {
				out.Security[k] = append(out.Security[k], v)
			}
		}
		break
	}
	if out.empty() {
		return nil
	}
	return out
}

// --- JavaScript analysis ------------------------------------------------------------------------

type Secret struct {
	Type  string `json:"type"`
	Value string `json:"value"` // masked
	Where string `json:"where"`
}

type JSInfo struct {
	Files        []string `json:"files"`
	Endpoints    []string `json:"endpoints"`
	InternalURLs []string `json:"internal_urls"`
	Secrets      []Secret `json:"secrets"`
}

type secretRule struct {
	name    string
	rx      *regexp.Regexp
	generic bool
}

var secretRules = []secretRule{
	{"Clé AWS", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), false},
	{"Clé Google API", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), false},
	{"Jeton Slack", regexp.MustCompile(`\bxox[abposr]-[0-9A-Za-z-]{10,}`), false},
	{"Webhook Slack", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}`), false},
	{"Jeton GitHub", regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}`), false},
	{"Jeton GitLab", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20}\b`), false},
	{"Clé Stripe secrète", regexp.MustCompile(`\b(sk|rk)_live_[0-9A-Za-z]{20,}`), false},
	{"Clé SendGrid", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`), false},
	{"Clé Mailgun", regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`), false},
	{"Clé Twilio", regexp.MustCompile(`\bSK[0-9a-f]{32}\b`), false},
	{"Clé privée", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), false},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), false},
	{"Chaîne de connexion", regexp.MustCompile(`\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^\s"'<>:/]+:[^\s"'<>@/]+@[^\s"'<>]+`), false},
	{"Azure SAS / clé de stockage", regexp.MustCompile(`AccountKey=[A-Za-z0-9+/=]{40,}|[?&]sig=[A-Za-z0-9%+/=]{30,}`), false},
	{"Secret générique", regexp.MustCompile(`(?i)["']?(api[_-]?key|api[_-]?secret|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/=!@#$%^&*.]{12,})["']`), true},
}

var (
	placeholderRx  = regexp.MustCompile(`(?i)^(x+|\*+|your|example|changeme|placeholder|undefined|null|true|false|test)`)
	endpointRx     = regexp.MustCompile("[\"'`](/(?:api|rest|graphql|v\\d+|internal|admin|private|auth|oauth|ws|services?)(?:/[A-Za-z0-9_\\-.{}:$]*)*)(?:\\?[^\"'`\\s]*)?[\"'`]")
	jsURLRx        = regexp.MustCompile("https?://[A-Za-z0-9._\\-]+(?::\\d+)?(?:/[^\\s\"'`<>()\\\\]*)?")
	internalHostRx = regexp.MustCompile(`(?i)\.(local|lan|corp|internal|intra|intranet|priv|home|localdomain|ad)$`)
	inlineScriptRx = regexp.MustCompile(`(?is)<script([^>]*)>(.*?)</script>`)
)

func isInternalURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Hostname() == "" {
		return false
	}
	h := strings.ToLower(p.Hostname())
	if ip := net.ParseIP(h); ip != nil {
		return isInternalIP(ip)
	}
	return internalHostRx.MatchString(h) || h == "localhost"
}

type jsSource struct{ origin, text string }

func inlineScripts(pageURL, page string) []jsSource {
	var parts []string
	for _, m := range inlineScriptRx.FindAllStringSubmatch(page, -1) {
		if !strings.Contains(strings.ToLower(m[1]), "src=") {
			parts = append(parts, m[2])
		}
	}
	if s := strings.Join(parts, "\n"); strings.TrimSpace(s) != "" {
		return []jsSource{{pageURL + " (inline)", s}}
	}
	return nil
}

func analyzeJS(sources []jsSource) *JSInfo {
	if len(sources) == 0 {
		return nil
	}
	info := &JSInfo{}
	endpoints, internal := map[string]bool{}, map[string]bool{}
	secrets := map[string]bool{}
	for _, s := range sources {
		info.Files = append(info.Files, s.origin)
		for _, m := range endpointRx.FindAllStringSubmatch(s.text, -1) {
			if len(endpoints) < 300 {
				endpoints[m[1]] = true
			}
		}
		for _, u := range jsURLRx.FindAllString(s.text, -1) {
			if isInternalURL(u) && len(internal) < 100 {
				internal[strings.TrimRight(u, ".,;")] = true
			}
		}
		for _, rule := range secretRules {
			for _, loc := range rule.rx.FindAllStringSubmatchIndex(s.text, -1) {
				value := s.text[loc[0]:loc[1]]
				if rule.generic {
					value = s.text[loc[4]:loc[5]]
					if placeholderRx.MatchString(value) || distinctRunes(value) < 6 {
						continue
					}
				}
				if secrets[value] { // specific rules run first: a value is reported once
					continue
				}
				secrets[value] = true
				line := strings.Count(s.text[:loc[0]], "\n") + 1
				info.Secrets = append(info.Secrets, Secret{rule.name, maskSecret(value), fmt.Sprintf("%s:%d", s.origin, line)})
			}
		}
	}
	info.Endpoints = sortedKeys(endpoints)
	info.InternalURLs = sortedKeys(internal)
	if len(info.Endpoints) == 0 && len(info.InternalURLs) == 0 && len(info.Secrets) == 0 {
		return &JSInfo{Files: info.Files}
	}
	return info
}

func distinctRunes(s string) int {
	set := map[rune]bool{}
	for _, r := range s {
		set[r] = true
	}
	return len(set)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sameSite: same host, or same parent domain (last two labels) for host names.
func sameSite(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	ha, hb := strings.ToLower(ua.Hostname()), strings.ToLower(ub.Hostname())
	if ha == "" || hb == "" {
		return false
	}
	if ha == hb {
		return true
	}
	if net.ParseIP(hb) != nil {
		return false
	}
	labels := strings.Split(hb, ".")
	root := strings.Join(labels[max(0, len(labels)-2):], ".")
	return ha == root || strings.HasSuffix(ha, "."+root)
}

// --- Subdomain takeover ------------------------------------------------------------------------

type Takeover struct {
	Host    string `json:"host"`
	CNAME   string `json:"cname"`
	Service string `json:"service"`
	Reason  string `json:"reason"`
	Level   string `json:"level"`
}

var takeoverRules = []struct {
	suffix, service string
	fp              *regexp.Regexp // nil = dangling only when the CNAME target does not exist
}{
	{".s3.amazonaws.com", "AWS S3", regexp.MustCompile(`NoSuchBucket|The specified bucket does not exist`)},
	{".s3-website", "AWS S3 (site)", regexp.MustCompile(`NoSuchBucket`)},
	{".github.io", "GitHub Pages", regexp.MustCompile(`There isn't a GitHub Pages site here`)},
	{".herokuapp.com", "Heroku", regexp.MustCompile(`no-such-app|No such app`)},
	{".herokudns.com", "Heroku", regexp.MustCompile(`no-such-app|No such app`)},
	{".azurewebsites.net", "Azure App Service", nil},
	{".cloudapp.net", "Azure Cloud Service", nil},
	{".cloudapp.azure.com", "Azure VM", nil},
	{".trafficmanager.net", "Azure Traffic Manager", nil},
	{".blob.core.windows.net", "Azure Blob", regexp.MustCompile(`The specified resource does not exist|BlobServiceProperties|InvalidQueryParameterValue`)},
	{".azureedge.net", "Azure CDN", nil},
	{".azure-api.net", "Azure API Management", nil},
	{".azurefd.net", "Azure Front Door", nil},
	{".elasticbeanstalk.com", "AWS Elastic Beanstalk", nil},
	{".wordpress.com", "WordPress.com", regexp.MustCompile(`Do you want to register`)},
	{".ghost.io", "Ghost", regexp.MustCompile(`The thing you were looking for is no longer here`)},
	{".pantheonsite.io", "Pantheon", regexp.MustCompile(`The gods are wise`)},
	{".zendesk.com", "Zendesk", regexp.MustCompile(`Help Center Closed`)},
	{".myshopify.com", "Shopify", regexp.MustCompile(`Sorry, this shop is currently unavailable`)},
	{".fastly.net", "Fastly", regexp.MustCompile(`Fastly error: unknown domain`)},
	{".surge.sh", "Surge", regexp.MustCompile(`project not found`)},
	{".bitbucket.io", "Bitbucket", regexp.MustCompile(`Repository not found`)},
	{".readthedocs.io", "Read the Docs", regexp.MustCompile(`unknown to Read the Docs`)},
	{".netlify.app", "Netlify", regexp.MustCompile(`Not Found - Request ID`)},
	{".helpscoutdocs.com", "Help Scout", regexp.MustCompile(`No settings were found for this company`)},
	{".helpjuice.com", "Helpjuice", regexp.MustCompile(`We could not find what you're looking for`)},
	{".freshdesk.com", "Freshdesk", regexp.MustCompile(`May be this is still fresh`)},
	{".uservoice.com", "UserVoice", regexp.MustCompile(`This UserVoice subdomain is currently available`)},
	{".teamwork.com", "Teamwork", regexp.MustCompile(`Oops - We didn't find your site`)},
	{".tumblr.com", "Tumblr", regexp.MustCompile(`Whatever you were looking for doesn't currently exist at this address`)},
	{".webflow.io", "Webflow", regexp.MustCompile(`The page you are looking for doesn't exist or has been moved`)},
	{".agilecrm.com", "Agile CRM", regexp.MustCompile(`Sorry, this page is no longer available`)},
	{".ngrok.io", "ngrok", regexp.MustCompile(`Tunnel .* not found`)},
}

func takeoverServers() []string {
	var out []string
	for _, s := range systemDNSServers() {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(strings.Trim(s, "[]"), "53")
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		out = []string{"1.1.1.1:53"}
	}
	return out
}

// cnameChain follows the CNAMEs of name. exists is false only when a resolver positively answers
// NXDOMAIN for the last target: no answer at all proves nothing.
func cnameChain(ctx context.Context, name string, servers []string) (chain []string, exists bool) {
	cur := name
	for i := 0; i < 8; i++ {
		var recs []DNSRecord
		for _, s := range servers {
			r, _, err := dnsQuery(ctx, s, cur, 5, 3*time.Second) // 5 = CNAME
			if err == nil {
				recs = r
				break
			}
		}
		next := ""
		for _, r := range recs {
			if r.Type == "CNAME" {
				next = strings.ToLower(strings.TrimSuffix(r.Data, "."))
				break
			}
		}
		if next == "" {
			break
		}
		chain = append(chain, next)
		cur = next
	}
	if len(chain) == 0 {
		return nil, true
	}
	for _, s := range servers {
		_, rcode, err := dnsQuery(ctx, s, chain[len(chain)-1], 1, 3*time.Second) // A
		if err == nil {
			return chain, rcode != 3
		}
	}
	return chain, true
}

func checkTakeover(ctx context.Context, names []string, pages map[string]string, logf func(string, ...any)) []Takeover {
	servers := takeoverServers()
	type res struct {
		chain  []string
		exists bool
	}
	out := make([]res, len(names))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c, e := cnameChain(ctx, n, servers)
			out[i] = res{c, e}
		}(i, n)
	}
	wg.Wait()
	var found []Takeover
	for i, n := range names {
		chain := out[i].chain
		if len(chain) == 0 {
			continue
		}
		service := ""
		var fp *regexp.Regexp
		for _, r := range takeoverRules {
			for _, c := range chain {
				if strings.Contains(c, r.suffix) {
					service, fp = r.service, r.fp
				}
			}
			if service != "" {
				break
			}
		}
		page := pages[strings.ToLower(n)]
		switch {
		case !out[i].exists:
			level, svc := "moyenne", "inconnu"
			if service != "" {
				level, svc = "haute", service
			}
			found = append(found, Takeover{n, strings.Join(chain, " -> "), svc, "la cible du CNAME n'existe plus (NXDOMAIN)", level})
		case fp != nil && page != "" && fp.MatchString(page):
			found = append(found, Takeover{n, strings.Join(chain, " -> "), service, "la page du service indique une ressource inexistante", "haute"})
		}
	}
	if len(found) > 0 {
		logf("[takeover] %d sous-domaine(s) à vérifier (CNAME orphelin)", len(found))
	}
	return found
}

// --- Banners of non-web services ----------------------------------------------------------------

var bannerRules = []struct {
	name string
	cpes []string
	rx   *regexp.Regexp
}{
	{"OpenSSH", []string{"openbsd:openssh"}, regexp.MustCompile(`SSH-[\d.]+-OpenSSH_([\w.]+)`)},
	{"Dropbear SSH", []string{"dropbear_ssh_project:dropbear_ssh"}, regexp.MustCompile(`SSH-[\d.]+-dropbear_([\d.]+)`)},
	{"SSH", nil, regexp.MustCompile(`^SSH-[\d.]+-(\S+)`)},
	{"vsftpd", []string{"beasts:vsftpd"}, regexp.MustCompile(`vsFTPd ([\d.]+)`)},
	{"ProFTPD", []string{"proftpd:proftpd"}, regexp.MustCompile(`ProFTPD ([\d.]+\w*)`)},
	{"Pure-FTPd", nil, regexp.MustCompile(`Pure-FTPd`)},
	{"FileZilla Server", []string{"filezilla-project:filezilla_server"}, regexp.MustCompile(`FileZilla Server(?: version)? ([\d.]+)`)},
	{"Microsoft FTP", nil, regexp.MustCompile(`Microsoft FTP Service`)},
	{"FTP", nil, regexp.MustCompile(`^220[ -]`)},
	{"Postfix", []string{"postfix:postfix"}, regexp.MustCompile(`ESMTP Postfix`)},
	{"Exim", []string{"exim:exim"}, regexp.MustCompile(`Exim ([\d.]+)`)},
	{"Microsoft Exchange SMTP", nil, regexp.MustCompile(`Microsoft ESMTP MAIL Service`)},
	{"Sendmail", []string{"sendmail:sendmail"}, regexp.MustCompile(`Sendmail ([\d.]+)`)},
	{"Dovecot", []string{"dovecot:dovecot"}, regexp.MustCompile(`Dovecot`)},
	{"POP3", nil, regexp.MustCompile(`^\+OK`)},
	{"IMAP", nil, regexp.MustCompile(`^\* OK`)},
	{"MariaDB", []string{"mariadb:mariadb"}, regexp.MustCompile(`([\d.]+)-MariaDB`)},
	{"MySQL", []string{"oracle:mysql"}, regexp.MustCompile(`(?s)^.{4}\x0a(\d+\.\d+\.\d+)`)},
	{"Redis", []string{"redis:redis"}, regexp.MustCompile(`redis_version:([\d.]+)`)},
	{"Redis", []string{"redis:redis"}, regexp.MustCompile(`^-NOAUTH`)},
	{"Telnet", nil, regexp.MustCompile(`^\xff[\xfb-\xfe]`)},
	{"VNC", nil, regexp.MustCompile(`^RFB (\d{3}\.\d{3})`)},
	{"RDP", nil, regexp.MustCompile(`^\x03\x00`)},
}

var rdpProbe = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0, 0x01, 0, 0x08, 0, 0x03, 0, 0, 0}

// grabBanner reads what a service sends first, or its answer to one harmless probe.
func grabBanner(ctx context.Context, host string, port int, p *Proxy) string {
	talk := func(probe []byte) ([]byte, error) {
		conn, err := dialTCP(ctx, p, host, port, 3*time.Second)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if probe != nil {
			if _, err := conn.Write(probe); err != nil {
				return nil, err
			}
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 2048)
		n, _ := conn.Read(buf)
		return buf[:n], nil
	}
	if port == 3389 {
		b, _ := talk(rdpProbe)
		return latin1(b)
	}
	b, err := talk(nil) // most services speak first (SSH, FTP, SMTP, POP, IMAP, MySQL, VNC)
	if err != nil {
		return ""
	}
	if len(b) == 0 {
		probe := []byte("\r\n")
		if port == 6379 {
			probe = []byte("INFO server\r\n")
		}
		b, _ = talk(probe)
	}
	return latin1(b)
}

func parseBanner(text string) (string, string, []string) {
	for _, r := range bannerRules {
		if m := r.rx.FindStringSubmatch(text); m != nil {
			v := ""
			if len(m) > 1 {
				v = m[1]
			}
			return r.name, v, r.cpes
		}
	}
	return "", "", nil
}

var spacesRx = regexp.MustCompile(`\s+`)

func bannerDisplay(text string) string {
	b := []rune(text)
	for i, c := range b {
		if c < 32 || c >= 127 {
			b[i] = ' '
		}
	}
	return truncate(strings.TrimSpace(spacesRx.ReplaceAllString(string(b), " ")), 160)
}

// --- HTML for report.html -------------------------------------------------------------------------

const reconCSS = `
.sev-critique{background:#b00;color:#fff}.sev-haute{background:#c60;color:#fff}
.sev-moyenne{background:#da3;color:#000}.sev-info{background:#999;color:#fff}
.sev{border-radius:3px;padding:1px 6px;font-size:12px}
code.bn{font-size:12px;background:#eee;padding:1px 4px}
`

func sevBadge(s string) string {
	return fmt.Sprintf(`<span class="sev sev-%s">%s</span>`, html.EscapeString(s), html.EscapeString(s))
}

func filesSection(results []Result) string {
	type row struct {
		rank int
		html string
	}
	var rows []row
	seen := map[string]bool{}
	for _, r := range results {
		for _, f := range r.FilesFound {
			if seen[f.URL] {
				continue
			}
			seen[f.URL] = true
			rows = append(rows, row{severityRank[f.Severity], fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d o</td></tr>`,
				sevBadge(f.Severity), urlLinks([]string{f.URL}, 1), f.Size)})
		}
	}
	if len(rows) == 0 {
		return ""
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].rank < rows[j].rank })
	var sb strings.Builder
	fmt.Fprintf(&sb, `<details open><summary><b>Fichiers sensibles exposés</b> - %d</summary><table><tr><th>Gravité</th><th>URL</th><th>Taille lue</th></tr>`, len(rows))
	for _, r := range rows {
		sb.WriteString(r.html)
	}
	sb.WriteString(`</table></details>`)
	return sb.String()
}

func serviceRoot(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

func jsSection(results []Result) string {
	e := html.EscapeString
	var rows []string
	seen := map[string]bool{}
	nSec := 0
	for _, r := range results {
		js := r.JS
		if js == nil || (len(js.Secrets) == 0 && len(js.Endpoints) == 0 && len(js.InternalURLs) == 0) {
			continue
		}
		root := serviceRoot(r.FinalURL)
		if root == "" || r.FinalURL == "" {
			root = serviceRoot(r.URL)
		}
		if seen[root] {
			continue
		}
		seen[root] = true
		nSec += len(js.Secrets)
		var sec []string
		for _, s := range js.Secrets {
			sec = append(sec, fmt.Sprintf(`<b>%s</b> <code>%s</code> <i>%s</i>`, e(s.Type), e(s.Value), e(s.Where)))
		}
		var eps []string
		for i, ep := range js.Endpoints {
			if i == 40 {
				eps = append(eps, fmt.Sprintf("+%d", len(js.Endpoints)-40))
				break
			}
			eps = append(eps, "<code>"+e(ep)+"</code>")
		}
		var internal []string
		for i, u := range js.InternalURLs {
			if i == 20 {
				break
			}
			internal = append(internal, e(u))
		}
		rows = append(rows, fmt.Sprintf(`<tr><td>%s<br><i>%d script(s)</i></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			urlLinks([]string{r.URL}, 1), len(js.Files), strings.Join(sec, "<br>"), strings.Join(internal, "<br>"), strings.Join(eps, ", ")))
	}
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf(`<details open><summary><b>JavaScript</b> - %d service(s), %d secret(s) possible(s) (valeurs masquées)</summary>`+
		`<table><tr><th>Service</th><th>Secrets possibles</th><th>URL internes</th><th>Chemins d'API</th></tr>%s</table></details>`,
		len(rows), nSec, strings.Join(rows, ""))
}

func wellKnownSection(results []Result) string {
	e := html.EscapeString
	var rows []string
	seen := map[string]bool{}
	for _, r := range results {
		w := r.WellKnown
		if w.empty() {
			continue
		}
		root := serviceRoot(r.URL)
		if seen[root] {
			continue
		}
		seen[root] = true
		var robots []string
		for i, p := range w.Robots {
			if i == 40 {
				robots = append(robots, fmt.Sprintf("+%d", len(w.Robots)-40))
				break
			}
			robots = append(robots, urlLinks([]string{joinURL(root+"/", p)}, 1))
		}
		sm := ""
		if w.SitemapURLs > 0 {
			sm = fmt.Sprintf("%d URL<br>%s", w.SitemapURLs, urlLinks(w.SitemapSample, 8))
		}
		var sec []string
		for _, k := range []string{"contact", "expires", "policy", "encryption", "hiring"} {
			if v := w.Security[k]; len(v) > 0 {
				sec = append(sec, k+" : "+e(strings.Join(v, ", ")))
			}
		}
		rows = append(rows, fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			urlLinks([]string{root + "/"}, 1), strings.Join(robots, "<br>"), sm, strings.Join(sec, "<br>")))
	}
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf(`<details><summary><b>robots.txt, sitemap, security.txt</b> - %d service(s)</summary><table><tr><th>Service</th>`+
		`<th>Chemins de robots.txt</th><th>Sitemap</th><th>security.txt</th></tr>%s</table></details>`, len(rows), strings.Join(rows, ""))
}

func takeoverSection(ts []Takeover) string {
	if len(ts) == 0 {
		return ""
	}
	e := html.EscapeString
	var sb strings.Builder
	fmt.Fprintf(&sb, `<details open><summary><b>Prise de contrôle de sous-domaine possible</b> - %d</summary><table><tr><th>Gravité</th><th>Nom</th><th>Chaîne CNAME</th><th>Service</th><th>Raison</th></tr>`, len(ts))
	for _, t := range ts {
		fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, sevBadge(t.Level), e(t.Host), e(t.CNAME), e(t.Service), e(t.Reason))
	}
	sb.WriteString(`</table></details>`)
	return sb.String()
}

func bannersSection(results []Result) string {
	e := html.EscapeString
	var rows []string
	seen := map[string]bool{}
	for _, r := range results {
		k := fmt.Sprintf("%s:%d", r.Host, r.Port)
		if (r.Banner == "" && r.Service == "") || seen[k] {
			continue // one line per service, not per user agent
		}
		seen[k] = true
		svc := r.Service
		if svc == "" {
			svc = "?"
		}
		rows = append(rows, fmt.Sprintf(`<tr><td>%s:%d</td><td>%s</td><td>%s</td><td><code class="bn">%s</code></td><td>%s</td></tr>`,
			e(r.Host), r.Port, e(svc), e(r.ServiceVersion), e(r.Banner), e(defaultCreds[r.Service])))
	}
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf(`<details open><summary><b>Services non web</b> - %d</summary><table><tr><th>Service</th><th>Produit</th>`+
		`<th>Version</th><th>Bannière</th><th>Identifiants par défaut connus</th></tr>%s</table></details>`, len(rows), strings.Join(rows, ""))
}
