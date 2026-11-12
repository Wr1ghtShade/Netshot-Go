package main

// What a captured web page reveals, without any extra scan:
//   - technologies and versions (headers, cookies, meta generator, scripts, HTML markers), then the
//     CVEs of the versions found (NVD), ranked with CISA KEV and FIRST EPSS
//   - favicon hash (MurmurHash3, same value as Shodan's http.favicon.hash)
//   - sensitive pages: directory listing ("Index of /"), login, admin, default page, debug page
//   - grouping of visually identical captures (difference hash of the screenshot)
//   - security headers and cookie flags
// The only extra request is the favicon. Only product names and versions go to NVD.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"html"
	"image"
	"image/png"
	"math/bits"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Tech is a technology found on a page or in a banner.
type Tech struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	CPEs    []string `json:"cpes"`
	Admin   bool     `json:"admin"`
}

func (t Tech) Label() string { return strings.TrimSpace(t.Name + " " + t.Version) }

type techPattern struct {
	where string // header:<name>, title, html, generator, script, cookie
	rx    *regexp.Regexp
}

type techRule struct {
	name  string
	cpes  []string
	admin bool
	pats  []techPattern
}

const verRx = `(\d+(?:\.\d+)+[a-z]?)`

func tr(name string, cpes []string, admin bool, pats ...string) techRule {
	r := techRule{name: name, cpes: cpes, admin: admin}
	for i := 0; i+1 < len(pats); i += 2 {
		r.pats = append(r.pats, techPattern{pats[i], regexp.MustCompile("(?i)" + strings.ReplaceAll(pats[i+1], "{V}", verRx))})
	}
	return r
}

var techRules = []techRule{
	tr("Apache httpd", []string{"apache:http_server"}, false, "header:server", `\bApache(?:/{V})?(?:[^-\w]|$)`),
	tr("nginx", []string{"f5:nginx", "nginx:nginx"}, false, "header:server", `\bnginx(?:/{V})?`),
	tr("Microsoft IIS", []string{"microsoft:internet_information_services"}, false, "header:server", `Microsoft-IIS(?:/{V})?`),
	tr("Microsoft HTTPAPI", nil, false, "header:server", `Microsoft-HTTPAPI(?:/{V})?`),
	tr("OpenResty", []string{"openresty:openresty"}, false, "header:server", `openresty(?:/{V})?`),
	tr("LiteSpeed", []string{"litespeedtech:litespeed_web_server"}, false, "header:server", `LiteSpeed`),
	tr("lighttpd", []string{"lighttpd:lighttpd"}, false, "header:server", `lighttpd(?:/{V})?`),
	tr("Caddy", nil, false, "header:server", `\bCaddy\b`),
	tr("Envoy", nil, false, "header:server", `\benvoy\b`),
	tr("Kestrel", nil, false, "header:server", `\bKestrel\b`),
	tr("Squid", []string{"squid-cache:squid"}, false, "header:server", `squid(?:/{V})?`, "header:via", `squid(?:/{V})?`),
	tr("Varnish", nil, false, "header:x-varnish", `.`, "header:via", `varnish`),
	tr("OpenSSL", []string{"openssl:openssl"}, false, "header:server", `OpenSSL/{V}`),
	tr("PHP", []string{"php:php"}, false, "header:x-powered-by", `PHP(?:/{V})?`, "header:server", `PHP/{V}`, "cookie", `^PHPSESSID$`),
	tr("Python", []string{"python:python"}, false, "header:server", `\bPython/{V}`),
	tr("Werkzeug", []string{"palletsprojects:werkzeug"}, false, "header:server", `Werkzeug(?:/{V})?`),
	tr("gunicorn", []string{"gunicorn:gunicorn"}, false, "header:server", `gunicorn(?:/{V})?`),
	tr("Express", nil, false, "header:x-powered-by", `^Express$`),
	tr("ASP.NET", nil, false, "header:x-powered-by", `ASP\.NET`, "header:x-aspnet-version", `{V}`, "cookie", `^ASP\.NET_SessionId$`),
	tr("Java servlet", nil, false, "cookie", `^JSESSIONID$`),
	tr("Apache Tomcat", []string{"apache:tomcat"}, false, "title", `Apache Tomcat(?:/{V})?`, "html", `<h3>Apache Tomcat/{V}</h3>`, "header:server", `Apache-Coyote`),
	tr("Jetty", []string{"eclipse:jetty"}, false, "header:server", `Jetty\((?:{V})?`),
	tr("Spring Boot", nil, false, "html", `Whitelabel Error Page`),
	tr("WordPress", []string{"wordpress:wordpress"}, false, "generator", `WordPress\s*{V}?`, "html", `/wp-(?:content|includes)/`),
	tr("Drupal", []string{"drupal:drupal"}, false, "generator", `Drupal\s*(\d+)?`, "header:x-generator", `Drupal\s*(\d+)?`),
	tr("Joomla", nil, false, "generator", `Joomla`),
	tr("Grafana", []string{"grafana:grafana"}, true, "title", `^Grafana\b`, "html", `"buildInfo":\{[^}]*?"version":"{V}`),
	tr("Kibana", []string{"elastic:kibana"}, true, "header:kbn-version", `{V}`, "header:kbn-name", `.`),
	tr("Jenkins", []string{"jenkins:jenkins"}, true, "header:x-jenkins", `{V}`),
	tr("GitLab", []string{"gitlab:gitlab"}, true, "generator", `GitLab`, "html", `content="GitLab"`),
	tr("phpMyAdmin", []string{"phpmyadmin:phpmyadmin"}, true, "title", `phpMyAdmin`),
	tr("Webmin", []string{"webmin:webmin"}, true, "header:server", `MiniServ(?:/{V})?`),
	tr("Confluence", []string{"atlassian:confluence_server", "atlassian:confluence_data_center"}, false,
		"header:x-confluence-request-time", `.`, "html", `name="ajs-version-number" content="{V}"`),
	tr("Jira", nil, false, "html", `name="application-name" content="JIRA"`),
	tr("SonarQube", nil, true, "title", `SonarQube`),
	tr("Nexus Repository", nil, true, "header:server", `Nexus(?:/{V})?`),
	tr("RabbitMQ", nil, true, "title", `RabbitMQ Management`),
	tr("Portainer", nil, true, "title", `^Portainer`),
	tr("Prometheus", nil, true, "title", `Prometheus Time Series`),
	tr("Keycloak", nil, false, "html", `/auth/resources/[^"']+/keycloak|kc-form-login`),
	tr("Outlook Web App", nil, false, "html", `/owa/auth/`, "header:x-owa-version", `{V}`),
	tr("SharePoint", nil, false, "header:microsoftsharepointteamservices", `{V}`),
	tr("Roundcube", nil, false, "html", `rcmloginuser|roundcube_sessid`, "cookie", `^roundcube_sessid$`),
	tr("Nextcloud", nil, false, "html", `nextcloud`, "header:x-nextcloud-well-known", `.`),
	tr("Zimbra", nil, false, "cookie", `^ZM_TEST$`, "title", `Zimbra`),
	tr("Fortinet FortiGate", nil, true, "html", `/remote/login|fgt_lang|ftnt-fortinet`, "cookie", `^SVPNCOOKIE$`),
	tr("Citrix NetScaler", nil, true, "cookie", `^NSC_`, "html", `/vpn/index\.html|/logon/LogonPoint/`),
	tr("Ivanti / Pulse Secure", nil, true, "html", `/dana-na/|/dana/`),
	tr("F5 BIG-IP", nil, true, "cookie", `^BIGipServer`, "header:server", `BigIP`, "html", `/tmui/`),
	tr("Palo Alto GlobalProtect", nil, true, "html", `global-protect|/global-protect/`),
	tr("Cloudflare", nil, false, "header:server", `^cloudflare$`, "header:cf-ray", `.`),
	tr("Akamai", nil, false, "header:server", `AkamaiGHost`),
	tr("jQuery", []string{"jquery:jquery"}, false, "script", `jquery[.-]{V}(?:\.slim)?(?:\.min)?\.js`),
	tr("Bootstrap", []string{"getbootstrap:bootstrap"}, false, "script", `bootstrap[@/.-]{V}`),
	tr("Angular", nil, false, "html", `ng-version="{V}"`),
	tr("React", nil, false, "html", `data-reactroot|__NEXT_DATA__`),
	tr("Vue.js", nil, false, "html", `data-v-[0-9a-f]{8}`),
}

var (
	scriptSrcRx = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)`)
	generatorRx = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)|<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']`)
)

// Header is one response header (Set-Cookie lines stay separate).
type Header struct{ Name, Value string }

func headerMap(hs []Header) map[string]string {
	m := map[string]string{}
	for _, h := range hs {
		n := strings.ToLower(h.Name)
		if v, ok := m[n]; ok {
			m[n] = v + "\n" + h.Value
		} else {
			m[n] = h.Value
		}
	}
	return m
}

type cookieInfo struct{ name, attrs string }

func cookieList(hs []Header) []cookieInfo {
	var out []cookieInfo
	for _, h := range hs {
		if !strings.EqualFold(h.Name, "set-cookie") {
			continue
		}
		for _, line := range strings.Split(h.Value, "\n") {
			first, attrs, _ := strings.Cut(line, ";")
			name, _, _ := strings.Cut(first, "=")
			if name = strings.TrimSpace(name); name != "" {
				out = append(out, cookieInfo{name, strings.ToLower(attrs)})
			}
		}
	}
	return out
}

func detectTech(hs []Header, page, title string) []Tech {
	hm := headerMap(hs)
	var cookies, scripts, gens []string
	for _, c := range cookieList(hs) {
		cookies = append(cookies, c.name)
	}
	for _, m := range scriptSrcRx.FindAllStringSubmatch(page, -1) {
		scripts = append(scripts, m[1])
	}
	for _, m := range generatorRx.FindAllStringSubmatch(page, -1) {
		gens = append(gens, m[1]+m[2])
	}
	var found []Tech
	for _, r := range techRules {
		hit, version := false, ""
		for _, p := range r.pats {
			var texts []string
			switch {
			case strings.HasPrefix(p.where, "header:"):
				texts = []string{hm[p.where[7:]]}
			case p.where == "title":
				texts = []string{title}
			case p.where == "html":
				texts = []string{page}
			case p.where == "generator":
				texts = gens
			case p.where == "script":
				texts = scripts
			default:
				texts = cookies
			}
			for _, t := range texts {
				if t == "" {
					continue
				}
				if m := p.rx.FindStringSubmatch(t); m != nil {
					hit = true
					if version == "" && len(m) > 1 && m[1] != "" {
						version = m[1]
					}
				}
			}
		}
		if hit {
			found = append(found, Tech{Name: r.name, Version: version, CPEs: r.cpes, Admin: r.admin})
		}
	}
	return found
}

// --- Sensitive pages -----------------------------------------------------------------------

var tagOrder = []string{"index-of", "debug", "default", "admin", "login", "auth-http"}

var tagLabels = map[string]string{
	"index-of":  "Index of (liste de fichiers)",
	"debug":     "page de debug / erreur détaillée",
	"default":   "page par défaut",
	"admin":     "interface d'administration",
	"login":     "formulaire de connexion",
	"auth-http": "authentification HTTP",
}

var (
	indexTitleRx = regexp.MustCompile(`(?i)^\s*(Index of /|Directory listing for /|Listing of /)`)
	indexHTMLRx  = regexp.MustCompile(`(?i)<h1>\s*Index of /|\?C=N;O=D|\[To Parent Directory\]|<title>[^<]* - /</title>`)
	defaultRx    = regexp.MustCompile(`(?i)Apache2 (?:Ubuntu|Debian) Default Page|Test Page for the (?:Apache|Nginx) HTTP Server|` +
		`<h1>It works!</h1>|Welcome to nginx!|Welcome to OpenResty!|IIS Windows Server|<title>IIS\d*</title>|` +
		`Internet Information Services|Welcome to CentOS|Welcome to JBoss|Caddy works!|Default Web Site Page|` +
		`Web Server's Default Page|Plesk Obsidian|If you're seeing this, you've successfully installed Tomcat`)
	debugRx = regexp.MustCompile(`(?i)Traceback \(most recent call last\)|Werkzeug Debugger|You're seeing this error because you have ` +
		`<code>DEBUG = True|Whitelabel Error Page|<title>phpinfo\(\)</title>|Fatal error</b>:|Stack Trace:|` +
		`Server Error in '/' Application|Laravel</title>|Symfony Exception`)
	adminTxtRx = regexp.MustCompile(`(?i)\b(admin|administration|administrator|manager|management|console|dashboard|` +
		`backoffice|back-office|webmin|cpanel|plesk|phpmyadmin|portainer|router|firewall)\b`)
	loginTxtRx = regexp.MustCompile(`(?i)\b(log ?in|sign ?in|connexion|se connecter|authentification|authentication|identification|logon)\b`)
	passwordRx = regexp.MustCompile(`(?i)<input[^>]+type=["']?password`)
	titleRx    = regexp.MustCompile(`(?is)<title>([^<]*)</title>`)
)

func isIndexPage(page string) bool {
	if m := titleRx.FindStringSubmatch(page); m != nil && indexTitleRx.MatchString(m[1]) {
		return true
	}
	return indexHTMLRx.MatchString(page)
}

func pageTags(title, page, finalURL string, status int, hs []Header, tech []Tech) []string {
	var tags []string
	if indexTitleRx.MatchString(title) || indexHTMLRx.MatchString(page) {
		tags = append(tags, "index-of")
	}
	if debugRx.MatchString(page) {
		tags = append(tags, "debug")
	}
	head := page
	if len(head) > 20000 {
		head = head[:20000]
	}
	if defaultRx.MatchString(title) || defaultRx.MatchString(head) {
		tags = append(tags, "default")
	}
	path := ""
	if u, err := url.Parse(finalURL); err == nil {
		path = u.Path
	}
	admin := adminTxtRx.MatchString(title) || adminTxtRx.MatchString(path)
	for _, t := range tech {
		admin = admin || t.Admin
	}
	if admin {
		tags = append(tags, "admin")
	}
	if passwordRx.MatchString(page) || loginTxtRx.MatchString(title) {
		tags = append(tags, "login")
	}
	if _, ok := headerMap(hs)["www-authenticate"]; ok || status == 401 {
		tags = append(tags, "auth-http")
	}
	return tags
}

// --- Security headers -------------------------------------------------------------------------

var digitRx = regexp.MustCompile(`\d`)

func headerIssues(finalURL string, hs []Header, page string) []string {
	hm := headerMap(hs)
	https := strings.HasPrefix(strings.ToLower(finalURL), "https://")
	var out []string
	csp := hm["content-security-policy"]
	if _, ok := hm["strict-transport-security"]; https && !ok {
		out = append(out, "HSTS absent")
	}
	if csp == "" {
		out = append(out, "CSP absente")
	}
	if _, ok := hm["x-frame-options"]; !ok && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		out = append(out, "anti-clickjacking absent (X-Frame-Options / frame-ancestors)")
	}
	if strings.ToLower(strings.TrimSpace(hm["x-content-type-options"])) != "nosniff" {
		out = append(out, "X-Content-Type-Options: nosniff absent")
	}
	if _, ok := hm["referrer-policy"]; !ok {
		out = append(out, "Referrer-Policy absente")
	}
	for _, h := range []string{"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"} {
		if v := hm[h]; v != "" && (h != "server" || digitRx.MatchString(v)) {
			out = append(out, fmt.Sprintf("version divulguée (%s: %s)", h, truncate(v, 60)))
		}
	}
	if !https && passwordRx.MatchString(page) {
		out = append(out, "mot de passe saisi en HTTP clair")
	}
	for _, c := range cookieList(hs) {
		var missing []string
		if https && !strings.Contains(c.attrs, "secure") {
			missing = append(missing, "Secure")
		}
		if !strings.Contains(c.attrs, "httponly") {
			missing = append(missing, "HttpOnly")
		}
		if !strings.Contains(c.attrs, "samesite") {
			missing = append(missing, "SameSite")
		}
		if len(missing) > 0 {
			out = append(out, fmt.Sprintf("cookie %s sans %s", c.name, strings.Join(missing, ", ")))
		}
	}
	return out
}

// --- Favicon hash ---------------------------------------------------------------------------------

// mmh3 is MurmurHash3 x86 32 bits, signed (same as the mmh3 Python package).
func mmh3(data []byte) int32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	n := len(data)
	end := n - n%4
	for i := 0; i < end; i += 4 {
		k := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[end:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// faviconHash is Shodan's http.favicon.hash: MurmurHash3 of the base64 text, newline every 76 chars.
func faviconHash(data []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		b.WriteString(enc[i:min(i+76, len(enc))])
		b.WriteByte('\n')
	}
	return mmh3([]byte(b.String()))
}

func shodanFaviconURL(h string) string {
	return "https://www.shodan.io/search?query=" + url.QueryEscape("http.favicon.hash:"+h)
}

const faviconJS = `(() => {
  const l = document.querySelector('link[rel~="icon" i], link[rel="shortcut icon" i], link[rel="apple-touch-icon" i]');
  return l && l.href ? l.href : new URL('/favicon.ico', location.href).href;
})()`

// fetchFavicon downloads the favicon once per URL and returns its hash ("" when none).
func (w *webState) fetchFavicon(ctx context.Context, iconURL, ua string) string {
	if !strings.HasPrefix(iconURL, "http://") && !strings.HasPrefix(iconURL, "https://") {
		return ""
	}
	w.mu.Lock()
	if v, ok := w.favicons[iconURL]; ok {
		w.mu.Unlock()
		return v
	}
	w.mu.Unlock()
	value := ""
	status, ctype, body, err := w.get(ctx, iconURL, ua, 3, 1<<20)
	head := strings.ToLower(strings.TrimLeft(string(body[:min(len(body), 16)]), " \t\r\n"))
	svg := strings.HasPrefix(ctype, "image/svg") || strings.HasPrefix(head, "<svg") || strings.HasPrefix(head, "<?xml")
	if err == nil && status == 200 && len(body) > 0 && !strings.Contains(ctype, "html") && (svg || !strings.HasPrefix(head, "<")) {
		value = fmt.Sprint(faviconHash(body))
	}
	w.mu.Lock()
	w.favicons[iconURL] = value
	w.mu.Unlock()
	return value
}

// --- Visual grouping ----------------------------------------------------------------------------

const phashMaxDistance = 20 // bits out of 256

// screenshotHash is a 256-bit difference hash of the PNG (bottom 40 px left out: the banner).
func screenshotHash(pngData []byte) string {
	img, err := png.Decode(bytes.NewReader(pngData))
	if err != nil {
		return ""
	}
	b := img.Bounds()
	h := max(1, b.Dy()-40)
	const gw, gh = 17, 16
	var grid [gh][gw]float64
	for gy := 0; gy < gh; gy++ {
		y0, y1 := b.Min.Y+gy*h/gh, b.Min.Y+(gy+1)*h/gh
		for gx := 0; gx < gw; gx++ {
			x0, x1 := b.Min.X+gx*b.Dx()/gw, b.Min.X+(gx+1)*b.Dx()/gw
			grid[gy][gx] = blockLuma(img, x0, y0, max(x1, x0+1), max(y1, y0+1))
		}
	}
	var out [32]byte
	bit := 0
	for y := 0; y < gh; y++ {
		for x := 0; x < 16; x++ {
			if grid[y][x] > grid[y][x+1] {
				out[bit/8] |= 1 << (7 - bit%8)
			}
			bit++
		}
	}
	return fmt.Sprintf("%x", out)
}

// blockLuma averages the luminance of a block, sampling at most ~32x32 points.
func blockLuma(img image.Image, x0, y0, x1, y1 int) float64 {
	sx, sy := max(1, (x1-x0)/32), max(1, (y1-y0)/32)
	var sum float64
	n := 0
	for y := y0; y < y1; y += sy {
		for x := x0; x < x1; x += sx {
			r, g, b, _ := img.At(x, y).RGBA()
			sum += 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)
			n++
		}
	}
	return sum / float64(max(1, n))
}

func hashDistance(a, b string) int {
	if len(a) != len(b) {
		return 1 << 20
	}
	d := 0
	for i := 0; i+16 <= len(a); i += 16 {
		var x, y uint64
		fmt.Sscanf(a[i:i+16], "%x", &x)
		fmt.Sscanf(b[i:i+16], "%x", &y)
		d += bits.OnesCount64(x ^ y)
	}
	return d
}

// groupSimilar sets Group / GroupSize on captures that look alike and returns the groups,
// largest first (indexes into results).
func groupSimilar(results []Result) [][]int {
	var idx []int
	for i, r := range results {
		results[i].Group, results[i].GroupSize = 0, 1
		if r.PHash != "" {
			idx = append(idx, i)
		}
	}
	parent := make([]int, len(idx))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	for i := 0; i < len(idx); i++ {
		for j := i + 1; j < len(idx); j++ {
			if hashDistance(results[idx[i]].PHash, results[idx[j]].PHash) <= phashMaxDistance {
				parent[find(j)] = find(i)
			}
		}
	}
	clusters := map[int][]int{}
	var roots []int
	for i, ri := range idx {
		root := find(i)
		if _, ok := clusters[root]; !ok {
			roots = append(roots, root)
		}
		clusters[root] = append(clusters[root], ri)
	}
	var groups [][]int
	for _, root := range roots {
		if len(clusters[root]) > 1 {
			groups = append(groups, clusters[root])
		}
	}
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i]) > len(groups[j]) })
	for n, g := range groups {
		for _, i := range g {
			results[i].Group, results[i].GroupSize = n+1, len(g)
		}
	}
	return groups
}

// --- CVEs of the versions found (NVD) -------------------------------------------------------------

// TechEntry is one technology / version across every service where it was seen.
type TechEntry struct {
	Tech
	URLs  []string `json:"urls"`
	Vulns []Vuln   `json:"vulns"`
}

func techInventory(results []Result) []*TechEntry {
	inv := map[string]*TechEntry{}
	var order []string
	for _, r := range results {
		for _, t := range r.Tech {
			k := t.Name + "\x00" + t.Version
			e, ok := inv[k]
			if !ok {
				e = &TechEntry{Tech: t}
				inv[k] = e
				order = append(order, k)
			}
			if !containsStr(e.URLs, r.URL) {
				e.URLs = append(e.URLs, r.URL)
			}
		}
	}
	out := make([]*TechEntry, 0, len(order))
	for _, k := range order {
		out = append(out, inv[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func nvdCVEs(ctx context.Context, cpe, version, key string) (map[string]float64, error) {
	match := "cpe:2.3:a:" + cpe + ":" + version
	out := map[string]float64{}
	var headers map[string]string
	if key != "" {
		headers = map[string]string{"apiKey": key}
	}
	for start := 0; ; {
		var res struct {
			ResultsPerPage  int `json:"resultsPerPage"`
			TotalResults    int `json:"totalResults"`
			Vulnerabilities []struct {
				CVE struct {
					ID      string                                                      `json:"id"`
					Metrics map[string][]struct{ CvssData struct{ BaseScore float64 } } `json:"metrics"`
				} `json:"cve"`
			} `json:"vulnerabilities"`
		}
		u := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=%s&noRejected&resultsPerPage=2000&startIndex=%d",
			strings.ReplaceAll(url.QueryEscape(match), "%3A", ":"), start)
		if err := getJSON(ctx, "nvd", u, headers, &res); err != nil {
			return out, err
		}
		for _, v := range res.Vulnerabilities {
			score := 0.0
			for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
				if ms := v.CVE.Metrics[k]; len(ms) > 0 {
					score = ms[0].CvssData.BaseScore
					break
				}
			}
			if v.CVE.ID != "" {
				out[v.CVE.ID] = score
			}
		}
		step := res.ResultsPerPage
		if step == 0 {
			step = 2000
		}
		start += step
		if start >= res.TotalResults {
			return out, nil
		}
	}
}

// lookupTechCVEs fills Vulns for every versioned technology with a CPE, then ranks with KEV / EPSS.
func lookupTechCVEs(ctx context.Context, inv []*TechEntry, keys Keys, logf func(string, ...any)) {
	key := keys.get("nvd")
	var todo []*TechEntry
	for _, e := range inv {
		if e.Version != "" && len(e.CPEs) > 0 {
			todo = append(todo, e)
		}
	}
	if len(todo) == 0 {
		return
	}
	pause := 6500 * time.Millisecond // NVD: 5 requests / 30 s without a key, 50 with one
	note := " (sans clé : ~7 s par requête)"
	if key != "" {
		pause, note = 700*time.Millisecond, ""
	}
	logf("[cve] %d version(s) à chercher dans NVD%s", len(todo), note)
	first := true
	for _, e := range todo {
		found := map[string]float64{}
		for _, cpe := range e.CPEs {
			if ctx.Err() != nil {
				return
			}
			if !first {
				select {
				case <-time.After(pause):
				case <-ctx.Done():
					return
				}
			}
			first = false
			m, err := nvdCVEs(ctx, cpe, e.Version, key)
			if err != nil {
				logf("[cve] %s : %v", e.Label(), err)
			}
			for c, s := range m {
				found[c] = s
			}
		}
		ids := make([]string, 0, len(found))
		for c := range found {
			ids = append(ids, c)
		}
		sort.Strings(ids)
		e.Vulns = nil
		for _, c := range ids {
			e.Vulns = append(e.Vulns, Vuln{CVE: c, CVSS: found[c]})
		}
		logf("[cve] %s : %d CVE", e.Label(), len(ids))
	}
	// Reuse the KEV / EPSS ranking of the IP enrichment
	exps := make([]*Exposure, len(todo))
	for i, e := range todo {
		exps[i] = &Exposure{Vulns: e.Vulns}
	}
	rankVulns(ctx, exps, logf)
	for i, e := range todo {
		e.Vulns = exps[i].Vulns
	}
}

func writeTechCSV(inv []*TechEntry, outdir string) error {
	f, err := os.Create(outdir + string(os.PathSeparator) + "technologies.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"technology", "version", "cpe", "services", "urls", "cves", "kev_cves", "max_epss", "max_cvss"})
	for _, e := range inv {
		var cves, kev []string
		maxE, maxC := 0.0, 0.0
		for _, v := range e.Vulns {
			cves = append(cves, v.CVE)
			if v.KEV {
				kev = append(kev, v.CVE)
			}
			maxE, maxC = max(maxE, v.EPSS), max(maxC, v.CVSS)
		}
		w.Write([]string{e.Name, e.Version, strings.Join(e.CPEs, " "), fmt.Sprint(len(e.URLs)), strings.Join(e.URLs, " "),
			strings.Join(cves, " "), strings.Join(kev, " "), fmt.Sprintf("%.4f", maxE), fmt.Sprintf("%.1f", maxC)})
	}
	w.Flush()
	return w.Error()
}

// --- HTML for report.html ----------------------------------------------------------------------

const webCSS = `
.tag{border-radius:3px;padding:1px 6px;font-size:12px;color:#fff;background:#666;margin-right:3px}
.tag-index-of,.tag-debug{background:#b00}.tag-admin{background:#c60}.tag-login{background:#246}
.tag-default{background:#777}.tag-auth-http{background:#357}
.tech{color:#333;font-size:12px}.fav{font-size:12px;color:#555}
.hdr{font-size:12px;color:#a50}
.dupcount{background:#555;color:#fff;border-radius:3px;padding:1px 6px;font-size:12px}
.groups{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.groups img{width:100%;display:block}
body.nodup .card.dup{display:none}body.nodup section.alldup{display:none}
`

func tagBadges(tags []string) string {
	var sb strings.Builder
	for _, t := range tags {
		fmt.Fprintf(&sb, `<span class="tag tag-%s" title="%s">%s</span>`, html.EscapeString(t), html.EscapeString(tagLabels[t]), html.EscapeString(t))
	}
	return sb.String()
}

func techLabels(ts []Tech) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Label()
	}
	return out
}

func cardExtras(r Result) string {
	e := html.EscapeString
	var parts []string
	if len(r.Tags) > 0 {
		parts = append(parts, tagBadges(r.Tags))
	}
	if r.Group > 0 {
		parts = append(parts, fmt.Sprintf(`<span class="dupcount" title="captures similaires">≈ groupe %d (%d)</span>`, r.Group, r.GroupSize))
	}
	out := ""
	if len(parts) > 0 {
		out = "<br>" + strings.Join(parts, " ")
	}
	if len(r.Tech) > 0 {
		out += `<br><span class="tech">` + e(strings.Join(techLabels(r.Tech), ", ")) + `</span>`
	}
	if r.FaviconHash != "" {
		out += fmt.Sprintf(`<br><span class="fav">favicon <a href="%s" title="recherche Shodan">%s</a></span>`, e(shodanFaviconURL(r.FaviconHash)), e(r.FaviconHash))
	}
	if len(r.HeaderIssues) > 0 {
		out += fmt.Sprintf(`<br><span class="hdr" title="%s">⚠ %d en-tête(s) / cookie(s) à revoir</span>`,
			e(strings.Join(r.HeaderIssues, "\n")), len(r.HeaderIssues))
	}
	return out
}

func urlLinks(urls []string, limit int) string {
	var parts []string
	for i, u := range urls {
		if i == limit {
			parts = append(parts, fmt.Sprintf("+%d", len(urls)-limit))
			break
		}
		parts = append(parts, fmt.Sprintf(`<a href="%s">%s</a>`, html.EscapeString(u), html.EscapeString(u)))
	}
	return strings.Join(parts, "<br>")
}

func techSection(inv []*TechEntry) string {
	if len(inv) == 0 {
		return ""
	}
	sorted := append([]*TechEntry{}, inv...)
	kev := func(e *TechEntry) int {
		n := 0
		for _, v := range e.Vulns {
			if v.KEV {
				n++
			}
		}
		return n
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		if kev(sorted[i]) != kev(sorted[j]) {
			return kev(sorted[i]) > kev(sorted[j])
		}
		return len(sorted[i].Vulns) > len(sorted[j].Vulns)
	})
	var sb strings.Builder
	nCVE := 0
	for _, x := range inv {
		nCVE += len(x.Vulns)
	}
	e := html.EscapeString
	fmt.Fprintf(&sb, `<details open><summary><b>Technologies détectées</b> - %d, %d CVE (versions lues dans les en-têtes, les pages et les bannières ; à confirmer)</summary>`, len(inv), nCVE)
	sb.WriteString(`<table><tr><th>Technologie</th><th>Version</th><th>Services</th><th>CVSS max</th><th>CVE (NVD)</th><th>Identifiants par défaut connus</th><th>URL</th></tr>`)
	for _, x := range sorted {
		cvss := ""
		if len(x.Vulns) > 0 {
			m := 0.0
			for _, v := range x.Vulns {
				m = max(m, v.CVSS)
			}
			cvss = fmt.Sprintf("%.1f", m)
		}
		ver := x.Version
		if ver == "" {
			ver = "?"
		}
		fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			e(x.Name), e(ver), len(x.URLs), cvss, vulnBadges(x.Vulns, 15), e(defaultCreds[x.Name]), urlLinks(x.URLs, 5))
	}
	sb.WriteString(`</table></details>`)
	return sb.String()
}

func sensitiveSection(results []Result) string {
	byTag := map[string][]string{}
	n := 0
	for _, r := range results {
		for _, t := range r.Tags {
			if !containsStr(byTag[t], r.URL) {
				byTag[t] = append(byTag[t], r.URL)
				n++
			}
		}
	}
	if n == 0 {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, `<details open><summary><b>Pages sensibles</b> - %d</summary><table><tr><th>Repère</th><th>Signification</th><th>Nombre</th><th>URL</th></tr>`, n)
	for _, t := range tagOrder {
		if urls := byTag[t]; len(urls) > 0 {
			fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>`, tagBadges([]string{t}), html.EscapeString(tagLabels[t]), len(urls), urlLinks(urls, 30))
		}
	}
	sb.WriteString(`</table></details>`)
	return sb.String()
}

func headersSection(results []Result) string {
	counts := map[string]int{}
	seen := map[string]bool{}
	var rows []string
	for _, r := range results {
		if len(r.HeaderIssues) == 0 || seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		for _, i := range r.HeaderIssues {
			k := i
			if strings.HasPrefix(i, "version divulguée") {
				k = "version divulguée"
			} else if strings.HasPrefix(i, "cookie ") {
				k = "cookie sans attribut"
			}
			counts[k]++
		}
		esc := make([]string, len(r.HeaderIssues))
		for i, x := range r.HeaderIssues {
			esc[i] = html.EscapeString(x)
		}
		rows = append(rows, fmt.Sprintf(`<tr><td>%s</td><td>%s</td></tr>`, urlLinks([]string{r.URL}, 1), strings.Join(esc, "<br>")))
	}
	if len(rows) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool { return counts[keys[i]] > counts[keys[j]] })
	var sum []string
	for _, k := range keys {
		sum = append(sum, fmt.Sprintf("%s : %d", k, counts[k]))
	}
	return fmt.Sprintf(`<details><summary><b>En-têtes de sécurité</b> - %d service(s) : %s</summary><table><tr><th>URL</th><th>Constats</th></tr>%s</table></details>`,
		len(rows), html.EscapeString(strings.Join(sum, ", ")), strings.Join(rows, ""))
}

func groupsSection(results []Result, groups [][]int) string {
	if len(groups) == 0 {
		return ""
	}
	var sb strings.Builder
	nDup := 0
	for n, g := range groups {
		nDup += len(g) - 1
		first := results[g[0]]
		var urls []string
		for _, i := range g {
			u := results[i].URL
			if ua := results[i].UA; ua != "" && ua != "default" {
				u += " (" + ua + ")"
			}
			urls = append(urls, u)
		}
		f := html.EscapeString(first.File)
		fmt.Fprintf(&sb, `<div class="card"><a href="%s"><img src="%s" loading="lazy"></a><div class="meta"><b>Groupe %d</b> - %d captures<br><details><summary>URL</summary>%s</details></div></div>`,
			f, f, n+1, len(g), urlLinks(urls, 200))
	}
	return fmt.Sprintf(`<details><summary><b>Pages similaires</b> - %d groupe(s), %d doublon(s) visuel(s)</summary><div class="groups">%s</div></details>`+
		`<label><input type="checkbox" id="nodup"> masquer les %d doublons visuels (une seule capture par groupe)</label><br>`,
		len(groups), nDup, sb.String(), nDup)
}

// --- Report filters ------------------------------------------------------------------------------

const filterCSS = `
.filters{position:sticky;top:0;z-index:5;background:#f4f4f4;padding:8px 0;border-bottom:1px solid #ddd;
  display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:13px}
.filters input[type=search]{width:280px;padding:4px}.filters select{padding:3px}
.card.f-hide,section.f-hide{display:none}
#fcount{color:#555}
`

const filterJS = `
(function(){
  var q=document.getElementById('fq'),s=document.getElementById('fstatus'),t=document.getElementById('ftag'),
      e=document.getElementById('ftech'),n=document.getElementById('fcount'),r=document.getElementById('freset');
  if(!q)return;
  function apply(){
    var text=q.value.toLowerCase().trim().split(/\s+/).filter(Boolean),shown=0,total=0;
    document.querySelectorAll('section').forEach(function(sec){
      var any=false;
      sec.querySelectorAll('.card').forEach(function(c){
        total++;
        var ok=(!s.value||c.dataset.status===s.value)
          &&(!t.value||(t.value==='none'?!c.dataset.tags:(' '+c.dataset.tags+' ').indexOf(' '+t.value+' ')>=0))
          &&(!e.value||('|'+c.dataset.tech+'|').indexOf('|'+e.value+'|')>=0)
          &&text.every(function(w){return c.dataset.q.indexOf(w)>=0});
        c.classList.toggle('f-hide',!ok);if(ok){any=true;shown++}
      });
      sec.classList.toggle('f-hide',!any);
    });
    n.textContent=shown+' / '+total+' captures';
  }
  [q,s,t,e].forEach(function(x){x.addEventListener('input',apply)});
  r.onclick=function(){q.value='';s.value='';t.value='';e.value='';apply()};
  apply();
  var d=document.getElementById('nodup');
  if(d)d.onchange=function(){document.body.classList.toggle('nodup',d.checked)};
})();
`

func statusClass(status int) string {
	if status >= 100 && status < 600 {
		return fmt.Sprintf("%dxx", status/100)
	}
	return "err"
}

func cardData(r Result) string {
	e := html.EscapeString
	var techNames []string
	for _, t := range r.Tech {
		techNames = append(techNames, t.Name)
	}
	q := strings.ToLower(strings.Join([]string{r.Host, fmt.Sprint(r.Port), r.URL, r.FinalURL, r.Title, itoaOrEmpty(r.Status),
		strings.Join(r.Tags, " "), strings.Join(techLabels(r.Tech), " "), r.UA, r.Service, r.Banner}, " "))
	return fmt.Sprintf(` data-status="%s" data-tags="%s" data-tech="%s" data-q="%s"`,
		statusClass(r.Status), e(strings.Join(r.Tags, " ")), e(strings.Join(techNames, "|")), e(q))
}

func filterBar(results []Result) string {
	e := html.EscapeString
	statuses := map[string]bool{}
	techs := map[string]bool{}
	tagSet := map[string]bool{}
	for _, r := range results {
		statuses[statusClass(r.Status)] = true
		for _, t := range r.Tech {
			techs[t.Name] = true
		}
		for _, t := range r.Tags {
			tagSet[t] = true
		}
	}
	var sb strings.Builder
	sb.WriteString(`<div class="filters"><input type="search" id="fq" placeholder="Rechercher (URL, titre, techno, tag…)"><select id="fstatus"><option value="">Tous les codes</option>`)
	var sl []string
	for s := range statuses {
		sl = append(sl, s)
	}
	sort.Strings(sl)
	for _, s := range sl {
		label := s
		if s == "err" {
			label = "Erreur / pas de page"
		}
		fmt.Fprintf(&sb, `<option value="%s">%s</option>`, s, label)
	}
	sb.WriteString(`</select><select id="ftag"><option value="">Tous les repères</option>`)
	for _, t := range tagOrder {
		if tagSet[t] {
			fmt.Fprintf(&sb, `<option value="%s">%s - %s</option>`, t, t, e(tagLabels[t]))
		}
	}
	sb.WriteString(`<option value="none">sans repère</option></select><select id="ftech"><option value="">Toutes les technologies</option>`)
	var tl []string
	for t := range techs {
		tl = append(tl, t)
	}
	sort.Slice(tl, func(i, j int) bool { return strings.ToLower(tl[i]) < strings.ToLower(tl[j]) })
	for _, t := range tl {
		fmt.Fprintf(&sb, `<option value="%s">%s</option>`, e(t), e(t))
	}
	sb.WriteString(`</select><button id="freset" type="button">Effacer</button><span id="fcount"></span></div>`)
	return sb.String()
}
