package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type Options struct {
	Ports          []int
	Concurrency    int
	ConnectTimeout time.Duration
	PageTimeout    time.Duration
	Delay          time.Duration // minimum time between two page loads
	UAs            []UA
	Width, Height  int
	Output         string
	Browser        string // path to msedge/chrome; empty = auto-detect
	Enrich         bool   // passive enrichment of the IPs found (InternetDB, LeakIX, KEV, EPSS)
	TLS            bool   // analyze the certificates and TLS setup of the https services found
	Label          bool   // write host:port, URL, status and date at the bottom of each capture
	Keys           Keys
	Analyze        bool        // technologies, sensitive pages, headers, favicon, JS, robots, banners, takeover
	Dirs           []string    // -dirs: folders to test for directory listings (nil = off)
	Files          []FileRule  // -files: sensitive files to test (nil = off)
	WAFProbe       bool        // -waf-probe: one request with a harmless attack-like string per web service
	Proxy          *Proxy      // pages, favicons, folders and files go through it
	Exclusions     *Exclusions // out-of-scope targets, never scanned
}

type Result struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	UA       string `json:"ua"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Title    string `json:"title"`
	FinalURL string `json:"final_url"`
	Size     int    `json:"size"`
	File     string `json:"file"`
	Error    string `json:"error"`

	// Page analysis (webinfo.go, recon.go)
	Tech           []Tech      `json:"tech,omitempty"`
	Tags           []string    `json:"tags,omitempty"`
	HeaderIssues   []string    `json:"header_issues,omitempty"`
	FaviconURL     string      `json:"favicon_url,omitempty"`
	FaviconHash    string      `json:"favicon_hash,omitempty"`
	PHash          string      `json:"phash,omitempty"`
	Group          int         `json:"visual_group,omitempty"`
	GroupSize      int         `json:"group_size,omitempty"`
	JS             *JSInfo     `json:"js,omitempty"`
	WellKnown      *WellKnown  `json:"well_known,omitempty"`
	FilesFound     []FileFound `json:"files_found,omitempty"`
	Banner         string      `json:"banner,omitempty"`
	Service        string      `json:"service,omitempty"`
	ServiceVersion string      `json:"service_version,omitempty"`
	Dir            bool        `json:"dir,omitempty"`               // capture of a folder found by -dirs
	WAF            []string    `json:"waf,omitempty"`               // WAF / protective CDN seen in headers and cookies
	WAFProbe       string      `json:"waf_probe,omitempty"`         // verdict of -waf-probe
	MixedContent   []string    `json:"mixed_content,omitempty"`     // http:// resources on an https page
	NoSRI          []string    `json:"no_sri,omitempty"`            // third-party scripts / styles without integrity
	Trackers       []string    `json:"trackers,omitempty"`          // known trackers and third-party services
	ThirdParty     []string    `json:"third_party_hosts,omitempty"` // third-party hosts loaded by the page
	PageText       string      `json:"-"`                           // for the takeover fingerprints
	Dup            bool        `json:"-"`                           // visual duplicate (report only)
}

// Callbacks are optional hooks used by the GUI and the CLI.
type Callbacks struct {
	Log      func(string)
	Progress func(done, total, found int)
	Shot     func(Result)
	TLS      func(TLSResult)
}

// findBrowser returns the Edge or Chrome executable to drive.
func findBrowser(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("browser not found: %s", explicit)
		}
		return explicit, nil
	}
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		for _, base := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles"), os.Getenv("LOCALAPPDATA")} {
			if base == "" {
				continue
			}
			candidates = append(candidates,
				filepath.Join(base, `Microsoft\Edge\Application\msedge.exe`),
				filepath.Join(base, `Google\Chrome\Application\chrome.exe`))
		}
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	default:
		for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"} {
			if p, err := exec.LookPath(name); err == nil {
				candidates = append(candidates, p)
			}
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", errors.New("no Edge or Chrome found: install one or use -browser <path>")
}

// rateLimiter guarantees at least `interval` between two page loads, across all workers.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func (r *rateLimiter) wait(ctx context.Context) error {
	if r.interval <= 0 {
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if d := time.Until(r.next); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.next = time.Now().Add(r.interval)
	return ctx.Err()
}

func portOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func safeName(s string) string { return unsafeChars.ReplaceAllString(s, "_") }

func buildURL(host string, port int, scheme string) string {
	h := host
	if strings.Contains(host, ":") {
		h = "[" + host + "]" // IPv6
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s/", scheme, h)
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, h, port)
}

func firstLine(err error) string {
	s := strings.SplitN(err.Error(), "\n", 2)[0]
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// labelJS draws a banner over the bottom of the page just before the screenshot, so every capture
// says where it comes from. Styles go through element.style (allowed even under a strict CSP);
// title and size are measured before, so the banner never changes them.
const labelJS = `(text => {
  const d = document.createElement('div');
  d.id = '__netshot_label';
  const s = d.style;
  s.position = 'fixed'; s.left = '0'; s.right = '0'; s.bottom = '0'; s.zIndex = '2147483647';
  s.display = 'block'; s.margin = '0'; s.boxSizing = 'border-box'; s.padding = '6px 12px';
  s.background = 'rgba(17, 24, 39, 0.88)'; s.color = '#ffffff'; s.textAlign = 'left';
  s.font = 'bold 15px Consolas, "Courier New", monospace'; s.lineHeight = '1.4';
  s.whiteSpace = 'pre'; s.overflow = 'hidden'; s.textOverflow = 'ellipsis'; s.pointerEvents = 'none';
  d.textContent = text;
  (document.body || document.documentElement).appendChild(d);
  return true;
})`

// shotLabel is the text of the banner: host:port, URL, redirect, HTTP status, user agent, date.
func shotLabel(host string, port int, url, finalURL string, status int, ua string) string {
	h := host
	if strings.Contains(host, ":") {
		h = "[" + host + "]"
	}
	text := fmt.Sprintf("%s:%d   %s", h, port, url)
	if finalURL != "" && finalURL != url {
		text += "  ->  " + finalURL
	}
	if status != 0 {
		text += fmt.Sprintf("   [%d]", status)
	}
	if ua != "" && ua != "default" {
		text += "   UA " + ua
	}
	return text + "   " + time.Now().Format("2006-01-02 15:04")
}

// capture opens url in a new tab with the given UA and saves a PNG.
// stopCtx aborts the capture when the user stops the scan.
func capture(stopCtx, browserCtx context.Context, opt Options, ws *webState, ua UA, host string, port int, url, outFile string) (Result, error) {
	tabCtx, cancelTab := chromedp.NewContext(browserCtx)
	defer cancelTab()
	ctx, cancel := context.WithTimeout(tabCtx, opt.PageTimeout)
	defer cancel()
	defer context.AfterFunc(stopCtx, cancel)()

	// No HTTP cache: each user agent must get a fresh answer from the server
	setup := []chromedp.Action{
		chromedp.EmulateViewport(int64(opt.Width), int64(opt.Height)),
		network.Enable(),
		network.SetCacheDisabled(true),
	}
	if ua.Value != "" {
		setup = append(setup, emulation.SetUserAgentOverride(ua.Value))
	}
	if p := opt.Proxy; p != nil && p.User != "" {
		// Chromium takes no credentials in --proxy-server: answer the proxy's challenge here
		setup = append(setup, fetch.Enable().WithHandleAuthRequests(true))
		chromedp.ListenTarget(ctx, func(ev any) {
			switch e := ev.(type) {
			case *fetch.EventRequestPaused:
				go chromedp.Run(ctx, fetch.ContinueRequest(e.RequestID))
			case *fetch.EventAuthRequired:
				go chromedp.Run(ctx, fetch.ContinueWithAuth(e.RequestID, &fetch.AuthChallengeResponse{
					Response: fetch.AuthChallengeResponseResponseProvideCredentials, Username: p.User, Password: p.Password}))
			}
		})
	}
	// Scripts loaded by the page, analysed afterwards without downloading them again
	type script struct {
		id  network.RequestID
		url string
	}
	var scriptsMu sync.Mutex
	var scripts []script
	if ws != nil {
		chromedp.ListenTarget(ctx, func(ev any) {
			if e, ok := ev.(*network.EventResponseReceived); ok && e.Type == network.ResourceTypeScript {
				scriptsMu.Lock()
				if len(scripts) < 40 {
					scripts = append(scripts, script{e.RequestID, e.Response.URL})
				}
				scriptsMu.Unlock()
			}
		})
	}
	if err := chromedp.Run(ctx, setup...); err != nil {
		return Result{}, err
	}
	resp, err := chromedp.RunResponse(ctx, chromedp.Navigate(url))
	if err != nil {
		return Result{}, err
	}
	var title, final, content string
	var png []byte
	err = chromedp.Run(ctx,
		chromedp.Sleep(800*time.Millisecond), // let JS render a bit
		chromedp.Title(&title),
		chromedp.Location(&final),
		chromedp.Evaluate(`document.documentElement ? document.documentElement.outerHTML : ''`, &content),
	)
	if err != nil {
		return Result{}, err
	}
	size := len(content)
	status := 0
	if resp != nil {
		status = int(resp.Status)
	}
	var info Result
	if ws != nil {
		var hs []Header
		if resp != nil {
			for k, v := range resp.Headers {
				for _, line := range strings.Split(fmt.Sprint(v), "\n") {
					hs = append(hs, Header{k, line})
				}
			}
		}
		info.Tech = detectTech(hs, content, title)
		info.Tags = pageTags(title, content, final, status, hs, info.Tech)
		info.HeaderIssues = headerIssues(final, hs, content)
		info.WAF = detectWAF(hs)
		var resJSON string
		if chromedp.Run(ctx, chromedp.Evaluate(pageResourcesJS, &resJSON)) == nil {
			pc := analyzeResources(final, resJSON)
			info.MixedContent, info.NoSRI, info.Trackers, info.ThirdParty = pc.MixedContent, pc.NoSRI, pc.Trackers, pc.ThirdParty
			info.HeaderIssues = append(info.HeaderIssues, pageIssues(pc)...)
		}
		var iconURL string
		if chromedp.Run(ctx, chromedp.Evaluate(faviconJS, &iconURL)) == nil {
			info.FaviconURL = iconURL
			info.FaviconHash = ws.fetchFavicon(ctx, iconURL, ua.Value)
		}
		scriptsMu.Lock()
		list := append([]script{}, scripts...)
		scriptsMu.Unlock()
		var sources []jsSource
		for _, sc := range list {
			if !sameSite(sc.url, final) {
				continue
			}
			var body []byte
			_ = chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
				b, err := network.GetResponseBody(sc.id).Do(c)
				body = b
				return err
			}))
			if len(body) > 0 {
				sources = append(sources, jsSource{sc.url, string(body[:min(len(body), 3_000_000)])})
			}
		}
		sources = append(sources, inlineScripts(final, content)...)
		info.JS = analyzeJS(sources)
		info.PageText = content[:min(len(content), 20000)]
	}
	if opt.Label {
		text, _ := json.Marshal(shotLabel(host, port, url, final, status, ua.Name))
		var ok bool
		_ = chromedp.Run(ctx, chromedp.Evaluate(labelJS+"("+string(text)+")", &ok)) // no banner if the page refuses
	}
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&png)); err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(outFile, png, 0o644); err != nil {
		return Result{}, err
	}
	if ws != nil {
		info.PHash = screenshotHash(png)
	}
	info.URL, info.Title, info.FinalURL, info.Size, info.File, info.Status = url, title, final, size, filepath.Base(outFile), status
	return info, nil
}

// Run scans every host:port, captures web pages, writes report.html and results.csv.
// Cancel ctx to stop.
func Run(ctx context.Context, hosts []string, opt Options, cb Callbacks) ([]Result, error) {
	logf := func(format string, a ...any) {
		if cb.Log != nil {
			cb.Log(fmt.Sprintf(format, a...))
		}
	}
	if len(opt.UAs) == 0 {
		opt.UAs = []UA{{Name: "default"}}
	}
	browser, err := findBrowser(opt.Browser)
	if err != nil {
		return nil, err
	}
	if !opt.Exclusions.empty() {
		hosts = opt.Exclusions.filter(hosts, logf)
		if len(hosts) == 0 {
			logf("[exclusion] plus aucune cible dans le périmètre")
			return nil, nil
		}
	}
	var extra []string
	if opt.Proxy != nil {
		// Chromium never sends localhost through a proxy unless told so
		extra = append(extra, "--proxy-server="+opt.Proxy.Server(), "--proxy-bypass-list=<-loopback>")
		how := "test des ports en direct"
		if opt.Proxy.Scheme == "socks5" {
			how = "test des ports via SOCKS5"
		}
		logf("[proxy] pages, favicons et dossiers via %s ; %s. Analyse TLS, enrichissement et NVD restent en direct.", opt.Proxy.Server(), how)
	}
	var ws *webState
	if opt.Analyze || opt.Dirs != nil || opt.Files != nil || opt.WAFProbe {
		ws = newWebState(opt.Proxy, opt.PageTimeout)
	}
	if err := os.MkdirAll(opt.Output, 0o755); err != nil {
		return nil, err
	}
	logf("Browser: %s", browser)

	// The browser lives outside ctx: stopping the scan must still let us close it cleanly
	browserCtx, closeBrowser, err := startBrowser(browser, opt.Width, opt.Height, extra...)
	if err != nil {
		return nil, fmt.Errorf("cannot start browser: %w", err)
	}
	defer closeBrowser()

	type job struct {
		host string
		port int
	}
	jobs := make(chan job)
	total := len(hosts) * len(opt.Ports)
	var done, found int64
	var mu sync.Mutex
	var results []Result
	limiter := &rateLimiter{interval: opt.Delay}

	add := func(r Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
		atomic.AddInt64(&found, 1)
	}

	worker := func() {
		for j := range jobs {
			if ctx.Err() == nil && isOpen(ctx, opt, j.host, j.port) {
				scanService(ctx, browserCtx, opt, ws, limiter, j.host, j.port, add, cb, logf)
			}
			atomic.AddInt64(&done, 1)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < max(1, opt.Concurrency); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); worker() }()
	}

	stopProgress := make(chan struct{})
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if cb.Progress != nil {
					cb.Progress(int(atomic.LoadInt64(&done)), total, int(atomic.LoadInt64(&found)))
				}
			case <-stopProgress:
				return
			}
		}
	}()

feed:
	for _, h := range hosts {
		for _, p := range opt.Ports {
			select {
			case jobs <- job{h, p}:
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()
	close(stopProgress)
	if cb.Progress != nil {
		cb.Progress(total, total, len(results))
	}

	var exposures []*Exposure
	if opt.Enrich && ctx.Err() == nil && len(results) > 0 {
		exposures = enrich(ctx, results, opt.Keys, logf)
		if err := writeExposureCSV(exposures, opt.Output); err != nil {
			logf("[enrich] %v", err)
		}
	}
	var reps []*Reputation
	if opt.Enrich && ctx.Err() == nil && len(results) > 0 {
		reps = checkReputation(ctx, results, exposures, opt.Keys, logf)
		if err := writeReputationCSV(reps, opt.Output); err != nil {
			logf("[réputation] %v", err)
		}
	}
	var tlsResults []TLSResult
	if opt.TLS && ctx.Err() == nil {
		if targets := tlsTargetsFromResults(results); len(targets) > 0 {
			logf("[tls] analyse de %d service(s) https", len(targets))
			tlsResults = analyzeTLSAll(ctx, targets, logf, cb.TLS)
			if err := writeTLSCSV(tlsResults, opt.Output); err != nil {
				logf("[tls] %v", err)
			}
		}
	}
	var inv []*TechEntry
	var groups [][]int
	var takeovers []Takeover
	if opt.Analyze && len(results) > 0 {
		sortResults(results) // groups hold indexes: sort once, before grouping
		groups = groupSimilar(results)
		if len(groups) > 0 {
			nDup := 0
			for _, g := range groups {
				nDup += len(g) - 1
			}
			logf("[web] %d groupe(s) de pages similaires, %d doublon(s) visuel(s)", len(groups), nDup)
		}
		nTags := 0
		for _, r := range results {
			if len(r.Tags) > 0 {
				nTags++
			}
		}
		if nTags > 0 {
			logf("[web] %d page(s) sensible(s) : voir « Pages sensibles » dans le rapport", nTags)
		}
		if ctx.Err() == nil {
			var names []string
			pages := map[string]string{}
			for _, h := range hosts {
				if net.ParseIP(strings.Trim(h, "[]")) == nil {
					names = append(names, strings.ToLower(h))
				}
			}
			for _, r := range results {
				if k := strings.ToLower(r.Host); r.PageText != "" && pages[k] == "" {
					pages[k] = r.PageText
				}
			}
			if len(names) > 0 {
				takeovers = checkTakeover(ctx, names, pages, logf)
			}
		}
		inv = techInventory(results)
		if opt.Enrich && ctx.Err() == nil {
			lookupTechCVEs(ctx, inv, opt.Keys, logf)
		}
		if err := writeTechCSV(inv, opt.Output); err != nil {
			logf("[web] %v", err)
		}
	}
	if err := writeReports(results, exposures, tlsResults, opt.Output, inv, groups, takeovers, reps); err != nil {
		return results, err
	}
	if err := writeResultsJSON(opt.Output, results, exposures, tlsResults, inv, groups, takeovers, reps); err != nil {
		logf("[export] results.json : %v", err)
	}
	if err := writeXLSX(filepath.Join(opt.Output, "results.xlsx"), buildSheets(results, exposures, inv, takeovers, reps)); err != nil {
		logf("[export] results.xlsx : %v", err)
	}
	ok := 0
	for _, r := range results {
		if r.File != "" {
			ok++
		}
	}
	state := "Done"
	if ctx.Err() != nil {
		state = "Stopped"
	}
	logf("%s: %d screenshots, %d errors. Report: %s", state, ok, len(results)-ok, filepath.Join(opt.Output, "report.html"))
	return results, nil
}

// isOpen tests the TCP port: through the SOCKS5 proxy when there is one, else directly.
func isOpen(ctx context.Context, opt Options, host string, port int) bool {
	if opt.Proxy != nil && opt.Proxy.Scheme == "socks5" {
		conn, err := dialTCP(ctx, opt.Proxy, host, port, opt.ConnectTimeout+2*time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}
	return portOpen(host, port, opt.ConnectTimeout)
}

// scanService captures one open host:port with every UA, trying the likely scheme first, then runs
// the per-service checks (robots, files, folders, banner of a non-web service).
func scanService(ctx, browserCtx context.Context, opt Options, ws *webState, limiter *rateLimiter, host string, port int,
	add func(Result), cb Callbacks, logf func(string, ...any)) {
	schemes := []string{"http", "https"}
	if httpsPorts[port] {
		schemes = []string{"https", "http"}
	}
	var rows []Result
	baseURL, baseUA := "", ""
	defer func() {
		for _, r := range rows {
			add(r)
		}
	}()
	var analysis *webState
	if opt.Analyze {
		analysis = ws
	}
	for _, ua := range opt.UAs {
		suffix, tag := "", ""
		if ua.Name != "default" {
			suffix, tag = "_"+safeName(ua.Name), "  ("+ua.Name+")"
		}
		lastErr := ""
		captured := false
		for _, scheme := range schemes {
			if limiter.wait(ctx) != nil {
				return
			}
			url := buildURL(host, port, scheme)
			out := filepath.Join(opt.Output, fmt.Sprintf("%s_%d_%s%s.png", safeName(host), port, scheme, suffix))
			r, err := capture(ctx, browserCtx, opt, analysis, ua, host, port, url, out)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if lastErr != "" {
					lastErr += " | "
				}
				lastErr += scheme + ": " + firstLine(err)
				continue
			}
			r.Host, r.Port, r.UA = host, port, ua.Name
			rows = append(rows, r)
			extra := ""
			if len(r.Tags) > 0 {
				extra += "  [" + strings.Join(r.Tags, ", ") + "]"
			}
			if len(r.Tech) > 0 {
				extra += "  " + strings.Join(techLabels(r.Tech[:min(4, len(r.Tech))]), ", ")
			}
			if len(r.WAF) > 0 {
				extra += "  WAF " + strings.Join(r.WAF, ", ")
			}
			logf("[+] %s  %d  %s%s%s", url, r.Status, truncate(r.Title, 60), tag, extra)
			if cb.Shot != nil {
				cb.Shot(r)
			}
			if baseURL == "" {
				baseURL, baseUA = url, ua.Value
			}
			captured = true
			break
		}
		if !captured {
			rows = append(rows, Result{Host: host, Port: port, UA: ua.Name, URL: buildURL(host, port, schemes[0]), Error: lastErr})
			logf("[-] %s:%d open but no web page (%s)%s", host, port, truncate(lastErr, 80), tag)
		}
	}
	if ctx.Err() != nil {
		return
	}
	first := -1
	for i, r := range rows {
		if r.File != "" {
			first = i
			break
		}
	}
	if first >= 0 && opt.Analyze {
		rows[first].WellKnown = ws.wellKnown(ctx, baseURL, baseUA)
		if w := rows[first].WellKnown; w != nil && len(w.Robots) > 0 {
			logf("[robots] %srobots.txt : %d chemin(s)", baseURL, len(w.Robots))
		}
	}
	if first >= 0 && opt.WAFProbe && ctx.Err() == nil {
		if limiter.wait(ctx) == nil {
			rows[first].WAFProbe = ws.probeWAF(ctx, baseURL, baseUA)
			if v := rows[first].WAFProbe; v != "" {
				logf("[waf] %s  %s", baseURL, v)
			}
		}
	}
	if first >= 0 && opt.Files != nil && ctx.Err() == nil {
		rows[first].FilesFound = ws.probeFiles(ctx, baseURL, baseUA, opt.Files, limiter)
		for _, f := range rows[first].FilesFound {
			logf("[fichier] %s  %s", f.URL, f.Severity)
		}
	}
	if first < 0 && opt.Analyze {
		text := grabBanner(ctx, host, port, opt.Proxy)
		name, version, cpes := parseBanner(text)
		if text != "" || name != "" {
			for i := range rows {
				rows[i].Banner, rows[i].Service, rows[i].ServiceVersion = bannerDisplay(text), name, version
				if name != "" {
					rows[i].Tech = []Tech{{Name: name, Version: version, CPEs: cpes}}
				}
			}
			svc := name
			if svc == "" {
				svc = "?"
			}
			logf("[service] %s:%d  %s %s  %s", host, port, svc, version, truncate(bannerDisplay(text), 80))
		}
	}
	if first >= 0 && opt.Dirs != nil && ctx.Err() == nil {
		for _, u := range ws.probeDirs(ctx, baseURL, baseUA, opt.Dirs, limiter) {
			if ctx.Err() != nil {
				return
			}
			p := strings.Trim(strings.TrimPrefix(u, serviceRoot(u)), "/")
			scheme := strings.SplitN(u, ":", 2)[0]
			out := filepath.Join(opt.Output, fmt.Sprintf("%s_%d_%s_dir_%s.png", safeName(host), port, scheme, safeName(p)))
			r, err := capture(ctx, browserCtx, opt, analysis, UA{Name: "default", Value: baseUA}, host, port, u, out)
			if err != nil {
				logf("[dir] %s  liste de fichiers, capture impossible (%s)", u, truncate(firstLine(err), 120))
				continue
			}
			r.Host, r.Port, r.UA, r.Dir = host, port, "dossier", true
			if !containsStr(r.Tags, "index-of") {
				r.Tags = append([]string{"index-of"}, r.Tags...)
			}
			rows = append(rows, r)
			logf("[dir] %s  %d  Index of : liste de fichiers", u, r.Status)
			if cb.Shot != nil {
				cb.Shot(r)
			}
		}
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
