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
func capture(stopCtx, browserCtx context.Context, opt Options, ua UA, host string, port int, url, outFile string) (Result, error) {
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
	if err := chromedp.Run(ctx, setup...); err != nil {
		return Result{}, err
	}
	resp, err := chromedp.RunResponse(ctx, chromedp.Navigate(url))
	if err != nil {
		return Result{}, err
	}
	var title, final string
	var size int
	var png []byte
	err = chromedp.Run(ctx,
		chromedp.Sleep(800*time.Millisecond), // let JS render a bit
		chromedp.Title(&title),
		chromedp.Location(&final),
		chromedp.Evaluate(`document.documentElement ? document.documentElement.outerHTML.length : 0`, &size),
	)
	if err != nil {
		return Result{}, err
	}
	status := 0
	if resp != nil {
		status = int(resp.Status)
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
	return Result{URL: url, Title: title, FinalURL: final, Size: size, File: filepath.Base(outFile), Status: status}, nil
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
	if err := os.MkdirAll(opt.Output, 0o755); err != nil {
		return nil, err
	}
	logf("Browser: %s", browser)

	// The browser lives outside ctx: stopping the scan must still let us close it cleanly
	browserCtx, closeBrowser, err := startBrowser(browser, opt.Width, opt.Height)
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
			if ctx.Err() == nil && portOpen(j.host, j.port, opt.ConnectTimeout) {
				scanService(ctx, browserCtx, opt, limiter, j.host, j.port, add, cb, logf)
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
	if err := writeReports(results, exposures, tlsResults, opt.Output); err != nil {
		return results, err
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

// scanService captures one open host:port with every UA, trying the likely scheme first.
func scanService(ctx, browserCtx context.Context, opt Options, limiter *rateLimiter, host string, port int,
	add func(Result), cb Callbacks, logf func(string, ...any)) {
	schemes := []string{"http", "https"}
	if httpsPorts[port] {
		schemes = []string{"https", "http"}
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
			r, err := capture(ctx, browserCtx, opt, ua, host, port, url, out)
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
			add(r)
			logf("[+] %s  %d  %s%s", url, r.Status, truncate(r.Title, 60), tag)
			if cb.Shot != nil {
				cb.Shot(r)
			}
			captured = true
			break
		}
		if !captured {
			add(Result{Host: host, Port: port, UA: ua.Name, URL: buildURL(host, port, schemes[0]), Error: lastErr})
			logf("[-] %s:%d open but no web page (%s)%s", host, port, truncate(lastErr, 80), tag)
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
