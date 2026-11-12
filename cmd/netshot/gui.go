package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed gui.html
var guiHTML string

//go:embed icon.png
var iconPNG []byte

// guiServer serves the interface on 127.0.0.1 under a random token path,
// so other local pages or users cannot drive it.
type guiServer struct {
	browser string
	baseOut string

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
	outdir  string
	subs    map[chan []byte]bool

	lastResults []Result // services found by the last scan, for the Certificats tab
}

type startRequest struct {
	Targets        string   `json:"targets"`
	Ports          string   `json:"ports"`
	Concurrency    int      `json:"concurrency"`
	ConnectTimeout float64  `json:"connect_timeout"`
	PageTimeout    float64  `json:"page_timeout"`
	Delay          float64  `json:"delay"`
	UAs            []string `json:"uas"`
	CustomUA       string   `json:"custom_ua"`
	Output         string   `json:"output"`
	Resolution     string   `json:"resolution"` // "1920x1080"
	Enrich         bool     `json:"enrich"`
	TLS            bool     `json:"tls"`
	Label          bool     `json:"label"`
	Dirs           bool     `json:"dirs"`
	Files          bool     `json:"files"`
	Proxy          string   `json:"proxy"`
	Exclude        string   `json:"exclude"`
	Confirm        bool     `json:"confirm"`
}

func runGUI(browser string, open bool) error {
	exe, _ := os.Executable()
	s := &guiServer{
		browser: browser,
		baseOut: filepath.Join(filepath.Dir(exe), "screenshots"),
		subs:    map[chan []byte]bool{},
	}

	tok := make([]byte, 16)
	rand.Read(tok)
	prefix := "/" + hex.EncodeToString(tok) + "/"

	mux := http.NewServeMux()
	mux.HandleFunc(prefix, s.handleIndex)
	mux.HandleFunc(prefix+"icon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(iconPNG)
	})
	mux.HandleFunc(prefix+"api/config", s.handleConfig)
	mux.HandleFunc(prefix+"api/theme", s.handleTheme)
	mux.HandleFunc(prefix+"api/start", s.handleStart)
	mux.HandleFunc(prefix+"api/stop", s.handleStop)
	mux.HandleFunc(prefix+"api/ct", s.handleCT)
	mux.HandleFunc(prefix+"api/keys", s.handleKeys)
	mux.HandleFunc(prefix+"api/import", s.handleImport)
	mux.HandleFunc(prefix+"api/dns", s.handleDNS)
	mux.HandleFunc(prefix+"api/tls", s.handleTLS)
	mux.HandleFunc(prefix+"api/tls-last", s.handleTLSLast)
	mux.HandleFunc(prefix+"api/whois", s.handleWhois)
	mux.HandleFunc(prefix+"api/leaks", s.handleLeaks)
	mux.HandleFunc(prefix+"api/leaks-export", s.handleLeaksExport)
	mux.HandleFunc(prefix+"api/events", s.handleEvents)
	mux.HandleFunc(prefix+"api/open", s.handleOpen)
	mux.HandleFunc(prefix+"api/quit", s.handleQuit)
	mux.HandleFunc(prefix+"files/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		dir := s.outdir
		s.mu.Unlock()
		if dir == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.StripPrefix(prefix+"files/", http.FileServer(http.Dir(dir))).ServeHTTP(w, r)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s%s", ln.Addr(), prefix)
	fmt.Println("NetShot interface:", url)
	fmt.Println("Close this window (or use the Quit button) to stop.")
	if open {
		openWindow(browser, url)
	}
	return http.Serve(ln, mux)
}

// openWindow shows the interface in an Edge/Chrome app window, or the default browser.
func openWindow(browser, url string) {
	if b, err := findBrowser(browser); err == nil {
		if exec.Command(b, "--app="+url, "--start-maximized").Start() == nil {
			go maximizeWindow("NetShot") // the page title
			return
		}
	}
	openPath(url)
}

func openPath(p string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", p)
	case "darwin":
		cmd = exec.Command("open", p)
	default:
		cmd = exec.Command("xdg-open", p)
	}
	cmd.Start()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *guiServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The saved theme is written into the page, so it is drawn with it from the first frame
	page := guiHTML
	if t := savedTheme(); t != "auto" {
		page = strings.Replace(page, `<html lang="fr">`, `<html lang="fr" data-theme="`+t+`">`, 1)
	}
	w.Write([]byte(page))
}

// handleTheme saves the theme chosen in the header.
func (s *guiServer) handleTheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Theme string `json:"theme"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !guiThemes[req.Theme] {
		writeJSON(w, map[string]any{"error": "thème inconnu"})
		return
	}
	if err := saveTheme(req.Theme); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *guiServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"uas":       allUAs(),
		"ports":     portsString(defaultPorts),
		"output":    s.baseOut,
		"max":       maxHostsDefault,
		"sources":   subSources,
		"keys":      keyStatus(),
		"keyPath":   keysPath(),
		"leakTypes": leakSearchTypes,
	})
}

func (s *guiServer) broadcast(kind string, payload any) {
	msg, _ := json.Marshal(map[string]any{"type": kind, "data": payload})
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- msg:
		default: // slow client: drop the event
		}
	}
}

func (s *guiServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := make(chan []byte, 512)
	s.mu.Lock()
	s.subs[ch] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
		go s.exitIfAbandoned()
	}()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// exitIfAbandoned stops the program when the interface window stays closed:
// a page reload reconnects well within the grace period.
func (s *guiServer) exitIfAbandoned() {
	time.Sleep(10 * time.Second)
	s.mu.Lock()
	abandoned := len(s.subs) == 0
	if abandoned && s.cancel != nil {
		s.cancel()
	}
	running := s.running
	s.mu.Unlock()
	if !abandoned {
		return
	}
	fmt.Println("Interface closed: stopping.")
	// Let a stopped scan close its browser and write its report
	for i := 0; running && i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		s.mu.Lock()
		running = s.running
		s.mu.Unlock()
	}
	os.Exit(0)
}

func (s *guiServer) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "invalid request"})
		return
	}
	hosts, opt, confirm, err := s.prepare(req)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	if confirm != "" && !req.Confirm {
		writeJSON(w, map[string]any{"confirm": confirm})
		return
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		writeJSON(w, map[string]any{"error": "a scan is already running"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.running, s.outdir = cancel, true, opt.Output
	s.mu.Unlock()

	go func() {
		s.broadcast("log", fmt.Sprintf("=== %d hosts x %d ports x %d UA -> %s", len(hosts), len(opt.Ports), len(opt.UAs), opt.Output))
		results, err := Run(ctx, hosts, opt, Callbacks{
			Log:      func(m string) { s.broadcast("log", m) },
			Progress: func(d, t, f int) { s.broadcast("progress", []int{d, t, f}) },
			Shot:     func(res Result) { s.broadcast("shot", res) },
			TLS:      func(res TLSResult) { s.broadcast("tls", res) },
		})
		s.mu.Lock()
		s.running = false
		s.lastResults = results
		s.mu.Unlock()
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		_, statErr := os.Stat(filepath.Join(opt.Output, "report.html"))
		s.broadcast("done", map[string]any{"error": errMsg, "stopped": ctx.Err() != nil, "report": statErr == nil})
		cancel()
	}()
	writeJSON(w, map[string]any{"ok": true, "output": opt.Output})
}

// prepare validates the form and returns hosts, options and an optional confirmation message.
func (s *guiServer) prepare(req startRequest) ([]string, Options, string, error) {
	items := strings.Split(strings.ReplaceAll(req.Targets, "\r", ""), "\n")
	hasTarget := false
	for _, i := range items {
		if cleanItem(i) != "" {
			hasTarget = true
		}
	}
	if !hasTarget {
		return nil, Options{}, "", errors.New("Aucune cible.")
	}
	items = expandASNs(context.Background(), items, func(format string, a ...any) {
		s.broadcast("log", fmt.Sprintf(format, a...))
	})
	ports, err := parsePorts(req.Ports)
	if err != nil || len(ports) == 0 {
		return nil, Options{}, "", errors.New("Ports invalides.")
	}
	if n := countTargets(items); n > maxHostsDefault {
		return nil, Options{}, "", fmt.Errorf("%.0f adresses : plage trop grande (max %d).", n, maxHostsDefault)
	}
	hosts := parseTargets(items)
	uaValues := append([]string{}, req.UAs...)
	if strings.TrimSpace(req.CustomUA) != "" {
		uaValues = append(uaValues, req.CustomUA)
	}
	uas := resolveUAs(uaValues)
	width, height := 1920, 1080
	fmt.Sscanf(req.Resolution, "%dx%d", &width, &height)
	base := strings.TrimSpace(req.Output)
	if base == "" {
		base = s.baseOut
	}
	opt := Options{
		Ports:          ports,
		Concurrency:    clampInt(req.Concurrency, 1, 200),
		ConnectTimeout: seconds(clampFloat(req.ConnectTimeout, 0.2, 30)),
		PageTimeout:    seconds(clampFloat(req.PageTimeout, 1, 120)),
		Delay:          seconds(clampFloat(req.Delay, 0, 600)),
		UAs:            uas,
		Width:          clampInt(width, 320, 3840),
		Height:         clampInt(height, 240, 2160),
		Output:         filepath.Join(base, "scan_"+time.Now().Format("20060102_150405")),
		Browser:        s.browser,
		Enrich:         req.Enrich,
		Label:          req.Label,
		TLS:            req.TLS,
		Keys:           loadKeys(),
		Analyze:        true,
	}
	if req.Dirs {
		opt.Dirs = dirWords(nil)
	}
	if req.Files {
		opt.Files = fileRules(nil)
	}
	proxy, err := parseProxy(req.Proxy)
	if err != nil {
		return nil, Options{}, "", fmt.Errorf("Proxy invalide : %v", err)
	}
	opt.Proxy = proxy
	opt.Exclusions = newExclusions(strings.Fields(strings.NewReplacer(",", " ", "\n", " ", "\r", " ").Replace(req.Exclude)))
	confirm := ""
	if tests := len(hosts) * len(ports); tests > 5000 {
		confirm = fmt.Sprintf("%d hôtes x %d ports = %d tests (x %d UA pour les services trouvés).\nContinuer ?",
			len(hosts), len(ports), tests, len(uas))
	}
	return hosts, opt, confirm, nil
}

// handleCT looks up hostnames with the passive sources; progress goes to the log.
func (s *guiServer) handleCT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Domains string   `json:"domains"`
		Sources []string `json:"sources"`
		Resolve bool     `json:"resolve"`
		Private bool     `json:"private"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "invalid request"})
		return
	}
	domains := strings.FieldsFunc(req.Domains, func(c rune) bool { return c == ',' || c == ';' || c == ' ' || c == '\n' || c == '\r' })
	if len(domains) == 0 || len(req.Sources) == 0 {
		writeJSON(w, map[string]any{"error": "Indique au moins un domaine et une source."})
		return
	}
	names := ctLookup(r.Context(), domains, ctOptions{
		Sources: req.Sources, Keys: loadKeys(), Resolve: req.Resolve, PrivateOnly: req.Private,
	}, func(format string, a ...any) { s.broadcast("log", fmt.Sprintf(format, a...)) })
	writeJSON(w, map[string]any{"names": names})
}

// keyStatus tells the page which keys are set, without ever sending their values back.
func keyStatus() []map[string]any {
	keys := loadKeys()
	var out []map[string]any
	for _, k := range keySources {
		out = append(out, map[string]any{"name": k.Name, "label": k.Label, "url": k.URL, "set": keys.get(k.Name) != ""})
	}
	return out
}

// handleKeys saves API keys: an empty value keeps the current key, "-" removes it.
func (s *guiServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "invalid request"})
		return
	}
	changes := Keys{}
	for name, v := range req {
		switch v = strings.TrimSpace(v); v {
		case "":
		case "-":
			changes[name] = "" // removal
		default:
			changes[name] = v
		}
	}
	if err := updateKeys(changes); err != nil { // merges into the file on disk, only the fields typed
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"keys": keyStatus(), "path": keysPath()})
}

// handleDNS returns the DNS records of a domain, as a table, as dig text and as targets.
func (s *guiServer) handleDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Domain string `json:"domain"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || normalizeDomain(req.Domain) == "" {
		writeJSON(w, map[string]any{"error": "Indique un domaine."})
		return
	}
	server := strings.TrimSpace(req.Server)
	if strings.EqualFold(server, "système") || strings.EqualFold(server, "systeme") {
		server = ""
	}
	rep := dnsLookup(r.Context(), req.Domain, server)
	writeJSON(w, map[string]any{"report": rep, "dig": formatDig(rep), "hosts": dnsHosts(rep.Records)})
}

// handleTLSLast lists the https services found by the last scan.
func (s *guiServer) handleTLSLast(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	targets := tlsTargetsFromResults(s.lastResults)
	s.mu.Unlock()
	writeJSON(w, map[string]any{"targets": targets})
}

// handleTLS analyzes the certificates and TLS setup of host:port targets. Each result is
// also pushed as a "tls" event so the table fills while the analysis runs. With export,
// the results are written to certificats_<date>.csv in the output folder.
func (s *guiServer) handleTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Targets string `json:"targets"`
		Output  string `json:"output"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "invalid request"})
		return
	}
	targets := parseTLSTargets(strings.Split(strings.ReplaceAll(req.Targets, "\r", ""), "\n"))
	if len(targets) == 0 {
		writeJSON(w, map[string]any{"error": "Indique au moins une cible (hôte ou hôte:port)."})
		return
	}
	logf := func(format string, a ...any) { s.broadcast("log", fmt.Sprintf(format, a...)) }
	logf("[tls] analyse de %d point(s) d'accès", len(targets))
	results := analyzeTLSAll(r.Context(), targets, logf, func(res TLSResult) { s.broadcast("tls", res) })
	base := strings.TrimSpace(req.Output)
	if base == "" {
		base = s.baseOut
	}
	csvPath := ""
	if err := os.MkdirAll(base, 0o755); err == nil {
		name := "certificats_" + time.Now().Format("20060102_150405") + ".csv"
		tmp := filepath.Join(base, ".tls_tmp")
		if os.MkdirAll(tmp, 0o755) == nil && writeTLSCSV(results, tmp) == nil {
			csvPath = filepath.Join(base, name)
			os.Rename(filepath.Join(tmp, "certificates.csv"), csvPath)
		}
		os.RemoveAll(tmp)
	}
	if csvPath != "" {
		logf("[tls] résultats enregistrés dans %s", csvPath)
	}
	writeJSON(w, map[string]any{"results": results, "csv": csvPath})
}

// handleWhois returns the owner of a domain, an IP or an AS, with the text version for Copier.
func (s *guiServer) handleWhois(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Query) == "" {
		writeJSON(w, map[string]any{"error": "Indique un domaine, une IP ou un AS."})
		return
	}
	rep := whoisLookup(r.Context(), req.Query)
	writeJSON(w, map[string]any{"report": rep, "text": formatWhois(rep)})
}

// handleLeaks queries LeakCheck. Values (passwords included) go to the page only, never to the log.
func (s *guiServer) handleLeaks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Query string `json:"query"`
		Type  string `json:"type"`
		Limit int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "invalid request"})
		return
	}
	ans, err := leakLookup(r.Context(), req.Query, loadKeys().get("leakcheck"), req.Type, req.Limit)
	if err != nil {
		s.broadcast("log", "[!] "+err.Error())
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, ans)
}

// handleLeaksExport writes the table, as built by the page (passwords masked unless shown),
// to fuites_<date>.csv in the output folder.
func (s *guiServer) handleLeaksExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Output string     `json:"output"`
		Rows   [][]string `json:"rows"` // first row = headings
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&req); err != nil || len(req.Rows) < 2 {
		writeJSON(w, map[string]any{"error": "Aucun résultat à exporter."})
		return
	}
	base := strings.TrimSpace(req.Output)
	if base == "" {
		base = s.baseOut
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	path := filepath.Join(base, "fuites_"+time.Now().Format("20060102_150405")+".csv")
	f, err := os.Create(path)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	// UTF-8 BOM and ';' so that Excel with French settings opens it directly
	f.WriteString("\xef\xbb\xbf")
	cw := csv.NewWriter(f)
	cw.Comma = ';'
	cw.WriteAll(req.Rows)
	f.Close()
	if err := cw.Error(); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"path": path})
}

// handleImport turns a loaded file (plain list or CSV export) into targets.
func (s *guiServer) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "invalid request"})
		return
	}
	lines := strings.Split(strings.ReplaceAll(req.Text, "\r", ""), "\n")
	writeJSON(w, map[string]any{"targets": importTargets(lines), "csv": looksLikeCSV(lines)})
}

func (s *guiServer) handleStop(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *guiServer) handleOpen(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	dir := s.outdir
	s.mu.Unlock()
	if dir == "" || r.Method != http.MethodPost {
		writeJSON(w, map[string]any{"error": "nothing to open"})
		return
	}
	switch r.URL.Query().Get("what") {
	case "report":
		openPath(filepath.Join(dir, "report.html"))
	case "folder":
		openPath(dir)
	case "file":
		// Only plain file names inside the current output folder
		name := filepath.Base(r.URL.Query().Get("name"))
		openPath(filepath.Join(dir, name))
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *guiServer) handleQuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	s.handleStop(w, r)
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}()
}

func clampInt(v, lo, hi int) int           { return max(lo, min(hi, v)) }
func clampFloat(v, lo, hi float64) float64 { return max(lo, min(hi, v)) }
