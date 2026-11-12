package main

// Scope of a scan: exclusion list (targets outside the contract) and proxy.
//
// Exclusions: IP, CIDR, host name, or *.domain (every sub-domain). A host name is also excluded when
// one of its addresses falls in an excluded range.
//
// Proxy: http://host:port (Burp, ZAP...) or socks5://host:port. Pages (browser flag), favicons,
// folders and files go through it. The TCP port test goes through a SOCKS5 proxy, and directly with
// an HTTP proxy (whose CONNECT answer says nothing about the port). TLS analysis, enrichment and NVD
// stay direct.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Exclusions ---------------------------------------------------------------------------------

type Exclusions struct {
	nets     []*net.IPNet
	names    map[string]bool
	suffixes []string // ".example.com"
}

func newExclusions(items []string) *Exclusions {
	x := &Exclusions{names: map[string]bool{}}
	for _, raw := range items {
		item := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])), ".")
		if item == "" {
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bitsLen := 32
			if ip.To4() == nil {
				bitsLen = 128
			}
			x.nets = append(x.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bitsLen, bitsLen)})
			continue
		}
		if _, n, err := net.ParseCIDR(item); err == nil {
			x.nets = append(x.nets, n)
			continue
		}
		if strings.HasPrefix(item, "*.") {
			x.suffixes = append(x.suffixes, item[1:])
		} else {
			x.names[item] = true
		}
	}
	return x
}

func (x *Exclusions) empty() bool {
	return x == nil || (len(x.nets) == 0 && len(x.names) == 0 && len(x.suffixes) == 0)
}

func (x *Exclusions) ipReason(ip net.IP) string {
	for _, n := range x.nets {
		if n.Contains(ip) {
			return fmt.Sprintf("%s dans %s", ip, n)
		}
	}
	return ""
}

// reason says why host is out of scope, or "" when it is in scope.
func (x *Exclusions) reason(host string) string {
	h := strings.TrimSuffix(strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]"), ".")
	if ip := net.ParseIP(h); ip != nil {
		return x.ipReason(ip)
	}
	if x.names[h] {
		return h + " exclu"
	}
	for _, s := range x.suffixes {
		if strings.HasSuffix(h, s) || h == s[1:] {
			return fmt.Sprintf("%s sous *%s", h, s)
		}
	}
	if len(x.nets) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ips, _ := net.DefaultResolver.LookupIPAddr(ctx, h)
		for _, ip := range ips {
			if r := x.ipReason(ip.IP); r != "" {
				return h + " -> " + r
			}
		}
	}
	return ""
}

// filter keeps the hosts in scope and logs what was removed.
func (x *Exclusions) filter(hosts []string, logf func(string, ...any)) []string {
	if x.empty() {
		return hosts
	}
	reasons := make([]string, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			reasons[i] = x.reason(h)
			<-sem
		}(i, h)
	}
	wg.Wait()
	var kept, removed []string
	for i, h := range hosts {
		if reasons[i] == "" {
			kept = append(kept, h)
		} else {
			removed = append(removed, reasons[i])
		}
	}
	if len(removed) > 0 {
		logf("[exclusion] %d cible(s) hors périmètre retirée(s)", len(removed))
		for i, r := range removed {
			if i == 20 {
				logf("    … +%d", len(removed)-20)
				break
			}
			logf("    - %s", r)
		}
	}
	return kept
}

// readExclusions reads -exclude values (comma or space separated) and -exclude-file files.
func readExclusions(values, files []string) (*Exclusions, error) {
	var items []string
	for _, v := range values {
		items = append(items, strings.Fields(strings.ReplaceAll(v, ",", " "))...)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		items = append(items, strings.Split(strings.ReplaceAll(strings.TrimPrefix(string(data), "\ufeff"), "\r", ""), "\n")...)
	}
	return newExclusions(items), nil
}

// --- Proxy ---------------------------------------------------------------------------------------

type Proxy struct {
	Scheme, Host   string
	Port           int
	User, Password string
	URL            *url.URL // for net/http
}

func (p *Proxy) Server() string {
	return fmt.Sprintf("%s://%s", p.Scheme, net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
}

func parseProxy(raw string) (*Proxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy %q: %v", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "socks5h" {
		scheme = "socks5"
	}
	if scheme != "http" && scheme != "https" && scheme != "socks5" {
		return nil, fmt.Errorf("proxy %q: http://, https:// or socks5:// expected", raw)
	}
	port, _ := strconv.Atoi(u.Port())
	if u.Hostname() == "" || port == 0 {
		return nil, fmt.Errorf("proxy %q: host:port expected, e.g. http://127.0.0.1:8080", raw)
	}
	p := &Proxy{Scheme: scheme, Host: u.Hostname(), Port: port, URL: u}
	if u.User != nil {
		if scheme == "socks5" {
			return nil, errors.New("Chromium does not support SOCKS5 with a password")
		}
		p.User = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	return p, nil
}

// dialTCP opens a TCP connection, directly or through a SOCKS5 proxy.
func dialTCP(ctx context.Context, p *Proxy, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if p == nil || p.Scheme != "socks5" {
		return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	fail := func(e error) (net.Conn, error) { conn.Close(); return nil, e }
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[1] != 0 {
		return fail(errors.New("socks: authentication refused"))
	}
	req := []byte{5, 1, 0}
	h := strings.Trim(host, "[]")
	if ip := net.ParseIP(h); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(append(req, 1), ip4...)
		} else {
			req = append(append(req, 4), ip.To16()...)
		}
	} else {
		req = append(append(req, 3, byte(len(h))), h...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fail(err)
	}
	if buf[1] != 0 {
		return fail(errors.New("socks: connection refused"))
	}
	n := map[byte]int{1: 4, 4: 16}[buf[3]]
	if buf[3] == 3 {
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fail(err)
		}
		n = int(l[0])
	}
	if _, err := io.ReadFull(conn, make([]byte, n+2)); err != nil {
		return fail(err)
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// --- Shared state of the page analysis -----------------------------------------------------------

// webState holds what the page analysis shares across workers: HTTP client (same proxy as the
// browser, certificates not checked), favicon cache, lists of folders and files to test.
type webState struct {
	client   *http.Client
	mu       sync.Mutex
	favicons map[string]string
}

func newWebState(p *Proxy, timeout time.Duration) *webState {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // internal services: self-signed certificates
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	if p != nil {
		tr.Proxy = http.ProxyURL(p.URL)
	}
	return &webState{
		client:   &http.Client{Transport: tr, Timeout: timeout},
		favicons: map[string]string{},
	}
}

// get fetches at most limit bytes (Range header), following up to maxRedirects redirects.
func (w *webState) get(ctx context.Context, rawURL, ua string, maxRedirects, limit int) (int, string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", limit-1))
	client := *w.client
	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
	return resp.StatusCode, strings.ToLower(resp.Header.Get("Content-Type")), body, err
}
