package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
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

// Passive enrichment of the IPs behind the services found by the scan.
// Public IPs only are sent to third parties: Shodan InternetDB (free, no key)
// and LeakIX (free key). CVEs are then ranked with CISA KEV and FIRST EPSS.

type Vuln struct {
	CVE  string  `json:"cve"`
	KEV  bool    `json:"kev"`  // in the CISA Known Exploited Vulnerabilities catalog
	EPSS float64 `json:"epss"` // probability of exploitation in the next 30 days
}

type Exposure struct {
	IP           string   `json:"ip"`
	Hosts        []string `json:"hosts"` // scanned names that resolve to this IP
	PTR          []string `json:"ptr"`
	Ports        []int    `json:"ports"`     // InternetDB
	Hostnames    []string `json:"hostnames"` // InternetDB
	Tags         []string `json:"tags"`
	CPEs         []string `json:"cpes"`
	Vulns        []Vuln   `json:"vulns"`
	LeakServices int      `json:"leakix_services"`
	Leaks        []string `json:"leakix_leaks"`
	Internal     bool     `json:"internal"`
	Notes        []string `json:"notes"`
	// Shodan (with a key): who owns the IP and what runs on each port
	Org      string   `json:"org"`
	ASN      string   `json:"asn"`
	Country  string   `json:"country"`
	OS       string   `json:"os"`
	Services []string `json:"services"` // "443/tcp nginx 1.18 - Titre de la page"
	LastSeen string   `json:"last_seen"`
}

func (e *Exposure) kevCount() int {
	n := 0
	for _, v := range e.Vulns {
		if v.KEV {
			n++
		}
	}
	return n
}

// enrich looks up every IP behind the scanned hosts.
func enrich(ctx context.Context, results []Result, keys Keys, logf func(string, ...any)) []*Exposure {
	// host -> IPs
	byIP := map[string]*Exposure{}
	var mu sync.Mutex
	hosts := map[string]bool{}
	for _, r := range results {
		hosts[r.Host] = true
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			var ips []net.IP
			if ip := net.ParseIP(h); ip != nil {
				ips = []net.IP{ip}
			} else {
				lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				addrs, _ := net.DefaultResolver.LookupIPAddr(lctx, h)
				cancel()
				for _, a := range addrs {
					ips = append(ips, a.IP)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			for _, ip := range ips {
				key := ip.String()
				e := byIP[key]
				if e == nil {
					e = &Exposure{IP: key, Internal: isInternalIP(ip)}
					byIP[key] = e
				}
				if h != key {
					e.Hosts = append(e.Hosts, h)
				}
			}
		}(h)
	}
	wg.Wait()

	exps := make([]*Exposure, 0, len(byIP))
	for _, e := range byIP {
		sort.Strings(e.Hosts)
		exps = append(exps, e)
	}
	sort.Slice(exps, func(i, j int) bool { return ipLess(exps[i].IP, exps[j].IP) })
	public := 0
	for _, e := range exps {
		if !e.Internal {
			public++
		}
	}
	leakKey, shodanKey := keys.get("leakix"), keys.get("shodan")
	shodanSrc := "Shodan InternetDB"
	if shodanKey != "" {
		shodanSrc = "Shodan (clé)"
	}
	logf("[enrich] %d IPs (%d public): reverse DNS, %s%s", len(exps), public, shodanSrc,
		map[bool]string{true: ", LeakIX", false: ""}[leakKey != ""])

	for _, e := range exps {
		wg.Add(1)
		sem <- struct{}{}
		go func(e *Exposure) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			names, _ := net.DefaultResolver.LookupAddr(lctx, e.IP)
			cancel()
			for _, n := range names {
				e.PTR = append(e.PTR, strings.TrimSuffix(n, "."))
			}
			// The hosts file can map dozens of names to one address: keep the first few
			if e.PTR = uniqueStrings(e.PTR); len(e.PTR) > 3 {
				e.PTR = append(e.PTR[:3], fmt.Sprintf("+%d", len(e.PTR)-3))
			}
			if e.Internal {
				return // never send internal addresses to third parties
			}
			// Full Shodan host data with a key, else the free InternetDB summary
			useIDB := shodanKey == ""
			if !useIDB {
				if err := shodanHost(ctx, e, shodanKey); err != nil {
					e.Notes = append(e.Notes, err.Error())
					useIDB = true
				}
			}
			if useIDB {
				if err := internetDB(ctx, e); err != nil {
					e.Notes = append(e.Notes, err.Error())
				}
			}
			if leakKey != "" {
				if err := leakIX(ctx, e, leakKey); err != nil {
					e.Notes = append(e.Notes, err.Error())
				}
			}
		}(e)
	}
	wg.Wait()

	rankVulns(ctx, exps, logf)
	return exps
}

func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	if a4, b4 := ia.To4(), ib.To4(); a4 != nil && b4 != nil {
		return string(a4) < string(b4)
	}
	return string(ia.To16()) < string(ib.To16())
}

// internetDB reads Shodan's free InternetDB: open ports, hostnames, tags, CPEs and CVEs.
func internetDB(ctx context.Context, e *Exposure) error {
	body, status, err := ctGet(ctx, "https://internetdb.shodan.io/"+e.IP, nil)
	if err != nil {
		return fmt.Errorf("internetdb: %w", err)
	}
	if status == http.StatusNotFound {
		return nil // nothing known
	}
	var res struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		CPEs      []string `json:"cpes"`
		Vulns     []string `json:"vulns"`
	}
	if status != http.StatusOK {
		return fmt.Errorf("internetdb: HTTP %d", status)
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return fmt.Errorf("internetdb: %w", err)
	}
	e.Ports, e.Hostnames, e.Tags, e.CPEs = res.Ports, res.Hostnames, res.Tags, res.CPEs
	for _, c := range res.Vulns {
		e.Vulns = append(e.Vulns, Vuln{CVE: c})
	}
	return nil
}

// shodanHost reads the full Shodan host record (key required): organisation, ASN,
// country, OS, open ports with the product / version / page title seen on each, CVEs.
// "No information available" (404) is not an error: Shodan just has not seen the IP.
func shodanHost(ctx context.Context, e *Exposure, key string) error {
	body, status, err := ctGet(ctx, "https://api.shodan.io/shodan/host/"+e.IP+"?key="+url.QueryEscape(key), nil)
	if err != nil {
		return fmt.Errorf("shodan: %w", err)
	}
	switch {
	case status == http.StatusNotFound:
		return nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("shodan: key refused (HTTP %d)", status)
	case status == http.StatusTooManyRequests:
		return errors.New("shodan: rate limit reached")
	case status != http.StatusOK:
		return fmt.Errorf("shodan: HTTP %d", status)
	}
	var res struct {
		Org        string          `json:"org"`
		ISP        string          `json:"isp"`
		ASN        string          `json:"asn"`
		Country    string          `json:"country_name"`
		OS         string          `json:"os"`
		Ports      []int           `json:"ports"`
		Hostnames  []string        `json:"hostnames"`
		Tags       []string        `json:"tags"`
		Vulns      json.RawMessage `json:"vulns"` // list, or object keyed by CVE in older answers
		LastUpdate string          `json:"last_update"`
		Data       []struct {
			Port      int      `json:"port"`
			Transport string   `json:"transport"`
			Product   string   `json:"product"`
			Version   string   `json:"version"`
			CPE23     []string `json:"cpe23"`
			HTTP      *struct {
				Title  string `json:"title"`
				Server string `json:"server"`
			} `json:"http"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return fmt.Errorf("shodan: %w", err)
	}
	e.Org, e.ASN, e.Country, e.OS = res.Org, res.ASN, res.Country, res.OS
	if e.Org == "" {
		e.Org = res.ISP
	}
	e.Ports, e.Hostnames, e.Tags = res.Ports, res.Hostnames, res.Tags
	e.LastSeen = strings.SplitN(res.LastUpdate, "T", 2)[0]
	var cves []string
	if json.Unmarshal(res.Vulns, &cves) != nil {
		var m map[string]any
		if json.Unmarshal(res.Vulns, &m) == nil {
			for c := range m {
				cves = append(cves, c)
			}
		}
	}
	sort.Strings(cves)
	for _, c := range cves {
		e.Vulns = append(e.Vulns, Vuln{CVE: c})
	}
	cpes := map[string]bool{}
	for _, d := range res.Data {
		svc := fmt.Sprintf("%d/%s", d.Port, d.Transport)
		if d.Product != "" {
			svc += " " + strings.TrimSpace(d.Product+" "+d.Version)
		} else if d.HTTP != nil && d.HTTP.Server != "" {
			svc += " " + d.HTTP.Server
		}
		if d.HTTP != nil && d.HTTP.Title != "" {
			svc += " - " + truncate(d.HTTP.Title, 60)
		}
		e.Services = append(e.Services, svc)
		for _, c := range d.CPE23 {
			if !cpes[c] {
				cpes[c] = true
				e.CPEs = append(e.CPEs, c)
			}
		}
	}
	sort.Strings(e.Services)
	return nil
}

// leakIX reads the services and leaks LeakIX indexed for the IP.
func leakIX(ctx context.Context, e *Exposure, key string) error {
	body, status, err := ctGet(ctx, "https://leakix.net/host/"+e.IP, map[string]string{"api-key": key})
	if err != nil {
		return fmt.Errorf("leakix: %w", err)
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status != http.StatusOK {
		return fmt.Errorf("leakix: HTTP %d", status)
	}
	var res struct {
		Services []map[string]any `json:"Services"`
		Leaks    []map[string]any `json:"Leaks"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return fmt.Errorf("leakix: %w", err)
	}
	e.LeakServices = len(res.Services)
	for _, l := range res.Leaks {
		desc := fmt.Sprint(l["event_source"])
		if p, ok := l["port"]; ok {
			desc += " :" + fmt.Sprint(p)
		}
		if lk, ok := l["leak"].(map[string]any); ok && lk["severity"] != nil {
			desc += " (" + fmt.Sprint(lk["severity"]) + ")"
		}
		e.Leaks = append(e.Leaks, desc)
	}
	return nil
}

// rankVulns flags CVEs listed in CISA KEV and adds their EPSS score.
func rankVulns(ctx context.Context, exps []*Exposure, logf func(string, ...any)) {
	cves := map[string]bool{}
	for _, e := range exps {
		for _, v := range e.Vulns {
			cves[v.CVE] = true
		}
	}
	if len(cves) == 0 {
		return
	}
	kev := map[string]bool{}
	var kevRes struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := getJSON(ctx, "cisa-kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil, &kevRes); err != nil {
		logf("[enrich] %v", err)
	}
	for _, v := range kevRes.Vulnerabilities {
		kev[v.CVE] = true
	}

	epss := map[string]float64{}
	list := make([]string, 0, len(cves))
	for c := range cves {
		list = append(list, c)
	}
	sort.Strings(list)
	for i := 0; i < len(list); i += 100 {
		batch := list[i:min(i+100, len(list))]
		var res struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := getJSON(ctx, "epss", "https://api.first.org/data/v1/epss?cve="+strings.Join(batch, ","), nil, &res); err != nil {
			logf("[enrich] %v", err)
			break
		}
		for _, d := range res.Data {
			epss[d.CVE], _ = strconv.ParseFloat(d.EPSS, 64)
		}
	}

	nKEV := 0
	for _, e := range exps {
		for i := range e.Vulns {
			e.Vulns[i].KEV = kev[e.Vulns[i].CVE]
			e.Vulns[i].EPSS = epss[e.Vulns[i].CVE]
			if e.Vulns[i].KEV {
				nKEV++
			}
		}
		sort.Slice(e.Vulns, func(i, j int) bool {
			if e.Vulns[i].KEV != e.Vulns[j].KEV {
				return e.Vulns[i].KEV
			}
			return e.Vulns[i].EPSS > e.Vulns[j].EPSS
		})
	}
	logf("[enrich] %d distinct CVEs, %d occurrences in CISA KEV", len(cves), nKEV)
}

func writeExposureCSV(exps []*Exposure, outdir string) error {
	f, err := os.Create(filepath.Join(outdir, "exposure.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"ip", "internal", "org", "asn", "country", "os", "hosts", "ptr", "shodan_ports", "shodan_hostnames",
		"services", "tags", "cpes", "cves", "kev_cves", "max_epss", "leakix_services", "leakix_leaks", "shodan_last_seen", "notes"})
	for _, e := range exps {
		var cves, kevs []string
		maxEPSS := 0.0
		for _, v := range e.Vulns {
			cves = append(cves, v.CVE)
			if v.KEV {
				kevs = append(kevs, v.CVE)
			}
			maxEPSS = max(maxEPSS, v.EPSS)
		}
		ports := make([]string, len(e.Ports))
		for i, p := range e.Ports {
			ports[i] = strconv.Itoa(p)
		}
		w.Write([]string{e.IP, strconv.FormatBool(e.Internal), e.Org, e.ASN, e.Country, e.OS,
			strings.Join(e.Hosts, " "), strings.Join(e.PTR, " "), strings.Join(ports, " "), strings.Join(e.Hostnames, " "),
			strings.Join(e.Services, "; "), strings.Join(e.Tags, " "), strings.Join(e.CPEs, " "),
			strings.Join(cves, " "), strings.Join(kevs, " "), strconv.FormatFloat(maxEPSS, 'f', 4, 64),
			strconv.Itoa(e.LeakServices), strings.Join(e.Leaks, "; "), e.LastSeen, strings.Join(e.Notes, "; ")})
	}
	w.Flush()
	return w.Error()
}
