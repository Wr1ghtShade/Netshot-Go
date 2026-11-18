package main

// DefectDojo export: defectdojo.json in the "Generic Findings Import" format, to import in an
// engagement (Import Scan > Generic Findings Import, or POST /api/v2/import-scan/).
// One finding per risk of the "Top risques" (risks.go), per CVE and IP, and per sensitive file not
// already among the risks. unique_id_from_tool is stable from one scan to the next, so a reimport
// closes what was fixed and keeps the history of what was not.

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ddFinding struct {
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Date             string   `json:"date"`
	CVE              string   `json:"cve,omitempty"`
	Mitigation       string   `json:"mitigation,omitempty"`
	References       string   `json:"references,omitempty"`
	Active           bool     `json:"active"`
	Verified         bool     `json:"verified"`
	StaticFinding    bool     `json:"static_finding"`
	DynamicFinding   bool     `json:"dynamic_finding"`
	UniqueIDFromTool string   `json:"unique_id_from_tool"`
	VulnIDFromTool   string   `json:"vuln_id_from_tool,omitempty"`
	ComponentName    string   `json:"component_name,omitempty"`
	ComponentVersion string   `json:"component_version,omitempty"`
	Endpoints        []string `json:"endpoints,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

var ddSeverity = map[string]string{"critique": "Critical", "haute": "High", "moyenne": "Medium", "basse": "Low", "info": "Info"}

func ddID(parts ...string) string {
	h := sha1.Sum([]byte("netshot\x00" + strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:10])
}

// ddEndpoint turns an asset ("https://x/", "host:443", "203.0.113.5 (a.fr)") into an endpoint.
func ddEndpoint(asset string) []string {
	a := strings.TrimSpace(asset)
	if i := strings.IndexAny(a, " ("); i > 0 {
		a = a[:i]
	}
	if a == "" || strings.Contains(a, "->") {
		return nil
	}
	if u, err := url.Parse(a); err == nil && u.Scheme != "" && u.Host != "" {
		return []string{a}
	}
	if ip := net.ParseIP(strings.Trim(a, "[]")); ip != nil && ip.To4() == nil {
		return []string{"[" + ip.String() + "]"} // DefectDojo reads "//" + endpoint as a URL
	}
	if !strings.ContainsAny(a, ".:") {
		return nil
	}
	return []string{a}
}

// cveSeverity: KEV first, then the CVSS score, then the EPSS; a CVE without score is Medium
// (version deduced from a banner or a database, to confirm).
func cveSeverity(v Vuln) string {
	switch {
	case v.KEV || v.CVSS >= 9:
		return "Critical"
	case v.CVSS >= 7 || v.EPSS >= 0.5:
		return "High"
	case v.CVSS >= 4 || v.CVSS == 0:
		return "Medium"
	}
	return "Low"
}

func buildDefectDojo(results []Result, exps []*Exposure, tlsResults []TLSResult, inv []*TechEntry, takeovers []Takeover,
	reps []*Reputation, cloud *CloudReport, ext *Extra, when time.Time) []ddFinding {
	date := when.Format("2006-01-02")
	var out []ddFinding
	seen := map[string]bool{}
	add := func(f ddFinding) {
		if seen[f.UniqueIDFromTool] {
			return
		}
		seen[f.UniqueIDFromTool] = true
		f.Date, f.Active, f.DynamicFinding = date, true, true
		if r := []rune(f.Title); len(r) > 500 { // DefectDojo rejects a title over its column width
			f.Title = string(r[:497]) + "…"
		}
		var eps []string
		for _, e := range f.Endpoints {
			eps = append(eps, ddEndpoint(e)...)
		}
		f.Endpoints = eps
		out = append(out, f)
	}
	// 1. CVEs, one finding per CVE and IP (InternetDB) or per CVE and technology (NVD)
	for _, x := range exps {
		hosts := append([]string{x.IP}, x.Hosts...)
		for _, v := range x.Vulns {
			desc := fmt.Sprintf("%s signalée sur %s par Shodan InternetDB (version déduite des bannières : à confirmer).", v.CVE, strings.Join(hosts, ", "))
			desc += vulnFacts(v)
			add(ddFinding{Title: v.CVE + " sur " + x.IP, Severity: cveSeverity(v), Description: desc, CVE: v.CVE,
				References: "https://nvd.nist.gov/vuln/detail/" + v.CVE, UniqueIDFromTool: ddID("cve", v.CVE, x.IP),
				VulnIDFromTool: v.CVE, Endpoints: hosts, Tags: []string{"netshot", "cve"}})
		}
	}
	for _, t := range inv {
		for _, v := range t.Vulns {
			desc := fmt.Sprintf("%s concerne %s %s, vu sur : %s.", v.CVE, t.Name, t.Version, strings.Join(t.URLs, ", "))
			desc += vulnFacts(v)
			var eps []string
			for _, u := range t.URLs {
				eps = append(eps, ddEndpoint(u)...)
			}
			add(ddFinding{Title: fmt.Sprintf("%s dans %s %s", v.CVE, t.Name, t.Version), Severity: cveSeverity(v), Description: desc,
				CVE: v.CVE, References: "https://nvd.nist.gov/vuln/detail/" + v.CVE, Mitigation: "Mettre à jour " + t.Name + ".",
				UniqueIDFromTool: ddID("tech", v.CVE, t.Name, t.Version), VulnIDFromTool: v.CVE, ComponentName: t.Name,
				ComponentVersion: t.Version, Endpoints: eps, Tags: []string{"netshot", "cve"}})
		}
	}
	// 2. the other risks of the summary (CVE ones are above)
	for _, r := range collectRisks(results, exps, tlsResults, takeovers, reps, cloud, ext) {
		if strings.Contains(r.Title, "CVE-") {
			continue
		}
		add(ddFinding{Title: r.Title, Severity: ddSeverity[r.Severity], Description: fmt.Sprintf("%s\n\nConcerne : %s\nDétail : section « %s » du rapport NetShot.", r.Title, r.Asset, r.Section),
			UniqueIDFromTool: ddID("risk", r.Title, r.Asset), VulnIDFromTool: r.Section, Endpoints: ddEndpoint(r.Asset),
			Tags: []string{"netshot", strings.ToLower(strings.ReplaceAll(r.Section, " ", "-"))}})
	}
	// 3. sensitive files of lower severity (critical and high ones are risks)
	for _, r := range results {
		for _, f := range r.FilesFound {
			if f.Severity == "critique" || f.Severity == "haute" {
				continue
			}
			add(ddFinding{Title: "Fichier exposé : /" + f.Path, Severity: orStr(ddSeverity[f.Severity], "Info"),
				Description: fmt.Sprintf("%s répond (%d octets).", f.URL, f.Size), UniqueIDFromTool: ddID("risk", "Fichier sensible exposé : /"+f.Path, f.URL),
				VulnIDFromTool: "Fichiers sensibles", Endpoints: ddEndpoint(f.URL), Tags: []string{"netshot", "fichiers-sensibles"}})
		}
	}
	rank := map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

func vulnFacts(v Vuln) string {
	var f []string
	if v.KEV {
		f = append(f, "exploitée activement (catalogue CISA KEV)")
	}
	if v.CVSS > 0 {
		f = append(f, fmt.Sprintf("CVSS %.1f", v.CVSS))
	}
	if v.EPSS > 0 {
		f = append(f, fmt.Sprintf("EPSS %.1f %%", v.EPSS*100))
	}
	if len(f) == 0 {
		return ""
	}
	s := strings.Join(f, ", ")
	return " " + strings.ToUpper(s[:1]) + s[1:] + "."
}

// writeDefectDojo writes defectdojo.json (Generic Findings Import).
func writeDefectDojo(outdir string, findings []ddFinding) error {
	doc := map[string]any{
		"name":     "NetShot " + time.Now().Format("2006-01-02 15:04"),
		"type":     "NetShot",
		"version":  version,
		"findings": findings,
	}
	if findings == nil {
		doc["findings"] = []ddFinding{}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outdir, "defectdojo.json"), data, 0o644)
}
