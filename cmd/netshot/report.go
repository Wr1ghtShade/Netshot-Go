package main

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// findDifferences returns what changes between user agents for one host:port (nil = same answer).
func findDifferences(group []Result) []string {
	var diffs []string
	distinct := func(f func(Result) string) bool {
		set := map[string]bool{}
		for _, r := range group {
			set[f(r)] = true
		}
		return len(set) > 1
	}
	if distinct(func(r Result) string { return strconv.Itoa(r.Status) }) {
		diffs = append(diffs, "status")
	}
	if distinct(func(r Result) string { return r.Title }) {
		diffs = append(diffs, "title")
	}
	if distinct(func(r Result) string { return r.FinalURL }) {
		diffs = append(diffs, "redirect")
	}
	if distinct(func(r Result) string { return strconv.FormatBool(r.File != "") }) {
		diffs = append(diffs, "capture failed")
	}
	lo, hi, n := 0, 0, 0
	for _, r := range group {
		if r.Size > 0 {
			if n == 0 || r.Size < lo {
				lo = r.Size
			}
			if r.Size > hi {
				hi = r.Size
			}
			n++
		}
	}
	if n > 1 && float64(hi-lo) > 0.2*float64(hi) {
		diffs = append(diffs, "page size")
	}
	return diffs
}

// sortResults orders by host then port (stable: the user agents keep their order).
func sortResults(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})
}

func writeReports(results []Result, exposures []*Exposure, tlsResults []TLSResult, outdir string,
	inv []*TechEntry, visualGroups [][]int, takeovers []Takeover, reps []*Reputation) error {
	sortResults(results) // already sorted when groups were computed: indexes stay valid
	firsts := map[int]bool{}
	for _, g := range visualGroups {
		firsts[g[0]] = true
	}
	for i := range results {
		// A sensitive page is never hidden as a visual duplicate (near-blank listings look alike)
		results[i].Dup = results[i].Group > 0 && !firsts[i] && len(results[i].Tags) == 0
	}

	f, err := os.Create(filepath.Join(outdir, "results.csv"))
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	w.Write([]string{"host", "port", "ua", "url", "status", "title", "final_url", "size", "file", "error",
		"tags", "tech", "favicon_hash", "header_issues", "visual_group", "waf", "waf_probe", "mixed_content", "no_sri", "trackers", "third_party_hosts"})
	for _, r := range results {
		w.Write([]string{r.Host, strconv.Itoa(r.Port), r.UA, r.URL, itoaOrEmpty(r.Status), r.Title,
			r.FinalURL, itoaOrEmpty(r.Size), r.File, r.Error, strings.Join(r.Tags, " "),
			strings.Join(techLabels(r.Tech), "; "), r.FaviconHash, strings.Join(r.HeaderIssues, "; "), itoaOrEmpty(r.Group),
			strings.Join(r.WAF, "; "), r.WAFProbe, strings.Join(r.MixedContent, " "), strings.Join(r.NoSRI, " "),
			strings.Join(r.Trackers, "; "), strings.Join(r.ThirdParty, " ")})
	}
	w.Flush()
	f.Close()
	if err := w.Error(); err != nil {
		return err
	}

	// One section per host:port, one card per user agent
	type key struct {
		host string
		port int
	}
	var order []key
	groups := map[key][]Result{}
	multiUA := false
	for _, r := range results {
		k := key{r.Host, r.Port}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	samePage := func(g []Result) []Result { // -dirs captures are other pages, not other user agents
		var out []Result
		for _, r := range g {
			if !r.Dir {
				out = append(out, r)
			}
		}
		return out
	}
	for _, g := range groups {
		multiUA = multiUA || len(samePage(g)) > 1
	}

	e := html.EscapeString
	// host (name or IP) -> exposures of its IPs
	byHost := map[string][]*Exposure{}
	for _, x := range exposures {
		byHost[x.IP] = append(byHost[x.IP], x)
		for _, h := range x.Hosts {
			byHost[h] = append(byHost[h], x)
		}
	}
	var sb strings.Builder
	nDiff := 0
	for _, k := range order {
		group := groups[k]
		var diffs []string
		if sp := samePage(group); len(sp) > 1 {
			diffs = findDifferences(sp)
		}
		class, badge := "same", ""
		allDup := true
		for _, r := range group {
			allDup = allDup && r.Dup
		}
		if allDup {
			class += " alldup"
		}
		if len(diffs) > 0 {
			nDiff++
			class = strings.Replace(class, "same", "has-diff", 1)
			badge = fmt.Sprintf(`<span class="diff">differs: %s</span>`, e(strings.Join(diffs, ", ")))
		}
		fmt.Fprintf(&sb, `<section class="%s"><h2>%s:%d %s</h2>`, class, e(k.host), k.port, badge)
		for _, x := range byHost[k.host] {
			sb.WriteString(exposureLine(x))
		}
		sb.WriteString(`<div class="grid">`)
		for _, r := range group {
			img := fmt.Sprintf(`<div class="err">%s</div>`, e(r.Error))
			if r.File != "" {
				img = fmt.Sprintf(`<a href="%s"><img src="%s" loading="lazy"></a>`, e(r.File), e(r.File))
			} else if r.Service != "" || r.Banner != "" {
				svc := r.Service
				if svc == "" {
					svc = "service"
				}
				img = fmt.Sprintf(`<div class="err" style="color:#333"><b>%s %s</b><br><code>%s</code></div>`, e(svc), e(r.ServiceVersion), e(r.Banner))
			}
			dup := ""
			if r.Dup {
				dup = " dup"
			}
			ua := ""
			if multiUA {
				ua = fmt.Sprintf(`<span class="ua">%s</span> `, e(r.UA))
			}
			size := ""
			if r.Size > 0 {
				size = fmt.Sprintf(` <span class="size">%d KB</span>`, r.Size/1024)
			}
			fmt.Fprintf(&sb, `<div class="card%s"%s>%s<div class="meta">%s<a href="%s">%s</a><br><b>%s</b> %s%s%s</div></div>`,
				dup, cardData(r), img, ua, e(r.URL), e(r.URL), itoaOrEmpty(r.Status), e(r.Title), size, cardExtras(r))
		}
		sb.WriteString(`</div></section>`)
	}

	filter := ""
	if multiUA {
		filter = fmt.Sprintf(`<label><input type="checkbox" id="only"> only show the %d services that answer differently depending on the user agent</label>`, nDiff)
	}
	page := fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><title>NetShot - rapport</title>
<link rel="icon" type="image/png" href="{{LOGO}}">
<style>
body{font-family:sans-serif;background:#f4f4f4;margin:16px}
h2{font-size:16px;margin:24px 0 8px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px}
.card{background:#fff;border:1px solid #ddd;border-radius:6px;overflow:hidden}
.card img{width:100%%;display:block;border-bottom:1px solid #eee}
.meta{padding:8px;font-size:13px;word-break:break-all}
.err{padding:40px 8px;color:#a00;font-size:12px}
.ua{background:#246;color:#fff;border-radius:3px;padding:1px 6px;font-size:12px}
.size{color:#777}
.diff{background:#c60;color:#fff;border-radius:3px;padding:2px 8px;font-size:12px;font-weight:normal}
body.only section.same{display:none}
.exp{font-size:13px;color:#333;margin:0 0 8px}
.kev{background:#b00;color:#fff;border-radius:3px;padding:1px 5px;font-size:12px}
.cve{background:#eee;border-radius:3px;padding:1px 5px;font-size:12px}
table{border-collapse:collapse;background:#fff;font-size:13px;margin:8px 0 16px;width:100%%}
th,td{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#f0f0f0}
details{margin:8px 0}
h1.brand{display:flex;align-items:center;gap:10px;margin:0 0 4px}
h1.brand img{width:36px;height:36px}
{{TLSCSS}}
{{WEBCSS}}
</style></head><body>
<h1 class="brand"><img src="{{LOGO}}" alt="">NetShot</h1><p>v{{VERSION}} - %d services, %d captures - %s</p>
{{TOP}}
%s
{{TLS}}
{{BOTTOM}}
%s
%s
<script>
var c=document.getElementById('only');
if(c)c.onchange=function(){document.body.classList.toggle('only',c.checked)};
{{FILTERJS}}
</script></body></html>`, len(order), len(results), time.Now().Format("2006-01-02 15:04"),
		exposureTable(exposures), filter, sb.String())
	// The logo is embedded so the report stays a single self-contained file
	page = strings.ReplaceAll(page, "{{VERSION}}", version)
	page = strings.ReplaceAll(page, "{{LOGO}}", "data:image/png;base64,"+base64.StdEncoding.EncodeToString(iconPNG))
	page = strings.Replace(page, "{{TLSCSS}}", tlsCSS, 1)
	page = strings.Replace(page, "{{TLS}}", tlsSection(tlsResults), 1)
	page = strings.Replace(page, "{{WEBCSS}}", webCSS+filterCSS+reconCSS, 1)
	page = strings.Replace(page, "{{TOP}}", reputationSection(reps)+takeoverSection(takeovers)+filesSection(results)+sensitiveSection(results)+
		jsSection(results)+techSection(inv)+bannersSection(results)+wellKnownSection(results), 1)
	page = strings.Replace(page, "{{BOTTOM}}", headersSection(results)+pageChecksSection(results)+groupsSection(results, visualGroups)+filterBar(results), 1)
	page = strings.Replace(page, "{{FILTERJS}}", filterJS, 1)
	return os.WriteFile(filepath.Join(outdir, "report.html"), []byte(page), 0o644)
}

// vulnBadges renders CVEs: KEV ones in red, with their EPSS score.
func vulnBadges(vs []Vuln, limit int) string {
	var sb strings.Builder
	for i, v := range vs {
		if i == limit {
			fmt.Fprintf(&sb, ` +%d`, len(vs)-limit)
			break
		}
		class, title := "cve", fmt.Sprintf("EPSS %.1f%%", v.EPSS*100)
		if v.KEV {
			class, title = "kev", "CISA KEV - "+title
		}
		fmt.Fprintf(&sb, ` <span class="%s" title="%s">%s</span>`, class, title, html.EscapeString(v.CVE))
	}
	return sb.String()
}

// exposureLine is the one-line summary shown under each host:port.
func exposureLine(x *Exposure) string {
	e := html.EscapeString
	parts := []string{"IP " + e(x.IP)}
	if len(x.PTR) > 0 {
		parts = append(parts, "PTR "+e(strings.Join(x.PTR, ", ")))
	}
	if x.Internal {
		parts = append(parts, "interne")
	}
	if x.Org != "" {
		parts = append(parts, e(x.Org))
	}
	if len(x.Ports) > 0 {
		ports := make([]string, len(x.Ports))
		for i, p := range x.Ports {
			ports[i] = strconv.Itoa(p)
		}
		parts = append(parts, "Shodan : ports "+strings.Join(ports, ","))
	}
	if x.LeakServices > 0 || len(x.Leaks) > 0 {
		parts = append(parts, fmt.Sprintf("LeakIX : %d services, %d fuites", x.LeakServices, len(x.Leaks)))
	}
	line := strings.Join(parts, " · ")
	if len(x.Vulns) > 0 {
		line += " ·" + vulnBadges(x.Vulns, 6)
	}
	return `<p class="exp">` + line + `</p>`
}

// exposureTable is the summary of every IP, most critical first.
func exposureTable(exps []*Exposure) string {
	if len(exps) == 0 {
		return ""
	}
	sorted := append([]*Exposure{}, exps...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.kevCount() != b.kevCount() {
			return a.kevCount() > b.kevCount()
		}
		return len(a.Vulns)+len(a.Leaks) > len(b.Vulns)+len(b.Leaks)
	})
	e := html.EscapeString
	var sb strings.Builder
	nKEV, nCVE := 0, 0
	for _, x := range exps {
		nKEV += x.kevCount()
		nCVE += len(x.Vulns)
	}
	fmt.Fprintf(&sb, `<details open><summary><b>Exposition (sources passives)</b> - %d IP, %d CVE, %d dans CISA KEV</summary>`,
		len(exps), nCVE, nKEV)
	sb.WriteString(`<table><tr><th>IP</th><th>Organisation</th><th>Noms</th><th>Ports (Shodan)</th><th>Services / technologies</th><th>CVE</th><th>LeakIX</th></tr>`)
	for _, x := range sorted {
		names := append(append(append([]string{}, x.Hosts...), x.PTR...), x.Hostnames...)
		ports := make([]string, len(x.Ports))
		for i, p := range x.Ports {
			ports[i] = strconv.Itoa(p)
		}
		ip := e(x.IP)
		if x.Internal {
			ip += " <i>(interne)</i>"
		}
		leaks := ""
		if x.LeakServices > 0 || len(x.Leaks) > 0 {
			leaks = fmt.Sprintf("%d services<br>%s", x.LeakServices, e(strings.Join(x.Leaks, ", ")))
		}
		org := e(strings.TrimSpace(strings.Join(uniqueStrings([]string{x.Org, x.ASN, x.Country}), " · ")))
		if x.OS != "" {
			org += "<br>OS : " + e(x.OS)
		}
		if x.LastSeen != "" {
			org += "<br><i>vu le " + e(x.LastSeen) + "</i>"
		}
		// Shodan services (with key) first, then tags and CPEs
		tech := append(append(append([]string{}, x.Services...), x.Tags...), x.CPEs...)
		fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			ip, org, e(strings.Join(uniqueStrings(names), ", ")), strings.Join(ports, ", "),
			strings.ReplaceAll(e(strings.Join(tech, "\n")), "\n", "<br>"), vulnBadges(x.Vulns, 12), leaks)
	}
	sb.WriteString(`</table></details>`)
	return sb.String()
}

func uniqueStrings(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func itoaOrEmpty(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}
