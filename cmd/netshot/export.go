package main

// results.json (everything the scan found) and results.xlsx (one sheet per topic, filters and frozen
// header), written with the standard library only.

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func writeResultsJSON(outdir string, results []Result, exps []*Exposure, tlsResults []TLSResult, inv []*TechEntry,
	groups [][]int, takeovers []Takeover) error {
	var similar [][]string
	for _, g := range groups {
		var urls []string
		for _, i := range g {
			urls = append(urls, results[i].URL)
		}
		similar = append(similar, urls)
	}
	data := map[string]any{
		"generated":     time.Now().Format(time.RFC3339),
		"services":      results,
		"technologies":  inv,
		"exposure":      exps,
		"tls":           tlsResults,
		"similar_pages": similar,
		"takeovers":     takeovers,
	}
	b, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outdir, "results.json"), b, 0o644)
}

// --- Minimal xlsx writer ---------------------------------------------------------------------------

type sheet struct {
	name   string
	header []string
	rows   [][]any
}

var badXML = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f]`)

func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func colName(n int) string {
	s := ""
	for n > 0 {
		n--
		s = string(rune('A'+n%26)) + s
		n /= 26
	}
	return s
}

func xlsxCell(ref string, v any, style int) string {
	st := ""
	if style > 0 {
		st = fmt.Sprintf(` s="%d"`, style)
	}
	switch x := v.(type) {
	case bool:
		b := 0
		if x {
			b = 1
		}
		return fmt.Sprintf(`<c r="%s" t="b"%s><v>%d</v></c>`, ref, st, b)
	case int:
		return fmt.Sprintf(`<c r="%s"%s><v>%d</v></c>`, ref, st, x)
	case float64:
		return fmt.Sprintf(`<c r="%s"%s><v>%g</v></c>`, ref, st, x)
	}
	text := badXML.ReplaceAllString(fmt.Sprint(v), "")
	if r := []rune(text); len(r) > 32000 {
		text = string(r[:32000])
	}
	if text == "" {
		return ""
	}
	return fmt.Sprintf(`<c r="%s" t="inlineStr"%s><is><t xml:space="preserve">%s</t></is></c>`, ref, st, xmlEsc(text))
}

func sheetXML(s sheet) string {
	widths := make([]int, len(s.header))
	for i, h := range s.header {
		widths[i] = len([]rune(h))
	}
	for _, row := range s.rows {
		for i, v := range row {
			for _, line := range strings.Split(fmt.Sprint(v), "\n") {
				widths[i] = max(widths[i], min(60, len([]rune(line))))
			}
		}
	}
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	sb.WriteString(`<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>`)
	for i, w := range widths {
		fmt.Fprintf(&sb, `<col min="%d" max="%d" width="%d" customWidth="1"/>`, i+1, i+1, w+2)
	}
	sb.WriteString(`</cols><sheetData><row r="1">`)
	for i, h := range s.header {
		sb.WriteString(xlsxCell(fmt.Sprintf("%s1", colName(i+1)), h, 1))
	}
	sb.WriteString(`</row>`)
	for n, row := range s.rows {
		fmt.Fprintf(&sb, `<row r="%d">`, n+2)
		for i, v := range row {
			style := 0
			if str, ok := v.(string); ok && strings.Contains(str, "\n") {
				style = 2
			}
			sb.WriteString(xlsxCell(fmt.Sprintf("%s%d", colName(i+1), n+2), v, style))
		}
		sb.WriteString(`</row>`)
	}
	fmt.Fprintf(&sb, `</sheetData><autoFilter ref="A1:%s%d"/></worksheet>`, colName(len(s.header)), max(1, len(s.rows)+1))
	return sb.String()
}

func writeXLSX(path string, sheets []sheet) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	z := zip.NewWriter(f)
	put := func(name, content string) error {
		w, err := z.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(content))
		return err
	}
	ct := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
		`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`
	var wbSheets, wbRels, defined strings.Builder
	for i, s := range sheets {
		n := i + 1
		if err := put(fmt.Sprintf("xl/worksheets/sheet%d.xml", n), sheetXML(s)); err != nil {
			return err
		}
		ct += fmt.Sprintf(`<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, n)
		name := s.name
		if r := []rune(name); len(r) > 31 {
			name = string(r[:31])
		}
		fmt.Fprintf(&wbSheets, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, xmlEsc(name), n, n)
		fmt.Fprintf(&wbRels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, n, n)
		fmt.Fprintf(&defined, `<definedName name="_xlnm._FilterDatabase" localSheetId="%d" hidden="1">'%s'!$A$1:$%s$%d</definedName>`,
			i, xmlEsc(name), colName(len(s.header)), max(1, len(s.rows)+1))
	}
	fmt.Fprintf(&wbRels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`, len(sheets)+1)
	parts := [][2]string{
		{"[Content_Types].xml", ct + `</Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
		{"xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
			`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>` + wbSheets.String() + `</sheets><definedNames>` + defined.String() + `</definedNames></workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + wbRels.String() + `</Relationships>`},
		{"xl/styles.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
			`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>` +
			`<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>` +
			`<fill><patternFill patternType="solid"><fgColor rgb="FF333333"/></patternFill></fill></fills><borders count="1"><border/></borders>` +
			`<cellStyleXfs count="1"><xf/></cellStyleXfs><cellXfs count="3"><xf/><xf fontId="1" fillId="2" applyFont="1" applyFill="1"/>` +
			`<xf applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf></cellXfs></styleSheet>`},
	}
	for _, p := range parts {
		if err := put(p[0], p[1]); err != nil {
			return err
		}
	}
	return z.Close()
}

func buildSheets(results []Result, exps []*Exposure, inv []*TechEntry, takeovers []Takeover) []sheet {
	var sheets []sheet
	svc := sheet{name: "Services", header: []string{"Hôte", "Port", "UA", "URL", "Code HTTP", "Titre", "URL finale", "Repères",
		"Technologies", "Favicon (hash)", "Groupe visuel", "Constats en-têtes", "Capture", "Erreur"}}
	for _, r := range results {
		group := ""
		if r.Group > 0 {
			group = fmt.Sprint(r.Group)
		}
		svc.rows = append(svc.rows, []any{r.Host, r.Port, r.UA, r.URL, itoaOrEmpty(r.Status), r.Title, r.FinalURL,
			strings.Join(r.Tags, " "), strings.Join(techLabels(r.Tech), ", "), r.FaviconHash, group, len(r.HeaderIssues), r.File, r.Error})
	}
	sheets = append(sheets, svc)
	sens := sheet{name: "Pages sensibles", header: []string{"Repère", "Signification", "URL", "Code HTTP", "Titre"}}
	for _, r := range results {
		for _, t := range r.Tags {
			sens.rows = append(sens.rows, []any{t, tagLabels[t], r.URL, itoaOrEmpty(r.Status), r.Title})
		}
	}
	sheets = append(sheets, sens)
	if len(inv) > 0 {
		tech := sheet{name: "Technologies", header: []string{"Technologie", "Version", "Services", "CVE", "CVE KEV", "EPSS max",
			"CVSS max", "Liste KEV", "Liste CVE", "Identifiants par défaut", "URL"}}
		for _, e := range inv {
			var all, kev []string
			maxE, maxC := 0.0, 0.0
			for _, v := range e.Vulns {
				all = append(all, v.CVE)
				if v.KEV {
					kev = append(kev, v.CVE)
				}
				maxE, maxC = max(maxE, v.EPSS), max(maxC, v.CVSS)
			}
			tech.rows = append(tech.rows, []any{e.Name, e.Version, len(e.URLs), len(e.Vulns), len(kev), maxE, maxC,
				strings.Join(kev, " "), strings.Join(all, " "), defaultCreds[e.Name], strings.Join(e.URLs, "\n")})
		}
		sheets = append(sheets, tech)
	}
	hdr := sheet{name: "En-têtes", header: []string{"URL", "Constat"}}
	seen := map[string]bool{}
	for _, r := range results {
		for _, i := range r.HeaderIssues {
			if k := r.URL + "\x00" + i; !seen[k] {
				seen[k] = true
				hdr.rows = append(hdr.rows, []any{r.URL, i})
			}
		}
	}
	sheets = append(sheets, hdr)
	files := sheet{name: "Fichiers exposés", header: []string{"Gravité", "URL", "Octets lus"}}
	for _, r := range results {
		for _, f := range r.FilesFound {
			files.rows = append(files.rows, []any{f.Severity, f.URL, f.Size})
		}
	}
	if len(files.rows) > 0 {
		sheets = append(sheets, files)
	}
	js := sheet{name: "JavaScript", header: []string{"Page", "Type", "Détail", "Valeur (secrets masqués)", "Source:ligne"}}
	for _, r := range results {
		if r.JS == nil {
			continue
		}
		for _, s := range r.JS.Secrets {
			js.rows = append(js.rows, []any{r.URL, "secret", s.Type, s.Value, s.Where})
		}
		for _, u := range r.JS.InternalURLs {
			js.rows = append(js.rows, []any{r.URL, "URL interne", "", u, ""})
		}
		for _, ep := range r.JS.Endpoints {
			js.rows = append(js.rows, []any{r.URL, "chemin d'API", "", ep, ""})
		}
	}
	if len(js.rows) > 0 {
		sheets = append(sheets, js)
	}
	if len(takeovers) > 0 {
		t := sheet{name: "Takeover", header: []string{"Gravité", "Nom", "Chaîne CNAME", "Service", "Raison"}}
		for _, x := range takeovers {
			t.rows = append(t.rows, []any{x.Level, x.Host, x.CNAME, x.Service, x.Reason})
		}
		sheets = append(sheets, t)
	}
	nw := sheet{name: "Services non web", header: []string{"Hôte", "Port", "Produit", "Version", "Bannière", "Identifiants par défaut"}}
	seenSvc := map[string]bool{}
	for _, r := range results {
		k := fmt.Sprintf("%s:%d", r.Host, r.Port)
		if (r.Banner != "" || r.Service != "") && !seenSvc[k] {
			seenSvc[k] = true
			nw.rows = append(nw.rows, []any{r.Host, r.Port, r.Service, r.ServiceVersion, r.Banner, defaultCreds[r.Service]})
		}
	}
	if len(nw.rows) > 0 {
		sheets = append(sheets, nw)
	}
	wk := sheet{name: "robots, sitemap", header: []string{"Service", "Source", "Valeur"}}
	for _, r := range results {
		w := r.WellKnown
		if w.empty() {
			continue
		}
		for _, p := range w.Robots {
			wk.rows = append(wk.rows, []any{r.URL, "robots.txt", p})
		}
		if w.SitemapURLs > 0 {
			wk.rows = append(wk.rows, []any{r.URL, "sitemap", fmt.Sprintf("%d URL", w.SitemapURLs)})
		}
		for _, k := range []string{"contact", "expires", "policy", "encryption", "hiring"} {
			if v := w.Security[k]; len(v) > 0 {
				wk.rows = append(wk.rows, []any{r.URL, "security.txt " + k, strings.Join(v, ", ")})
			}
		}
	}
	if len(wk.rows) > 0 {
		sheets = append(sheets, wk)
	}
	if len(exps) > 0 {
		ex := sheet{name: "Exposition", header: []string{"IP", "Interne", "Organisation", "ASN", "Pays", "Noms", "Ports (Shodan)",
			"Services", "CVE", "CVE KEV", "Liste CVE", "LeakIX"}}
		for _, e := range exps {
			var ports, all, kev []string
			for _, p := range e.Ports {
				ports = append(ports, fmt.Sprint(p))
			}
			for _, v := range e.Vulns {
				all = append(all, v.CVE)
				if v.KEV {
					kev = append(kev, v.CVE)
				}
			}
			ex.rows = append(ex.rows, []any{e.IP, e.Internal, e.Org, e.ASN, e.Country, strings.Join(e.Hosts, " "),
				strings.Join(ports, " "), strings.Join(e.Services, "; "), len(e.Vulns), strings.Join(kev, " "), strings.Join(all, " "),
				strings.Join(e.Leaks, "; ")})
		}
		sheets = append(sheets, ex)
	}
	return sheets
}
