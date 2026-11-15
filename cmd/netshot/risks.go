package main

// "Top risques": the findings of every check, ranked, at the top of the report, so the client sees
// first what to fix first. Each line names the asset and points to the section that details it.

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

type Risk struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Asset    string `json:"asset"`
	Section  string `json:"section"`
}

var tagRisk = map[string][2]string{
	"debug":     {"haute", "Page de débogage exposée"},
	"admin":     {"moyenne", "Interface d'administration exposée"},
	"index-of":  {"moyenne", "Liste de fichiers ouverte (index of)"},
	"default":   {"info", "Page par défaut (serveur non configuré)"},
	"auth-http": {"info", "Authentification HTTP basique"},
}

// collectRisks gathers the findings of the scan, most severe first.
func collectRisks(results []Result, exps []*Exposure, tlsResults []TLSResult, takeovers []Takeover,
	reps []*Reputation, cloud *CloudReport, ext *Extra) []Risk {
	var out []Risk
	add := func(sev, title, asset, section string) {
		out = append(out, Risk{sev, title, asset, section})
	}
	for _, x := range exps {
		hosts := x.IP
		if len(x.Hosts) > 0 {
			hosts += " (" + strings.Join(x.Hosts, ", ") + ")"
		}
		for _, v := range x.Vulns {
			switch {
			case v.KEV:
				add("critique", "Vulnérabilité exploitée activement (CISA KEV) : "+v.CVE, hosts, "Exposition des IP")
			case v.EPSS >= 0.5:
				add("haute", fmt.Sprintf("Vulnérabilité à forte probabilité d'exploitation (EPSS %.0f %%) : %s", v.EPSS*100, v.CVE), hosts, "Exposition des IP")
			}
		}
		for _, l := range x.Leaks {
			add("haute", "Fuite de données signalée par LeakIX : "+l, hosts, "Exposition des IP")
		}
	}
	seenTag := map[string]bool{}
	for _, r := range results {
		svc := fmt.Sprintf("%s:%d", r.Host, r.Port)
		for _, f := range r.FilesFound {
			if f.Severity == "critique" || f.Severity == "haute" {
				add(f.Severity, "Fichier sensible exposé : /"+f.Path, f.URL, "Fichiers sensibles")
			}
		}
		if r.JS != nil {
			for _, s := range r.JS.Secrets {
				add("haute", "Secret dans le JavaScript : "+s.Type, s.Where, "Analyse des pages")
			}
		}
		for _, t := range r.Tags {
			if tr, ok := tagRisk[t]; ok && tr[0] != "info" && !seenTag[svc+t] {
				seenTag[svc+t] = true
				add(tr[0], tr[1], orStr(r.FinalURL, r.URL), "Pages sensibles")
			}
		}
	}
	for _, t := range tlsResults {
		switch t.Grade {
		case "F":
			add("haute", "Configuration TLS dangereuse (note F)", t.Target, "TLS")
		case "T":
			add("moyenne", "Certificat non reconnu (note T)", t.Target, "TLS")
		}
	}
	for _, t := range takeovers {
		add("haute", "Prise de contrôle de sous-domaine possible ("+t.Service+")", t.Host+" -> "+t.CNAME, "Prise de contrôle de sous-domaine")
	}
	for _, r := range reps {
		if r.Level == "critique" || r.Level == "haute" {
			add(r.Level, "Réputation : "+reputationSummary(r), r.Host, "Réputation")
		}
	}
	if ext != nil {
		for _, u := range ext.UDP {
			if u.Severity != "info" {
				add(u.Severity, fmt.Sprintf("%s (%d/udp) : %s", u.Service, u.Port, u.Detail), u.IP, "Services UDP")
			}
		}
		for _, d := range ext.IPv6 {
			if len(d.V6Only) > 0 {
				add("haute", "Ports ouverts en IPv6 seulement (filtrage IPv6 oublié) : "+ints(d.V6Only), d.Host+" "+d.IPv6, "Parité IPv4 / IPv6")
			}
		}
		n := 0
		for _, h := range ext.GitHub {
			if strings.Contains(h.Query, "password") {
				n++
			}
		}
		if n > 0 {
			add("moyenne", fmt.Sprintf("%d fichier(s) de code public citant un domaine avec un mot de passe, secret ou jeton", n), "GitHub", "Code public (GitHub)")
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank[out[i].Severity] < severityRank[out[j].Severity] })
	return out
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// risksSection shows the 10 most severe findings (identical titles merged).
func risksSection(risks []Risk) string {
	if len(risks) == 0 {
		return `<p><b>Top risques</b> : aucun constat critique, élevé ou moyen.</p>`
	}
	type merged struct {
		Risk
		assets []string
	}
	var list []*merged
	index := map[string]*merged{}
	for _, r := range risks {
		k := r.Severity + "|" + r.Title
		if m := index[k]; m != nil {
			if !containsStr(m.assets, r.Asset) {
				m.assets = append(m.assets, r.Asset)
			}
			continue
		}
		m := &merged{Risk: r, assets: []string{r.Asset}}
		index[k] = m
		list = append(list, m)
	}
	count := map[string]int{}
	for _, m := range list {
		count[m.Severity]++
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, `<details open class="risks"><summary><b>Top risques</b> - %d critique(s), %d élevé(s), %d moyen(s)</summary><table><tr><th>Gravité</th><th>Constat</th><th>Concerne</th><th>Détail</th></tr>`,
		count["critique"], count["haute"], count["moyenne"])
	for i, m := range list {
		if i == 10 {
			fmt.Fprintf(&sb, `<tr><td colspan="4">… et %d autre(s) constat(s) dans les sections ci-dessous.</td></tr>`, len(list)-10)
			break
		}
		assets := m.assets
		more := ""
		if len(assets) > 3 {
			more = fmt.Sprintf(" (+%d)", len(assets)-3)
			assets = assets[:3]
		}
		fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s%s</td><td>%s</td></tr>`, sevBadge(m.Severity),
			html.EscapeString(m.Title), html.EscapeString(strings.Join(assets, ", ")), more, html.EscapeString(m.Section))
	}
	sb.WriteString(`</table></details>`)
	return sb.String()
}
