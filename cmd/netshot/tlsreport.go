package main

import (
	"encoding/csv"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Output of the TLS analysis: text (CLI), certificates.csv and a section of report.html.

func protoList(r TLSResult) string {
	var on []string
	for _, p := range protoOrder {
		if r.Protocols[p] {
			on = append(on, p)
		}
	}
	return strings.Join(on, " ")
}

func formatTLS(r TLSResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "== %s  (IP %s, SNI %s)  note %s\n", r.Target, r.IP, r.SNI, r.Grade)
	if r.Error != "" {
		fmt.Fprintf(&sb, "   %s\n\n", r.Error)
		return sb.String()
	}
	fmt.Fprintf(&sb, "   Protocoles   : %s\n", protoList(r))
	fmt.Fprintf(&sb, "   Négocié      : %s  groupe %s  ALPN %s\n", r.Negotiated, r.KeyGroup, r.ALPN)
	fmt.Fprintf(&sb, "   PQC (X25519MLKEM768) : %v\n", r.PQ)
	if c := r.Cert; c != nil {
		fmt.Fprintf(&sb, "   Certificat   : %s\n   Émetteur     : %s\n", c.Subject, c.Issuer)
		fmt.Fprintf(&sb, "   Validité     : %s -> %s (%d jours restants)\n", c.NotBefore, c.NotAfter, c.DaysLeft)
		fmt.Fprintf(&sb, "   Clé / sig.   : %s / %s\n", c.Key, c.SigAlg)
		fmt.Fprintf(&sb, "   SAN          : %s\n", strings.Join(c.SANs, ", "))
		fmt.Fprintf(&sb, "   Confiance    : %v  nom OK %v  auto-signé %v  OCSP agrafé %v  SCT %v\n",
			c.Trusted, c.NameMatch, c.SelfSigned, c.OCSPStapled, c.SCT)
		for _, ch := range c.Chain {
			fmt.Fprintf(&sb, "   Chaîne       : %s\n", ch)
		}
	}
	for _, p := range protoOrder {
		for _, ci := range r.Ciphers[p] {
			fmt.Fprintf(&sb, "   %-7s %-9s %s\n", p, ci.Strength, ci.Name)
		}
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&sb, "   - %s\n", f)
	}
	sb.WriteString("\n")
	return sb.String()
}

func writeTLSCSV(results []TLSResult, outdir string) error {
	f, err := os.Create(filepath.Join(outdir, "certificates.csv"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"target", "ip", "grade", "protocols", "pqc_mlkem", "negotiated", "key_group", "alpn",
		"subject", "issuer", "sans", "not_after", "days_left", "key", "signature", "trusted", "name_match",
		"self_signed", "ocsp_stapled", "sct", "hsts", "weak_ciphers", "insecure_ciphers", "findings", "error"})
	for _, r := range results {
		weak, insecure := 0, 0
		for _, list := range r.Ciphers {
			for _, c := range list {
				switch c.Strength {
				case "weak":
					weak++
				case "insecure":
					insecure++
				}
			}
		}
		row := []string{r.Target, r.IP, r.Grade, protoList(r), strconv.FormatBool(r.PQ), r.Negotiated, r.KeyGroup, r.ALPN}
		if c := r.Cert; c != nil {
			row = append(row, c.Subject, c.Issuer, strings.Join(c.SANs, " "), c.NotAfter, strconv.Itoa(c.DaysLeft), c.Key,
				c.SigAlg, strconv.FormatBool(c.Trusted), strconv.FormatBool(c.NameMatch), strconv.FormatBool(c.SelfSigned),
				strconv.FormatBool(c.OCSPStapled), strconv.FormatBool(c.SCT))
		} else {
			row = append(row, "", "", "", "", "", "", "", "", "", "", "", "")
		}
		row = append(row, r.HSTS, strconv.Itoa(weak), strconv.Itoa(insecure), strings.Join(r.Findings, " | "), r.Error)
		w.Write(row)
	}
	w.Flush()
	return w.Error()
}

// tlsSection is the "Certificats et TLS" part of report.html.
func tlsSection(results []TLSResult) string {
	if len(results) == 0 {
		return ""
	}
	e := html.EscapeString
	yes := func(b bool) string {
		if b {
			return `<span class="ok">oui</span>`
		}
		return `<span class="no">non</span>`
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, `<details open><summary><b>Certificats et TLS</b> - %d point(s) d'accès</summary><table>`, len(results))
	sb.WriteString(`<tr><th>Cible</th><th>Note</th><th>Expiration</th><th>Protocoles</th><th>PQC</th><th>Clé / signature</th><th>Émetteur</th><th>Confiance</th><th>Constats</th></tr>`)
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(&sb, `<tr><td>%s</td><td>-</td><td colspan="7">%s</td></tr>`, e(r.Target), e(r.Error))
			continue
		}
		exp, key, issuer, trust := "", "", "", ""
		if c := r.Cert; c != nil {
			cls := ""
			if c.DaysLeft < 0 {
				cls = "no"
			} else if c.DaysLeft < 30 {
				cls = "warnc"
			}
			exp = fmt.Sprintf(`<span class="%s">%s<br>%d j</span>`, cls, e(c.NotAfter), c.DaysLeft)
			key = e(c.Key) + "<br>" + e(c.SigAlg)
			issuer = e(c.Issuer)
			trust = yes(c.Trusted && c.NameMatch)
		}
		var protos []string
		for _, p := range protoOrder {
			if r.Protocols[p] {
				cls := "ok"
				if p == "SSLv3" || p == "TLS1.0" || p == "TLS1.1" {
					cls = "no"
				}
				protos = append(protos, fmt.Sprintf(`<span class="%s">%s</span>`, cls, p))
			}
		}
		var finds []string
		for _, f := range r.Findings {
			if strings.HasPrefix(f, "⚠") {
				finds = append(finds, e(f))
			}
		}
		fmt.Fprintf(&sb, `<tr><td>%s</td><td><b class="grade g%s">%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			e(r.Target), strings.TrimSuffix(r.Grade, "+"), e(r.Grade), exp, strings.Join(protos, " "), yes(r.PQ),
			key, issuer, trust, strings.Join(finds, "<br>"))
	}
	sb.WriteString(`</table></details>`)
	return sb.String()
}

const tlsCSS = `
.ok{color:#15803d;font-weight:600}.no{color:#b91c1c;font-weight:600}.warnc{color:#c2410c;font-weight:600}
.grade{display:inline-block;min-width:28px;text-align:center;border-radius:4px;padding:1px 4px;color:#fff}
.gA{background:#15803d}.gB{background:#65a30d}.gC{background:#ca8a04}.gT{background:#c2410c}.gF{background:#b91c1c}
`
