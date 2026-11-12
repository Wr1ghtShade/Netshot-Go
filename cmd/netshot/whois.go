package main

// Who owns a domain, an IP address or an AS. Same behaviour as the Python version (core/whois.py).
//
// Two sources, queried in parallel:
//   - RDAP (RFC 9082/9083): structured JSON over HTTPS, the server found through the IANA bootstrap
//     files. Used for the summary table and the findings.
//   - WHOIS (port 43): the classic text answer, following the IANA referral and, for thin registries
//     such as .com, the registrar's own server. Often blocked by company firewalls: then only RDAP.
//
// A subdomain (www.example.com) is looked up as its registered domain: RDAP is asked for the name
// with one label less until a registry knows it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type WhoisField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type WhoisReport struct {
	Query    string       `json:"query"`
	Kind     string       `json:"kind"` // domain, ip, autnum ("" = not recognized)
	Name     string       `json:"name"`
	RDAPURL  string       `json:"rdap_url"`
	Rows     []WhoisField `json:"rows"`
	Findings []string     `json:"findings"`
	Raw      string       `json:"raw"`
	Errors   []string     `json:"errors"`
}

var (
	whoisASN      = regexp.MustCompile(`(?i)^AS?(\d+)$`)
	whoisRedacted = regexp.MustCompile(`(?i)redact|privacy|not disclosed|withheld|data protected`)
	whoisRefer    = regexp.MustCompile(`(?im)^(?:refer|whois):\s*(\S+)`)
	whoisRegSrv   = regexp.MustCompile(`(?i)Registrar WHOIS Server:\s*(\S+)`)

	bootstrapMu    sync.Mutex
	bootstrapCache = map[string][][][]string{}
)

var whoisEventLabels = []struct{ action, label string }{
	{"registration", "Création"}, {"expiration", "Expiration"}, {"last changed", "Dernière modification"},
	{"last update of RDAP database", "Mise à jour base RDAP"}, {"transfer", "Dernier transfert"},
}

var whoisRoles = []struct{ role, label string }{
	{"registrar", "Registrar"}, {"registrant", "Titulaire"}, {"administrative", "Contact admin"},
	{"technical", "Contact technique"}, {"abuse", "Abuse"}, {"noc", "NOC"},
}

// --- RDAP ------------------------------------------------------------------------------------

func rdapGet(ctx context.Context, url string, v any) (int, error) {
	body, status, err := ctGet(ctx, url, map[string]string{"Accept": "application/rdap+json, application/json"})
	if err != nil {
		return 0, err
	}
	if status == 200 {
		if err := json.Unmarshal(body, v); err != nil {
			return status, fmt.Errorf("réponse illisible : %w", err)
		}
	}
	return status, nil
}

// bootstrap returns the IANA services for "dns", "ipv4", "ipv6" or "asn" (cached for the session).
func bootstrap(ctx context.Context, kind string) ([][][]string, error) {
	bootstrapMu.Lock()
	defer bootstrapMu.Unlock()
	if s, ok := bootstrapCache[kind]; ok {
		return s, nil
	}
	var data struct {
		Services [][][]string `json:"services"`
	}
	status, err := rdapGet(ctx, "https://data.iana.org/rdap/"+kind+".json", &data)
	if err != nil || status != 200 {
		if err == nil {
			err = fmt.Errorf("HTTP %d", status)
		}
		return nil, fmt.Errorf("bootstrap IANA %s : %w", kind, err)
	}
	bootstrapCache[kind] = data.Services
	return data.Services, nil
}

func rdapBase(urls []string) string {
	u := urls[0]
	for _, x := range urls {
		if strings.HasPrefix(x, "https://") {
			u = x
			break
		}
	}
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return u
}

// rdapServer returns the RDAP base URL for the query, "" when the registry has no RDAP service.
func rdapServer(ctx context.Context, kind, query string) (string, error) {
	switch kind {
	case "domain":
		services, err := bootstrap(ctx, "dns")
		if err != nil {
			return "", err
		}
		tld := query[strings.LastIndex(query, ".")+1:]
		for _, s := range services {
			if len(s) == 2 && len(s[1]) > 0 && containsStr(s[0], tld) {
				return rdapBase(s[1]), nil
			}
		}
	case "ip":
		ip, err := netip.ParseAddr(query)
		if err != nil {
			return "", err
		}
		kindFile := "ipv4"
		if ip.Is6() {
			kindFile = "ipv6"
		}
		services, err := bootstrap(ctx, kindFile)
		if err != nil {
			return "", err
		}
		best, bestLen := "", -1
		for _, s := range services {
			if len(s) != 2 || len(s[1]) == 0 {
				continue
			}
			for _, p := range s[0] {
				if pfx, err := netip.ParsePrefix(p); err == nil && pfx.Contains(ip) && pfx.Bits() > bestLen {
					best, bestLen = rdapBase(s[1]), pfx.Bits()
				}
			}
		}
		return best, nil
	case "autnum":
		n, _ := strconv.ParseUint(query, 10, 32)
		services, err := bootstrap(ctx, "asn")
		if err != nil {
			return "", err
		}
		for _, s := range services {
			if len(s) != 2 || len(s[1]) == 0 {
				continue
			}
			for _, r := range s[0] {
				lo, hi, ok := strings.Cut(r, "-")
				if !ok {
					hi = lo
				}
				a, _ := strconv.ParseUint(lo, 10, 32)
				b, _ := strconv.ParseUint(hi, 10, 32)
				if a <= n && n <= b {
					return rdapBase(s[1]), nil
				}
			}
		}
	}
	return "", nil
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// vcard reads fn, org, email, tel and country from a jCard.
func vcard(e map[string]any) map[string]string {
	out := map[string]string{}
	arr, _ := e["vcardArray"].([]any)
	if len(arr) < 2 {
		return out
	}
	items, _ := arr[1].([]any)
	for _, it := range items {
		item, _ := it.([]any)
		if len(item) < 4 {
			continue
		}
		name, _ := item[0].(string)
		params, _ := item[1].(map[string]any)
		switch name {
		case "fn", "org", "email", "tel":
			if _, done := out[name]; !done {
				out[name] = jsonText(item[3])
			}
		case "adr":
			if parts, ok := item[3].([]any); ok && len(parts) > 0 && jsonText(parts[len(parts)-1]) != "" {
				out["country"] = jsonText(parts[len(parts)-1])
			} else if cc, ok := params["cc"].(string); ok {
				out["country"] = cc
			}
		}
	}
	return out
}

func jsonText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		var parts []string
		for _, p := range x {
			if s := jsonText(p); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

// walkEntities flattens nested entities (the abuse contact sits inside the registrar) by role.
func walkEntities(v any, found map[string][]map[string]any) map[string][]map[string]any {
	list, _ := v.([]any)
	for _, x := range list {
		e, ok := x.(map[string]any)
		if !ok {
			continue
		}
		roles, _ := e["roles"].([]any)
		for _, r := range roles {
			if s, ok := r.(string); ok {
				found[s] = append(found[s], e)
			}
		}
		walkEntities(e["entities"], found)
	}
	return found
}

func contact(e map[string]any) string {
	v := vcard(e)
	first := v["fn"]
	if first == "" {
		first = v["org"]
	}
	if first == "" {
		first = jsonText(e["handle"])
	}
	parts := []string{first}
	if v["org"] != "" && v["org"] != first {
		parts = append(parts, v["org"])
	}
	for _, k := range []string{"country", "email"} {
		if v[k] != "" {
			parts = append(parts, v[k])
		}
	}
	return strings.Join(uniqueStrings(parts), " · ")
}

func str(m map[string]any, k string) string { return jsonText(m[k]) }

func whoisDate(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

func whoisSummary(kind string, data map[string]any) []WhoisField {
	var rows []WhoisField
	add := func(label, value string) {
		if value == "" {
			return
		}
		for _, r := range rows {
			if r.Label == label && r.Value == value {
				return
			}
		}
		rows = append(rows, WhoisField{label, value})
	}
	switch kind {
	case "domain":
		ldh := strings.ToLower(str(data, "ldhName"))
		add("Domaine", ldh)
		if u := str(data, "unicodeName"); u != "" && !strings.EqualFold(u, ldh) {
			add("Nom Unicode", u)
		}
	case "ip":
		add("Plage", str(data, "startAddress")+" - "+str(data, "endAddress"))
		var cidrs []string
		list, _ := data["cidr0_cidrs"].([]any)
		for _, c := range list {
			m, _ := c.(map[string]any)
			p := str(m, "v4prefix")
			if p == "" {
				p = str(m, "v6prefix")
			}
			cidrs = append(cidrs, p+"/"+str(m, "length"))
		}
		add("CIDR", strings.Join(cidrs, ", "))
		add("Nom du réseau", str(data, "name"))
		add("Type", str(data, "type"))
		add("Pays", str(data, "country"))
		add("Réseau parent", str(data, "parentHandle"))
	case "autnum":
		as := "AS" + str(data, "startAutnum")
		if end := str(data, "endAutnum"); end != "" && end != str(data, "startAutnum") {
			as += "-AS" + end
		}
		add("AS", as)
		add("Nom", str(data, "name"))
		add("Pays", str(data, "country"))
	}
	add("Identifiant (handle)", str(data, "handle"))
	add("Statut", jsonList(data["status"]))
	events, _ := data["events"].([]any)
	for _, ev := range events {
		m, _ := ev.(map[string]any)
		for _, l := range whoisEventLabels {
			if str(m, "eventAction") == l.action {
				add(l.label, whoisDate(str(m, "eventDate")))
			}
		}
	}
	roles := walkEntities(data["entities"], map[string][]map[string]any{})
	for _, r := range whoisRoles {
		list := roles[r.role]
		if len(list) > 2 {
			list = list[:2]
		}
		for _, e := range list {
			value := contact(e)
			if r.role == "registrar" {
				ids, _ := e["publicIds"].([]any)
				for _, id := range ids {
					m, _ := id.(map[string]any)
					if strings.Contains(str(m, "type"), "IANA") {
						value += " (IANA " + str(m, "identifier") + ")"
						break
					}
				}
			}
			add(r.label, value)
		}
	}
	if kind == "domain" {
		var ns []string
		list, _ := data["nameservers"].([]any)
		for _, n := range list {
			m, _ := n.(map[string]any)
			ns = append(ns, strings.ToLower(str(m, "ldhName")))
		}
		add("Serveurs de noms", strings.Join(ns, ", "))
		if sec, ok := data["secureDNS"].(map[string]any); ok {
			if signed, ok := sec["delegationSigned"].(bool); ok {
				add("DNSSEC", map[bool]string{true: "signé", false: "non signé"}[signed])
			}
		}
	}
	add("Serveur WHOIS", str(data, "port43"))
	return rows
}

func jsonList(v any) string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		out = append(out, jsonText(x))
	}
	return strings.Join(out, ", ")
}

// whoisFindings: expiry, transfer lock, registry lock, DNSSEC, hidden registrant.
func whoisFindings(kind string, data map[string]any) []string {
	var f []string
	if kind != "domain" {
		return f
	}
	events, _ := data["events"].([]any)
	for _, ev := range events {
		m, _ := ev.(map[string]any)
		if str(m, "eventAction") != "expiration" || str(m, "eventDate") == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, str(m, "eventDate"))
		if err != nil {
			continue
		}
		days := int(time.Until(t).Hours() / 24)
		switch {
		case days < 0:
			f = append(f, fmt.Sprintf("⚠ Domaine expiré depuis %d jours", -days))
		case days < 60:
			f = append(f, fmt.Sprintf("⚠ Expire dans %d jours (%s)", days, whoisDate(str(m, "eventDate"))))
		default:
			f = append(f, fmt.Sprintf("✓ Expire dans %d jours (%s)", days, whoisDate(str(m, "eventDate"))))
		}
	}
	status := strings.ToLower(jsonList(data["status"]))
	if status != "" {
		if strings.Contains(status, "transfer prohibited") {
			f = append(f, "✓ Verrou de transfert actif (transfer prohibited)")
		} else {
			f = append(f, "⚠ Pas de verrou de transfert (clientTransferProhibited) : détournement du domaine plus facile")
		}
		for _, s := range strings.Split(status, ", ") {
			if strings.HasPrefix(s, "server") {
				f = append(f, "✓ Verrou au niveau du registre (server…Prohibited)")
				break
			}
		}
	}
	if sec, ok := data["secureDNS"].(map[string]any); ok {
		if signed, ok := sec["delegationSigned"].(bool); ok {
			if signed {
				f = append(f, "✓ DNSSEC : délégation signée")
			} else {
				f = append(f, "⚠ DNSSEC : délégation non signée")
			}
		}
	}
	reg := walkEntities(data["entities"], map[string][]map[string]any{})["registrant"]
	hidden := true
	for _, e := range reg {
		if c := contact(e); c != "" && !whoisRedacted.MatchString(c) {
			hidden = false
		}
	}
	if hidden {
		f = append(f, "Titulaire masqué (RGPD / protection de la vie privée)")
	}
	return f
}

// rdapLookup returns the name actually found, the URL and the object. Domains: strip labels
// until the registry knows one.
func rdapLookup(ctx context.Context, kind, query string) (string, string, map[string]any, error) {
	base, err := rdapServer(ctx, kind, query)
	if err != nil {
		return "", "", nil, err
	}
	if base == "" {
		return "", "", nil, errors.New("pas de serveur RDAP pour cette ressource")
	}
	if kind == "domain" {
		labels := strings.Split(query, ".")
		last := 0
		for i := 0; i < len(labels)-1; i++ {
			name := strings.Join(labels[i:], ".")
			url := base + "domain/" + name
			var data map[string]any
			status, err := rdapGet(ctx, url, &data)
			if err != nil {
				return "", "", nil, err
			}
			if status == 200 && data != nil {
				return name, url, data, nil
			}
			last = status
		}
		return "", "", nil, fmt.Errorf("domaine inconnu du registre (HTTP %d)", last)
	}
	path := "autnum/"
	if kind == "ip" {
		path = "ip/"
	}
	url := base + path + query
	var data map[string]any
	status, err := rdapGet(ctx, url, &data)
	if err != nil {
		return "", "", nil, err
	}
	if status != 200 || data == nil {
		return "", "", nil, fmt.Errorf("HTTP %d", status)
	}
	return query, url, data, nil
}

// --- WHOIS port 43 -------------------------------------------------------------------------------

func whois43(ctx context.Context, server, query string) (string, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil && len(body) == 0 {
		return "", err
	}
	// Servers answer with CRLF: keep plain newlines, or the copied text gets a blank line between each line
	text := strings.ReplaceAll(strings.ToValidUTF8(string(body), "\uFFFD"), "\r\n", "\n")
	return strings.ReplaceAll(text, "\r", "\n"), nil
}

// whoisText: IANA referral, then the registry, then a thin registry's registrar.
func whoisText(ctx context.Context, query string) (string, error) {
	iana, err := whois43(ctx, "whois.iana.org", query)
	if err != nil {
		return "", err
	}
	m := whoisRefer.FindStringSubmatch(iana)
	if m == nil {
		return iana, nil
	}
	server := m[1]
	text, err := whois43(ctx, server, query)
	if err != nil {
		return "", err
	}
	out := []string{"% " + server, strings.TrimSpace(text)}
	if r := whoisRegSrv.FindStringSubmatch(text); r != nil {
		reg := strings.ToLower(r[1])
		for _, p := range []string{"whois://", "http://", "https://"} {
			reg = strings.TrimPrefix(reg, p)
		}
		reg = strings.Trim(reg, "/")
		if reg != "" && reg != strings.ToLower(server) {
			if t, err := whois43(ctx, reg, query); err == nil {
				out = append(out, "", "% "+reg, strings.TrimSpace(t))
			} else {
				out = append(out, "", "% "+reg+" : pas de réponse ("+err.Error()+")")
			}
		}
	}
	return strings.Join(out, "\n") + "\n", nil
}

// --- Entry point ---------------------------------------------------------------------------------

// classifyWhois returns ("ip" | "autnum" | "domain", normalized query) or ("", "").
func classifyWhois(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if m := whoisASN.FindStringSubmatch(raw); m != nil {
		return "autnum", m[1]
	}
	if ip, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return "ip", ip.Unmap().String()
	}
	d := normalizeDomain(raw)
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if strings.Contains(d, ".") && !strings.ContainsAny(d, " @") {
		return "domain", d
	}
	return "", ""
}

func whoisLookup(ctx context.Context, raw string) WhoisReport {
	kind, query := classifyWhois(raw)
	rep := WhoisReport{Query: strings.TrimSpace(raw), Kind: kind, Name: query, Rows: []WhoisField{}, Findings: []string{}, Errors: []string{}}
	if kind == "" {
		rep.Errors = append(rep.Errors, "entrée non reconnue : domaine, IP ou AS1234 attendu")
		return rep
	}
	whoisQuery := query
	if kind == "autnum" {
		rep.Name = "AS" + query
		whoisQuery = rep.Name
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	type rdapRes struct {
		name, url string
		data      map[string]any
		err       error
	}
	rdapCh := make(chan rdapRes, 1)
	go func() {
		n, u, d, err := rdapLookup(ctx, kind, query)
		rdapCh <- rdapRes{n, u, d, err}
	}()
	var rd rdapRes
	got := false
	// For a subdomain, WHOIS needs the registered domain: wait for RDAP to name it
	if kind == "domain" {
		rd, got = <-rdapCh, true
		if rd.err == nil {
			whoisQuery = rd.name
		}
	}
	raw43, err43 := whoisText(ctx, whoisQuery)
	if !got {
		rd = <-rdapCh
	}
	if err43 != nil {
		rep.Errors = append(rep.Errors, "WHOIS (port 43) : "+err43.Error()+" - port 43 souvent filtré en entreprise")
	} else {
		rep.Raw = raw43
	}
	if rd.err != nil {
		rep.Errors = append(rep.Errors, "RDAP : "+rd.err.Error())
		return rep
	}
	if kind != "autnum" {
		rep.Name = rd.name
	}
	rep.RDAPURL = rd.url
	rep.Rows = whoisSummary(kind, rd.data)
	rep.Findings = whoisFindings(kind, rd.data)
	return rep
}

func formatWhois(rep WhoisReport) string {
	head := "; netshot WHOIS " + rep.Query
	if rep.Name != "" && rep.Name != rep.Query {
		head += "  (" + rep.Name + ")"
	}
	lines := []string{head}
	if rep.RDAPURL != "" {
		lines = append(lines, ";; RDAP "+rep.RDAPURL)
	}
	width := 0
	for _, r := range rep.Rows {
		width = max(width, len([]rune(r.Label)))
	}
	for _, r := range rep.Rows {
		lines = append(lines, r.Label+strings.Repeat(" ", width-len([]rune(r.Label))+2)+r.Value)
	}
	if len(rep.Findings) > 0 {
		lines = append(lines, "", ";; FINDINGS")
		for _, x := range rep.Findings {
			lines = append(lines, ";  "+x)
		}
	}
	if len(rep.Errors) > 0 {
		lines = append(lines, "", ";; ERRORS")
		for _, x := range rep.Errors {
			lines = append(lines, ";  "+x)
		}
	}
	if rep.Raw != "" {
		lines = append(lines, "", ";; WHOIS (port 43)", strings.TrimRight(rep.Raw, "\n"))
	}
	return strings.Join(lines, "\n") + "\n"
}
