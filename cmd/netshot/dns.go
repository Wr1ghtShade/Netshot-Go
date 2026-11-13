package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A small DNS client (no dependency) to show what `dig` shows for a domain.
//
// "ANY" queries are refused or answered with a single HINFO record by most modern
// servers (RFC 8482), so the ANY answer is shown as is, then every common type is
// queried one by one.

type DNSRecord struct {
	Name string `json:"name"`
	TTL  uint32 `json:"ttl"`
	Type string `json:"type"`
	Data string `json:"data"`
}

type DNSReport struct {
	Domain   string      `json:"domain"`
	Server   string      `json:"server"`
	Any      []DNSRecord `json:"any"`
	AnyNote  string      `json:"any_note"`
	Records  []DNSRecord `json:"records"`
	Findings []string    `json:"findings"`
	Errors   []string    `json:"errors"`
}

var dnsTypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT", 28: "AAAA",
	33: "SRV", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 99: "SPF",
	255: "ANY", 257: "CAA",
}

func dnsTypeCode(name string) uint16 {
	for k, v := range dnsTypeNames {
		if v == name {
			return k
		}
	}
	return 0
}

// Types asked on the domain itself, then well-known names below it.
var apexTypes = []string{"A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "DS", "DNSKEY", "HTTPS"}

var extraQueries = []struct{ Prefix, Type string }{
	{"www", "CNAME"}, {"www", "A"},
	{"_dmarc", "TXT"}, {"_mta-sts", "TXT"}, {"_smtp._tls", "TXT"}, {"default._bimi", "TXT"},
	{"_autodiscover._tcp", "SRV"}, {"_sip._tls", "SRV"}, {"_sipfederationtls._tcp", "SRV"},
	{"_ldap._tcp", "SRV"}, {"_kerberos._tcp", "SRV"}, {"_ldap._tcp.dc._msdcs", "SRV"}, {"_gc._tcp", "SRV"},
	{"_xmpp-server._tcp", "SRV"}, {"_caldavs._tcp", "SRV"},
}

// dkimSelectors are common DKIM selectors (Google, Microsoft 365, Mailchimp, SendGrid, Mailjet, Brevo,
// Proton, Zoho, Fastmail, Mailgun…). The real selector of a domain can be any word: none found here
// does not prove there is no DKIM.
var dkimSelectors = []string{"google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2", "k3", "s1", "s2",
	"mandrill", "mxvault", "smtp", "mx", "everlytickey1", "everlytickey2", "zoho", "zmail", "protonmail", "protonmail2",
	"protonmail3", "key1", "sig1", "mailjet", "brevo1", "brevo2", "fm1", "fm2", "fm3", "krs", "cm"}

func init() {
	for _, s := range dkimSelectors {
		extraQueries = append(extraQueries, struct{ Prefix, Type string }{s + "._domainkey", "TXT"})
	}
}

// dkimFound returns the selectors that publish a DKIM key, and those whose key is revoked (empty p=).
func dkimFound(domain string, recs []DNSRecord) (found, revoked []string) {
	suffix := "._domainkey." + domain
	// a CNAME selector1._domainkey.domain -> …onmicrosoft.com: the TXT record carries the target name
	alias := map[string]string{}
	for _, r := range recs {
		if name := strings.ToLower(r.Name); r.Type == "CNAME" && strings.HasSuffix(name, suffix) {
			alias[strings.TrimSuffix(strings.ToLower(r.Data), ".")] = strings.TrimSuffix(name, suffix)
		}
	}
	for _, r := range recs {
		if r.Type != "TXT" {
			continue
		}
		name, sel := strings.ToLower(r.Name), ""
		if strings.HasSuffix(name, suffix) {
			sel = strings.TrimSuffix(name, suffix)
		} else if s, ok := alias[name]; ok {
			sel = s
		}
		data := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(r.Data, `"`, ""), " ", ""))
		if sel == "" || !(strings.Contains(data, "v=dkim1") || strings.Contains(data, "p=")) {
			continue
		}
		if strings.Contains(data, "p=;") || strings.HasSuffix(data, "p=") {
			if !containsStr(revoked, sel) {
				revoked = append(revoked, sel)
			}
		} else if !containsStr(found, sel) {
			found = append(found, sel)
		}
	}
	sort.Strings(found)
	sort.Strings(revoked)
	return found, revoked
}

// dnsLookup runs every query against server ("" = system resolvers).
func dnsLookup(ctx context.Context, domain, server string) DNSReport {
	domain = normalizeDomain(domain)
	rep := DNSReport{Domain: domain}
	servers := []string{server}
	if server == "" {
		servers = systemDNSServers()
		if len(servers) == 0 {
			servers = []string{"1.1.1.1"}
			rep.Errors = append(rep.Errors, "no system DNS server found, using 1.1.1.1")
		}
	}
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			servers[i] = net.JoinHostPort(strings.Trim(s, "[]"), "53")
		}
	}

	// ask picks the first server that answers
	ask := func(name string, qtype uint16) ([]DNSRecord, int, string, error) {
		var lastErr error
		for _, s := range servers {
			recs, rcode, err := dnsQuery(ctx, s, name, qtype, 3*time.Second)
			if err == nil {
				return recs, rcode, s, nil
			}
			lastErr = err
		}
		return nil, 0, "", lastErr
	}

	anyRecs, rcode, used, err := ask(domain, 255)
	rep.Server = used
	switch {
	case err != nil:
		rep.AnyNote = "ANY : pas de réponse (" + err.Error() + ")"
	case rcode != 0:
		rep.AnyNote = "ANY refusé par le serveur (" + rcodeName(rcode) + ")"
	case len(anyRecs) == 0:
		rep.AnyNote = "ANY : réponse vide (refus RFC 8482)"
	case len(anyRecs) == 1 && anyRecs[0].Type == "HINFO":
		rep.AnyNote = "ANY : réponse minimale HINFO (RFC 8482), détail par type ci-dessous"
	default:
		rep.AnyNote = fmt.Sprintf("ANY : %d enregistrements", len(anyRecs))
	}
	rep.Any = anyRecs

	type q struct {
		name  string
		qtype string
	}
	var queries []q
	for _, t := range apexTypes {
		queries = append(queries, q{domain, t})
	}
	for _, e := range extraQueries {
		queries = append(queries, q{e.Prefix + "." + domain, e.Type})
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 12)
	seen := map[string]bool{}
	for _, qu := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(qu q) {
			defer wg.Done()
			defer func() { <-sem }()
			recs, rcode, _, err := ask(qu.name, dnsTypeCode(qu.qtype))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s %s: %v", qu.name, qu.qtype, err))
				return
			}
			if rcode != 0 && rcode != 3 { // NXDOMAIN is a normal answer for optional names
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s %s: %s", qu.name, qu.qtype, rcodeName(rcode)))
			}
			for _, r := range recs {
				k := r.Name + "|" + r.Type + "|" + r.Data
				if !seen[k] {
					seen[k] = true
					rep.Records = append(rep.Records, r)
				}
			}
		}(qu)
	}
	wg.Wait()
	order := map[string]int{}
	for i, t := range append(append([]string{}, apexTypes...), "SRV", "RRSIG") {
		order[t] = i
	}
	sort.SliceStable(rep.Records, func(i, j int) bool {
		a, b := rep.Records[i], rep.Records[j]
		if (a.Name == domain) != (b.Name == domain) {
			return a.Name == domain
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if order[a.Type] != order[b.Type] {
			return order[a.Type] < order[b.Type]
		}
		return a.Data < b.Data
	})
	sort.Strings(rep.Errors)
	rep.Findings = dnsFindings(domain, rep.Records)
	return rep
}

// dnsFindings reads the mail, certificate and DNSSEC posture from the records.
func dnsFindings(domain string, recs []DNSRecord) []string {
	var spf, dmarc []string
	var caa, ds, mtasts, ad, mx bool
	for _, r := range recs {
		data := strings.Trim(r.Data, `"`)
		switch {
		case r.Name == domain && r.Type == "TXT" && strings.HasPrefix(strings.ToLower(data), "v=spf1"):
			spf = append(spf, data)
		case r.Name == "_dmarc."+domain && r.Type == "TXT" && strings.HasPrefix(strings.ToLower(data), "v=dmarc1"):
			dmarc = append(dmarc, data)
		case r.Name == domain && r.Type == "CAA":
			caa = true
		case r.Name == domain && r.Type == "DS":
			ds = true
		case r.Name == domain && r.Type == "MX":
			mx = true
		case r.Name == "_mta-sts."+domain && r.Type == "TXT":
			mtasts = true
		case r.Type == "SRV" && (strings.HasPrefix(r.Name, "_ldap._tcp.dc._msdcs.") || strings.HasPrefix(r.Name, "_kerberos._tcp.")):
			ad = true
		}
	}
	var f []string
	switch {
	case len(spf) == 0 && mx:
		f = append(f, "⚠ Pas de SPF alors que le domaine reçoit du mail (MX)")
	case len(spf) == 0:
		f = append(f, "Pas de SPF")
	case len(spf) > 1:
		f = append(f, "⚠ Plusieurs enregistrements SPF : SPF invalide")
	case strings.Contains(spf[0], "+all"):
		f = append(f, "⚠ SPF en +all : n'importe quel serveur peut envoyer pour le domaine")
	case strings.Contains(spf[0], "?all"):
		f = append(f, "SPF neutre (?all) : peu protecteur")
	case strings.Contains(spf[0], "~all"):
		f = append(f, "SPF en ~all (softfail)")
	case strings.Contains(spf[0], "-all"):
		f = append(f, "✓ SPF strict (-all)")
	}
	if len(dmarc) == 0 {
		f = append(f, "⚠ Pas de DMARC")
	} else {
		p := ""
		for _, part := range strings.Split(dmarc[0], ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(k, "p") {
				p = strings.ToLower(v)
			}
		}
		switch p {
		case "reject":
			f = append(f, "✓ DMARC p=reject")
		case "quarantine":
			f = append(f, "✓ DMARC p=quarantine")
		default:
			f = append(f, "⚠ DMARC p="+p+" : surveillance seulement, aucun blocage")
		}
	}
	dkim, revoked := dkimFound(domain, recs)
	switch {
	case len(dkim) > 0:
		f = append(f, "✓ DKIM publié (sélecteur(s) : "+strings.Join(dkim, ", ")+")")
	case mx || len(spf) > 0:
		f = append(f, fmt.Sprintf("DKIM non trouvé parmi %d sélecteurs courants (le sélecteur réel peut être un autre)", len(dkimSelectors)))
	}
	if len(revoked) > 0 {
		f = append(f, "Clé DKIM révoquée (p= vide) : "+strings.Join(revoked, ", "))
	}
	if caa {
		f = append(f, "✓ CAA présent : autorités de certification limitées")
	} else {
		f = append(f, "Pas de CAA : toute autorité de certification peut émettre")
	}
	if ds {
		f = append(f, "✓ DNSSEC actif (DS publié)")
	} else {
		f = append(f, "DNSSEC absent (pas de DS)")
	}
	if mtasts {
		f = append(f, "✓ MTA-STS publié")
	}
	if ad {
		f = append(f, "⚠ Enregistrements Active Directory visibles (_ldap / _kerberos)")
	}
	return f
}

// dnsHosts returns the host names and IPs found in the records (for the targets).
func dnsHosts(recs []DNSRecord) []string {
	var out []string
	for _, r := range recs {
		switch r.Type {
		case "A", "AAAA", "CNAME", "NS":
			out = append(out, strings.TrimSuffix(r.Data, "."))
		case "MX":
			if f := strings.Fields(r.Data); len(f) == 2 && f[1] != "." {
				out = append(out, strings.TrimSuffix(f[1], "."))
			}
		case "SRV":
			if f := strings.Fields(r.Data); len(f) == 4 && f[3] != "." {
				out = append(out, strings.TrimSuffix(f[3], "."))
			}
		}
		if (r.Type == "A" || r.Type == "AAAA") && r.Name != "" {
			out = append(out, r.Name)
		}
	}
	return uniqueStrings(out)
}

// formatDig prints a report the way dig does.
func formatDig(rep DNSReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "; netshot DNS %s  @%s\n;; %s\n", rep.Domain, rep.Server, rep.AnyNote)
	for _, r := range rep.Any {
		fmt.Fprintf(&sb, "%s.\t%d\tIN\t%s\t%s\n", r.Name, r.TTL, r.Type, r.Data)
	}
	sb.WriteString("\n;; RECORDS (type by type)\n")
	for _, r := range rep.Records {
		fmt.Fprintf(&sb, "%-40s %6d IN %-7s %s\n", r.Name+".", r.TTL, r.Type, r.Data)
	}
	sb.WriteString("\n;; FINDINGS\n")
	for _, f := range rep.Findings {
		sb.WriteString(";  " + f + "\n")
	}
	if len(rep.Errors) > 0 {
		sb.WriteString("\n;; ERRORS\n")
		for _, e := range rep.Errors {
			sb.WriteString(";  " + e + "\n")
		}
	}
	return sb.String()
}

// --- Wire format ------------------------------------------------------------------

func rcodeName(rc int) string {
	switch rc {
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return "RCODE " + strconv.Itoa(rc)
}

func buildQuery(name string, qtype uint16) ([]byte, uint16, error) {
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	msg := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(msg[4:], 1)      // one question
	binary.BigEndian.PutUint16(msg[10:], 1)     // one additional: EDNS0
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid name %q", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN
	// EDNS0 OPT record: 4096-byte UDP answers, so long TXT records fit
	msg = append(msg, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	return msg, id, nil
}

func dnsQuery(ctx context.Context, server, name string, qtype uint16, timeout time.Duration) ([]DNSRecord, int, error) {
	query, id, err := buildQuery(name, qtype)
	if err != nil {
		return nil, 0, err
	}
	resp, err := exchange(ctx, "udp", server, query, timeout)
	// Retry over TCP when the UDP answer is truncated, or empty without error: some
	// resolvers (1.1.1.1) drop large answers (big TXT sets) without setting the TC flag.
	if err == nil && len(resp) >= 12 {
		truncated := resp[2]&0x02 != 0
		empty := binary.BigEndian.Uint16(resp[6:]) == 0 && resp[3]&0x0F == 0
		if truncated || empty {
			if tresp, terr := exchange(ctx, "tcp", server, query, timeout); terr == nil && len(tresp) >= 12 {
				resp = tresp
			}
		}
	}
	if err != nil {
		return nil, 0, err
	}
	if len(resp) < 12 || binary.BigEndian.Uint16(resp) != id {
		return nil, 0, errors.New("invalid answer")
	}
	return parseAnswer(resp)
}

func exchange(ctx context.Context, network, server string, query []byte, timeout time.Duration) ([]byte, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if network == "tcp" {
		buf := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		if _, err := conn.Write(append(buf, query...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := ioReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		_, err := ioReadFull(conn, resp)
		return resp, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	resp := make([]byte, 65535)
	n, err := conn.Read(resp)
	return resp[:n], err
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for jumps := 0; jumps < 64; jumps++ {
		if off >= len(msg) {
			return "", 0, errors.New("truncated name")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		case l&0xC0 == 0xC0: // compression pointer
			if off+1 >= len(msg) {
				return "", 0, errors.New("truncated pointer")
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		default:
			if off+1+l > len(msg) {
				return "", 0, errors.New("truncated label")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, errors.New("name loop")
}

func parseAnswer(msg []byte) ([]DNSRecord, int, error) {
	rcode := int(msg[3] & 0x0F)
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := readName(msg, off)
		if err != nil {
			return nil, rcode, err
		}
		off = next + 4
	}
	var recs []DNSRecord
	for i := 0; i < an; i++ {
		name, next, err := readName(msg, off)
		if err != nil || next+10 > len(msg) {
			return recs, rcode, errors.New("truncated answer")
		}
		typ := binary.BigEndian.Uint16(msg[next:])
		ttl := binary.BigEndian.Uint32(msg[next+4:])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8:]))
		start := next + 10
		if start+rdlen > len(msg) {
			return recs, rcode, errors.New("truncated rdata")
		}
		tname := dnsTypeNames[typ]
		if tname == "" {
			tname = "TYPE" + strconv.Itoa(int(typ))
		}
		recs = append(recs, DNSRecord{Name: name, TTL: ttl, Type: tname, Data: rdataString(msg, typ, start, rdlen)})
		off = start + rdlen
	}
	return recs, rcode, nil
}

// rdataString renders record data like dig does.
func rdataString(msg []byte, typ uint16, start, n int) string {
	rd := msg[start : start+n]
	nameAt := func(off int) string {
		s, _, err := readName(msg, off)
		if err != nil {
			return "?"
		}
		return s + "."
	}
	charStrings := func(b []byte) []string {
		var out []string
		for len(b) > 0 {
			l := int(b[0])
			if 1+l > len(b) {
				break
			}
			out = append(out, strconv.Quote(string(b[1:1+l])))
			b = b[1+l:]
		}
		return out
	}
	switch typ {
	case 1, 28:
		return net.IP(rd).String()
	case 2, 5, 12:
		return nameAt(start)
	case 15:
		if n < 3 {
			break
		}
		return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(rd), nameAt(start+2))
	case 16, 99, 13:
		return strings.Join(charStrings(rd), " ")
	case 6:
		mname, o, err := readName(msg, start)
		if err != nil {
			break
		}
		rname, o2, err := readName(msg, o)
		if err != nil || o2+20 > start+n {
			break
		}
		v := msg[o2:]
		return fmt.Sprintf("%s. %s. %d %d %d %d %d", mname, rname, binary.BigEndian.Uint32(v),
			binary.BigEndian.Uint32(v[4:]), binary.BigEndian.Uint32(v[8:]), binary.BigEndian.Uint32(v[12:]),
			binary.BigEndian.Uint32(v[16:]))
	case 33:
		if n < 7 {
			break
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(rd), binary.BigEndian.Uint16(rd[2:]),
			binary.BigEndian.Uint16(rd[4:]), nameAt(start+6))
	case 257:
		if n < 2 || 2+int(rd[1]) > n {
			break
		}
		tl := int(rd[1])
		return fmt.Sprintf("%d %s %q", rd[0], rd[2:2+tl], rd[2+tl:])
	case 43:
		if n < 4 {
			break
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(rd), rd[2], rd[3], strings.ToUpper(hex.EncodeToString(rd[4:])))
	case 48:
		if n < 4 {
			break
		}
		key := base64.StdEncoding.EncodeToString(rd[4:])
		if len(key) > 40 {
			key = key[:40] + "…"
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(rd), rd[2], rd[3], key)
	case 64, 65:
		return svcbString(msg, start, n)
	}
	return fmt.Sprintf(`\# %d %s`, n, hex.EncodeToString(rd))
}

// svcbString renders HTTPS / SVCB records: priority, target and the common parameters.
func svcbString(msg []byte, start, n int) string {
	if n < 3 {
		return "?"
	}
	prio := binary.BigEndian.Uint16(msg[start:])
	target, off, err := readName(msg, start+2)
	if err != nil {
		return "?"
	}
	if target == "" {
		target = "."
	} else {
		target += "."
	}
	parts := []string{strconv.Itoa(int(prio)), target}
	end := start + n
	for off+4 <= end {
		key := binary.BigEndian.Uint16(msg[off:])
		l := int(binary.BigEndian.Uint16(msg[off+2:]))
		v := msg[off+4 : min(off+4+l, end)]
		off += 4 + l
		switch key {
		case 1: // alpn
			var alpn []string
			for len(v) > 0 && 1+int(v[0]) <= len(v) {
				alpn = append(alpn, string(v[1:1+int(v[0])]))
				v = v[1+int(v[0]):]
			}
			parts = append(parts, "alpn="+strings.Join(alpn, ","))
		case 3:
			if len(v) == 2 {
				parts = append(parts, "port="+strconv.Itoa(int(binary.BigEndian.Uint16(v))))
			}
		case 4, 6:
			size := map[uint16]int{4: 4, 6: 16}[key]
			var ips []string
			for i := 0; i+size <= len(v); i += size {
				ips = append(ips, net.IP(v[i:i+size]).String())
			}
			parts = append(parts, map[uint16]string{4: "ipv4hint=", 6: "ipv6hint="}[key]+strings.Join(ips, ","))
		case 5:
			parts = append(parts, "ech=…")
		default:
			parts = append(parts, fmt.Sprintf("key%d=%s", key, hex.EncodeToString(v)))
		}
	}
	return strings.Join(parts, " ")
}
