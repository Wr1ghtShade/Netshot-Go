package main

// Wider discovery around the scanned organisation (1.2.10):
//   - certificate pivot: names of the certificates served on 443 by the targets (SAN); those of the
//     scanned domains are added to the scan. The organisation names (O=) of these certificates are
//     searched in crt.sh: the domains certified under the same name are listed, never added.
//   - IP blocks registered to the organisation (RDAP of the public IPs found): listed, never added.
//   - UDP (-udp, active): DNS (open resolver), NTP, SNMP (v3 discovery, no community tried), IKE,
//     OpenVPN, SSDP on each target IP.
//   - IPv4 / IPv6 parity: the scanned ports of the dual-stack names on both families; a port open
//     in IPv6 only is a forgotten firewall rule.
//   - Code leaks (key "github"): GitHub code search of the organisation's domains (repository, file
//     and link only; the files are not downloaded).
// The "Top risques" summary of the report (risks.go) reads all of it.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
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

type PivotName struct {
	Name      string `json:"name"`
	Via       string `json:"via"`                 // "certificat de host:443" or "crt.sh O=…"
	Added     bool   `json:"added"`               // added to the scan
	Candidate bool   `json:"candidate,omitempty"` // would have been added with -add-discovered
}

type Netblock struct {
	CIDR    string `json:"cidr"`
	Name    string `json:"name"`
	Org     string `json:"org"`
	Handle  string `json:"handle"`
	Match   string `json:"match"` // organisation term found in the block
	FromIP  string `json:"from_ip"`
	Size    int    `json:"size"`    // addresses (IPv4) or 0
	Scanned int    `json:"scanned"` // scanned IPs in the block
}

type UDPService struct {
	IP       string `json:"ip"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

type ParityDiff struct {
	Host   string `json:"host"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
	V6Only []int  `json:"v6_only,omitempty"`
	V4Only []int  `json:"v4_only,omitempty"`
}

type CodeHit struct {
	Repo  string `json:"repo"`
	Path  string `json:"path"`
	URL   string `json:"url"`
	Query string `json:"query"`
}

type Extra struct {
	CertOrgs   []string     `json:"cert_orgs,omitempty"`
	CertNames  []PivotName  `json:"cert_names,omitempty"`
	OrgDomains []PivotName  `json:"org_domains,omitempty"`
	Netblocks  []Netblock   `json:"netblocks,omitempty"`
	UDP        []UDPService `json:"udp,omitempty"`
	UDPNote    string       `json:"udp_note,omitempty"`
	IPv6       []ParityDiff `json:"ipv6_parity,omitempty"`
	IPv6Note   string       `json:"ipv6_note,omitempty"`
	GitHub     []CodeHit    `json:"github,omitempty"`
	GitHubNote string       `json:"github_note,omitempty"`
}

// --- Certificate pivot ---------------------------------------------------------------------------

// certOrgSkip: organisations of shared certificates (CDN, hosting, cloud) that say nothing about the client.
var certOrgSkip = []string{"cloudflare", "amazon", "google", "microsoft", "akamai", "fastly", "automattic",
	"github", "heroku", "salesforce", "ovh", "wix", "squarespace", "shopify", "incapsula", "imperva",
	"sucuri", "zscaler", "let's encrypt", "digicert", "sectigo", "globalsign", "atlassian", "okta", "zendesk"}

func skipOrg(o string) bool {
	l := strings.ToLower(o)
	if len(strings.TrimSpace(l)) < 4 {
		return true
	}
	for _, s := range certOrgSkip {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// peekCert returns the SAN names and organisations of the certificate served on host:443.
func peekCert(ctx context.Context, p *Proxy, host string) ([]string, []string) {
	conn, err := dialTCP(ctx, p, host, 443, 4*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	cfg := &tls.Config{InsecureSkipVerify: true}
	if net.ParseIP(strings.Trim(host, "[]")) == nil {
		cfg.ServerName = host
	}
	c := tls.Client(conn, cfg)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, nil
	}
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil
	}
	return certs[0].DNSNames, certs[0].Subject.Organization
}

// certPivot reads the certificates of the targets and of the hosts already added; it returns the
// names of the organisation's domains to add and fills ext.
func certPivot(ctx context.Context, p *Proxy, hosts []string, own map[string]bool, ext *Extra,
	logf func(string, ...any)) []string {
	targets := hosts
	if len(targets) > 300 {
		targets = targets[:300]
	}
	type peek struct {
		host        string
		names, orgs []string
	}
	res := make([]peek, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i, h := range targets {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			n, o := peekCert(ctx, p, h)
			res[i] = peek{h, n, o}
		}(i, h)
	}
	wg.Wait()
	known := map[string]bool{}
	for _, h := range hosts {
		known[strings.ToLower(h)] = true
	}
	var add []string
	seen := map[string]bool{}
	for _, r := range res {
		for _, o := range r.orgs {
			if !skipOrg(o) && !containsStr(ext.CertOrgs, o) {
				ext.CertOrgs = append(ext.CertOrgs, o)
			}
		}
		for _, n := range r.names {
			n = strings.ToLower(strings.TrimPrefix(n, "*."))
			if n == "" || seen[n] || known[n] || !strings.Contains(n, ".") {
				continue
			}
			seen[n] = true
			pn := PivotName{Name: n, Via: "certificat de " + r.host + ":443"}
			if own[registrableDomain(n)] && resolves(ctx, n) {
				pn.Added = true
				add = append(add, n)
				known[n] = true
			}
			ext.CertNames = append(ext.CertNames, pn)
		}
	}
	if len(ext.CertNames) > 0 {
		logf("[pivot] %d nom(s) lus dans les certificats, %d ajouté(s) au scan", len(ext.CertNames), len(add))
	}
	return add
}

// crtshOrg lists the registrable domains certified under the organisation name org (crt.sh O=).
func crtshOrg(ctx context.Context, org string) ([]string, error) {
	u := "https://crt.sh/?O=" + url.QueryEscape(org) + "&output=json&exclude=expired"
	actx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var rows []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := getJSON(actx, "crt.sh", u, nil, &rows); err != nil {
		return nil, err
	}
	count := map[string]int{}
	for _, r := range rows {
		for _, n := range append(strings.Split(r.NameValue, "\n"), r.CommonName) {
			n = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n), "*.")))
			if n == "" || !strings.Contains(n, ".") || net.ParseIP(n) != nil || strings.ContainsAny(n, " @") {
				continue
			}
			count[registrableDomain(n)]++
		}
	}
	out := make([]string, 0, len(count))
	for d := range count {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if count[out[i]] != count[out[j]] {
			return count[out[i]] > count[out[j]]
		}
		return out[i] < out[j]
	})
	return out, nil
}

// orgPivot searches crt.sh for the organisation names of the certificates (3 at most) and LISTS the
// domains certified under the same name (100 at most): it never adds them to the scan. The same
// organisation name can cover a public website hosted by a third party (shared hosting, agency)
// while the audit covers an internal network: the auditor decides what is in scope.
func orgPivot(ctx context.Context, own map[string]bool, known map[string]bool, ext *Extra, logf func(string, ...any)) []string {
	orgs := ext.CertOrgs
	if len(orgs) > 3 {
		orgs = orgs[:3]
	}
	for _, o := range orgs {
		if ctx.Err() != nil {
			break
		}
		domains, err := crtshOrg(ctx, o)
		if err != nil {
			logf("[pivot] crt.sh O=%s : %v", o, err)
			continue
		}
		n := 0
		for _, d := range domains {
			if own[d] || known[d] || n >= 100 {
				continue
			}
			n++
			ext.OrgDomains = append(ext.OrgDomains, PivotName{Name: d, Via: "crt.sh O=" + o})
		}
		logf("[pivot] crt.sh O=%s : %d autre(s) domaine(s) au même nom, listés dans le rapport (non scannés : à ajouter aux cibles s'ils sont dans le périmètre)", o, n)
	}
	return nil
}

// --- RDAP netblocks ------------------------------------------------------------------------------

func normTerm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// orgTerms: what identifies the organisation in a WHOIS record (certificate organisations, tenant
// brand, first label of its domains).
func orgTerms(ext *Extra, cloud *CloudReport, own map[string]bool) []string {
	var out []string
	add := func(s string) {
		if t := normTerm(s); len(t) >= 4 && !containsStr(out, t) {
			out = append(out, t)
		}
	}
	for _, o := range ext.CertOrgs {
		add(strings.Fields(o + " x")[0]) // first word: "Exemple SA" -> exemple
		add(o)
	}
	if cloud != nil {
		for _, t := range cloud.Tenants {
			add(t.Brand)
		}
	}
	for d := range own {
		add(strings.Split(d, ".")[0])
	}
	return out
}

// findNetblocks looks up the RDAP record of the public IPs (40 at most) and keeps the blocks whose
// name or holder matches the organisation, outside the cloud providers.
func findNetblocks(ctx context.Context, ips []string, cloudIPs map[string]bool, terms []string, ext *Extra,
	logf func(string, ...any)) {
	if len(terms) == 0 {
		return
	}
	seenBlock := map[string]bool{}
	n := 0
	for _, ip := range ips {
		if ctx.Err() != nil || n >= 40 {
			break
		}
		if cloudIPs[ip] {
			continue
		}
		covered := false
		for _, b := range ext.Netblocks {
			if _, nw, err := net.ParseCIDR(b.CIDR); err == nil && nw.Contains(net.ParseIP(ip)) {
				covered = true
			}
		}
		if covered {
			continue
		}
		n++
		_, _, data, err := rdapLookup(ctx, "ip", ip)
		if err != nil || data == nil {
			continue
		}
		name, handle := str(data, "name"), str(data, "handle")
		holder := ""
		for _, role := range []string{"registrant", "administrative"} {
			if es := walkEntities(data["entities"], map[string][]map[string]any{})[role]; len(es) > 0 {
				v := vcard(es[0])
				holder = strings.TrimSpace(v["org"] + " " + v["fn"])
				break
			}
		}
		hay := normTerm(name + " " + holder + " " + jsonText(data["remarks"]))
		match := ""
		for _, t := range terms {
			if strings.Contains(hay, t) {
				match = t
				break
			}
		}
		if match == "" {
			continue
		}
		var cidrs []string
		if list, ok := data["cidr0_cidrs"].([]any); ok {
			for _, x := range list {
				if m, ok := x.(map[string]any); ok {
					pfx := str(m, "v4prefix")
					if pfx == "" {
						pfx = str(m, "v6prefix")
					}
					if l, ok := m["length"].(float64); ok && pfx != "" {
						cidrs = append(cidrs, fmt.Sprintf("%s/%d", pfx, int(l)))
					}
				}
			}
		}
		if len(cidrs) == 0 {
			if s, e := str(data, "startAddress"), str(data, "endAddress"); s != "" {
				cidrs = append(cidrs, s+" - "+e)
			}
		}
		for _, c := range cidrs {
			if seenBlock[c] {
				continue
			}
			seenBlock[c] = true
			size := 0
			if _, nw, err := net.ParseCIDR(c); err == nil {
				if ones, bits := nw.Mask.Size(); bits == 32 {
					if ones < 16 {
						continue // too wide to be the organisation's own block (a provider's)
					}
					size = 1 << (32 - ones)
				}
			}
			ext.Netblocks = append(ext.Netblocks, Netblock{CIDR: c, Name: name, Org: holder, Handle: handle,
				Match: match, FromIP: ip, Size: size})
		}
	}
	for i := range ext.Netblocks {
		_, nw, err := net.ParseCIDR(ext.Netblocks[i].CIDR)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if nw.Contains(net.ParseIP(ip)) {
				ext.Netblocks[i].Scanned++
			}
		}
	}
	if len(ext.Netblocks) > 0 {
		logf("[pivot] %d bloc(s) d'IP au nom de l'organisation (à ajouter au périmètre si le client confirme)", len(ext.Netblocks))
	}
}

// --- UDP -----------------------------------------------------------------------------------------

type udpProbe struct {
	port    int
	service string
	payload func() []byte
	read    func(resp []byte) (detail, severity string)
}

func dnsProbePacket() []byte {
	// recursive query for example.com A: an answer with RA and records = open resolver
	q := []byte{0x13, 0x37, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"example", "com"} {
		q = append(append(q, byte(len(l))), l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

var udpProbes = []udpProbe{
	{53, "DNS", dnsProbePacket, func(r []byte) (string, string) {
		if len(r) < 12 {
			return "répond", "info"
		}
		ra := r[3]&0x80 != 0
		answers := binary.BigEndian.Uint16(r[6:8])
		if ra && answers > 0 && r[3]&0x0f == 0 {
			return "résolveur ouvert : résout pour n'importe qui (amplification DDoS, empoisonnement)", "haute"
		}
		return "serveur DNS (récursion refusée)", "info"
	}},
	{123, "NTP", func() []byte { b := make([]byte, 48); b[0] = 0x23; return b }, func(r []byte) (string, string) {
		if len(r) >= 2 {
			return fmt.Sprintf("serveur NTP (strate %d)", r[1]), "info"
		}
		return "répond", "info"
	}},
	{161, "SNMP", snmpDiscovery, func(r []byte) (string, string) {
		return "SNMP exposé sur Internet (identifiant moteur SNMPv3 obtenu)", "moyenne"
	}},
	{500, "IKE (VPN IPsec)", ikePacket, func(r []byte) (string, string) {
		return "passerelle VPN IPsec (IKE répond)", "info"
	}},
	{1194, "OpenVPN", func() []byte {
		b := []byte{0x38}
		sid := make([]byte, 8)
		rand.Read(sid)
		return append(append(b, sid...), 0, 0, 0, 0, 0)
	}, func(r []byte) (string, string) {
		return "serveur OpenVPN (sans tls-auth : répond à un inconnu)", "info"
	}},
	{1900, "SSDP (UPnP)", func() []byte {
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	}, func(r []byte) (string, string) {
		d := "UPnP exposé sur Internet (amplification DDoS, équipement grand public)"
		for _, l := range strings.Split(string(r), "\r\n") {
			if strings.HasPrefix(strings.ToUpper(l), "SERVER:") {
				d += " - " + strings.TrimSpace(l[7:])
			}
		}
		return d, "moyenne"
	}},
}

// tlv encodes one BER element.
func tlv(tag byte, content ...[]byte) []byte {
	var body []byte
	for _, c := range content {
		body = append(body, c...)
	}
	n := len(body)
	if n < 128 {
		return append([]byte{tag, byte(n)}, body...)
	}
	return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
}

func berInt(v int) []byte {
	b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	for len(b) > 1 && b[0] == 0 && b[1] < 0x80 {
		b = b[1:]
	}
	return tlv(0x02, b)
}

// snmpDiscovery: SNMPv3 engine discovery (RFC 3414 §4), no community and no user: an agent answers
// with a Report carrying its engine ID.
func snmpDiscovery() []byte {
	usm := tlv(0x30, tlv(0x04), berInt(0), berInt(0), tlv(0x04), tlv(0x04), tlv(0x04))
	header := tlv(0x30, berInt(0x1337), berInt(65507), tlv(0x04, []byte{0x04}), berInt(3))
	pdu := tlv(0xa0, berInt(0x2a), berInt(0), berInt(0), tlv(0x30))
	scoped := tlv(0x30, tlv(0x04), tlv(0x04), pdu)
	return tlv(0x30, berInt(3), header, tlv(0x04, usm), scoped)
}

// ikePacket: IKEv1 Main Mode, one proposal (AES-128, SHA1, group 2, PSK) as ike-scan sends.
func ikePacket() []byte {
	transform := []byte{0, 0, 0, 0, 1, 1, 0, 0,
		0x80, 0x01, 0x00, 0x07, 0x80, 0x0e, 0x00, 0x80, 0x80, 0x02, 0x00, 0x02, 0x80, 0x04, 0x00, 0x02,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x0b, 0x00, 0x01, 0x80, 0x0c, 0x70, 0x80}
	binary.BigEndian.PutUint16(transform[2:], uint16(len(transform)))
	proposal := append([]byte{0, 0, 0, 0, 1, 1, 0, 1}, transform...)
	binary.BigEndian.PutUint16(proposal[2:], uint16(len(proposal)))
	sa := append([]byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1}, proposal...)
	binary.BigEndian.PutUint16(sa[2:], uint16(len(sa)))
	hdr := make([]byte, 28)
	rand.Read(hdr[:8])
	hdr[16], hdr[17], hdr[18] = 1, 0x10, 2 // next payload SA, version 1.0, Main Mode
	binary.BigEndian.PutUint32(hdr[24:], uint32(28+len(sa)))
	return append(hdr, sa...)
}

func udpAsk(ctx context.Context, ip string, pr udpProbe) []byte {
	for try := 0; try < 2 && ctx.Err() == nil; try++ {
		conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, strconv.Itoa(pr.port)), 2*time.Second)
		if err != nil {
			return nil
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(pr.payload()); err != nil {
			conn.Close()
			return nil
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err == nil && n > 0 {
			return buf[:n]
		}
	}
	return nil
}

// probeUDP sends the UDP probes to every target IP (256 at most).
func probeUDP(ctx context.Context, ipHosts map[string][]string, ext *Extra, logf func(string, ...any)) {
	ips := make([]string, 0, len(ipHosts))
	for ip := range ipHosts {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) > 256 {
		ext.UDPNote = fmt.Sprintf("%d IP, seules les 256 premières sondées", len(ips))
		ips = ips[:256]
	}
	logf("[udp] %d IP x %d sondes (DNS, NTP, SNMP, IKE, OpenVPN, SSDP)", len(ips), len(udpProbes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for _, ip := range ips {
		for _, pr := range udpProbes {
			wg.Add(1)
			go func(ip string, pr udpProbe) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if r := udpAsk(ctx, ip, pr); r != nil {
					d, sev := pr.read(r)
					mu.Lock()
					ext.UDP = append(ext.UDP, UDPService{IP: ip, Host: strings.Join(ipHosts[ip], ", "), Port: pr.port,
						Service: pr.service, Detail: d, Severity: sev})
					mu.Unlock()
				}
			}(ip, pr)
		}
	}
	wg.Wait()
	sort.Slice(ext.UDP, func(i, j int) bool {
		a, b := ext.UDP[i], ext.UDP[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		return a.Port < b.Port
	})
	logf("[udp] %d service(s) UDP répondent", len(ext.UDP))
}

// --- IPv4 / IPv6 parity --------------------------------------------------------------------------

// hasIPv6 tells whether this machine can reach the IPv6 Internet (a UDP "connection" sends nothing).
func hasIPv6() bool {
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func portOpenCtx(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// checkParity tries the scanned ports on the first IPv4 and the first IPv6 address of every
// dual-stack name (50 names at most).
func checkParity(ctx context.Context, names []string, ports []int, timeout time.Duration, ext *Extra, logf func(string, ...any)) {
	type pair struct{ host, v4, v6 string }
	var pairs []pair
	for _, n := range names {
		if len(pairs) >= 50 || ctx.Err() != nil {
			break
		}
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(lctx, n)
		cancel()
		if err != nil {
			continue
		}
		p := pair{host: n}
		for _, a := range addrs {
			if a.IP.To4() != nil && p.v4 == "" {
				p.v4 = a.IP.String()
			} else if a.IP.To4() == nil && p.v6 == "" && a.IP.IsGlobalUnicast() {
				p.v6 = a.IP.String()
			}
		}
		if p.v4 != "" && p.v6 != "" && !isInternalIP(net.ParseIP(p.v4)) {
			pairs = append(pairs, p)
		}
	}
	if len(pairs) == 0 {
		return
	}
	if !hasIPv6() {
		ext.IPv6Note = fmt.Sprintf("%d nom(s) double pile, mais pas d'accès IPv6 depuis ce poste : parité non vérifiée", len(pairs))
		logf("[ipv6] %s", ext.IPv6Note)
		return
	}
	logf("[ipv6] parité IPv4 / IPv6 de %d nom(s) double pile sur %d port(s)", len(pairs), len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	open := map[string]bool{}
	for _, p := range pairs {
		for _, port := range ports {
			for _, ip := range []string{p.v4, p.v6} {
				wg.Add(1)
				go func(ip string, port int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					if portOpenCtx(ctx, ip, port, timeout) {
						mu.Lock()
						open[ip+"|"+strconv.Itoa(port)] = true
						mu.Unlock()
					}
				}(ip, port)
			}
		}
	}
	wg.Wait()
	for _, p := range pairs {
		d := ParityDiff{Host: p.host, IPv4: p.v4, IPv6: p.v6}
		for _, port := range ports {
			o4, o6 := open[p.v4+"|"+strconv.Itoa(port)], open[p.v6+"|"+strconv.Itoa(port)]
			if o6 && !o4 {
				d.V6Only = append(d.V6Only, port)
			} else if o4 && !o6 {
				d.V4Only = append(d.V4Only, port)
			}
		}
		if len(d.V6Only)+len(d.V4Only) > 0 {
			ext.IPv6 = append(ext.IPv6, d)
		}
	}
	logf("[ipv6] %d nom(s) avec des ports différents entre IPv4 et IPv6", len(ext.IPv6))
}

// --- GitHub --------------------------------------------------------------------------------------

var githubAPI = "https://api.github.com"

// searchGitHub looks for the organisation's domains in public code (3 domains, 2 queries each,
// 7 s apart: code search allows 10 requests per minute).
func searchGitHub(ctx context.Context, domains []string, token string, ext *Extra, logf func(string, ...any)) {
	if len(domains) > 3 {
		domains = domains[:3]
	}
	seen := map[string]bool{}
	first := true
	for _, d := range domains {
		for _, q := range []string{`"` + d + `"`, `"` + d + `" password OR secret OR token OR apikey`} {
			if ctx.Err() != nil {
				return
			}
			if !first {
				select {
				case <-time.After(7 * time.Second):
				case <-ctx.Done():
					return
				}
			}
			first = false
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI+"/search/code?per_page=30&q="+url.QueryEscape(q), nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
			resp, err := cloudClient.Do(req)
			if err != nil {
				ext.GitHubNote = err.Error()
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			resp.Body.Close()
			if resp.StatusCode == 401 {
				ext.GitHubNote = "jeton GitHub refusé (HTTP 401)"
				logf("[github] %s", ext.GitHubNote)
				return
			}
			if resp.StatusCode == 403 || resp.StatusCode == 429 {
				ext.GitHubNote = fmt.Sprintf("limite de recherche GitHub atteinte (HTTP %d) : résultats partiels", resp.StatusCode)
				logf("[github] %s", ext.GitHubNote)
				return
			}
			var res struct {
				Total int `json:"total_count"`
				Items []struct {
					Path    string `json:"path"`
					HTMLURL string `json:"html_url"`
					Repo    struct {
						FullName string `json:"full_name"`
					} `json:"repository"`
				} `json:"items"`
			}
			if resp.StatusCode != 200 || json.Unmarshal(body, &res) != nil {
				continue
			}
			for _, it := range res.Items {
				if seen[it.HTMLURL] {
					continue
				}
				seen[it.HTMLURL] = true
				ext.GitHub = append(ext.GitHub, CodeHit{Repo: it.Repo.FullName, Path: it.Path, URL: it.HTMLURL, Query: q})
			}
			logf("[github] %s : %d fichier(s)", q, res.Total)
		}
	}
}

// --- Report --------------------------------------------------------------------------------------

func (e *Extra) empty() bool {
	return e == nil || len(e.CertNames)+len(e.OrgDomains)+len(e.Netblocks)+len(e.UDP)+len(e.IPv6)+len(e.GitHub) == 0 &&
		e.IPv6Note == "" && e.GitHubNote == "" && e.UDPNote == ""
}

func addedMark(p PivotName) string {
	switch {
	case p.Added:
		return "ajouté au scan"
	case p.Candidate:
		return "découvert, non scanné : à ajouter aux cibles s'il est dans le périmètre"
	case strings.HasPrefix(p.Via, "crt.sh"):
		return "non scanné : à ajouter aux cibles s'il est dans le périmètre"
	}
	return "hors des domaines scannés ou ne résout pas"
}

func extraSections(e *Extra) string {
	if e.empty() {
		return ""
	}
	esc := html.EscapeString
	var sb strings.Builder
	if len(e.CertNames)+len(e.OrgDomains)+len(e.Netblocks) > 0 {
		added := 0
		for _, p := range append(append([]PivotName{}, e.CertNames...), e.OrgDomains...) {
			if p.Added {
				added++
			}
		}
		fmt.Fprintf(&sb, `<details><summary><b>Découverte élargie</b> - %d nom(s) ou domaine(s) trouvé(s), %d ajouté(s) au scan, %d bloc(s) d'IP au nom de l'organisation</summary>`,
			len(e.CertNames)+len(e.OrgDomains), added, len(e.Netblocks))
		if len(e.CertOrgs) > 0 {
			fmt.Fprintf(&sb, `<p>Organisation(s) des certificats : %s</p>`, esc(strings.Join(e.CertOrgs, ", ")))
		}
		if list := append(append([]PivotName{}, e.CertNames...), e.OrgDomains...); len(list) > 0 {
			sb.WriteString(`<table><tr><th>Nom</th><th>Trouvé par</th><th>Suite</th></tr>`)
			for _, p := range list {
				fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td></tr>`, esc(p.Name), esc(p.Via), addedMark(p))
			}
			sb.WriteString(`</table>`)
			var todo []string
			for _, p := range list {
				if p.Candidate || (!p.Added && strings.HasPrefix(p.Via, "crt.sh")) {
					todo = append(todo, p.Name)
				}
			}
			if len(todo) > 0 {
				fmt.Fprintf(&sb, `<p>Non scannés, à ajouter aux cibles s'ils sont dans le périmètre : <code>%s</code></p>`, esc(strings.Join(todo, " ")))
			}
		}
		if len(e.Netblocks) > 0 {
			sb.WriteString(`<p>Blocs d'IP enregistrés au nom de l'organisation (RDAP) : <b>non scannés</b>, à ajouter au périmètre si le client confirme qu'ils sont à lui.</p>`)
			sb.WriteString(`<table><tr><th>Bloc</th><th>Nom</th><th>Titulaire</th><th>Indice</th><th>Vu depuis</th><th>IP scannées</th></tr>`)
			var cidrs []string
			for _, b := range e.Netblocks {
				cidrs = append(cidrs, b.CIDR)
				fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d / %d</td></tr>`,
					esc(b.CIDR), esc(b.Name), esc(b.Org), esc(b.Match), esc(b.FromIP), b.Scanned, b.Size)
			}
			sb.WriteString(`</table>`)
			fmt.Fprintf(&sb, `<p>Cibles à copier : <code>%s</code></p>`, esc(strings.Join(cidrs, " ")))
		}
		sb.WriteString(`</details>`)
	}
	if len(e.UDP) > 0 || e.UDPNote != "" {
		fmt.Fprintf(&sb, `<details><summary><b>Services UDP</b> - %d réponse(s)</summary>`, len(e.UDP))
		if e.UDPNote != "" {
			fmt.Fprintf(&sb, `<p>%s</p>`, esc(e.UDPNote))
		}
		if len(e.UDP) > 0 {
			sb.WriteString(`<table><tr><th>Gravité</th><th>IP</th><th>Noms</th><th>Port</th><th>Service</th><th>Constat</th></tr>`)
			for _, u := range e.UDP {
				fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%d/udp</td><td>%s</td><td>%s</td></tr>`,
					sevBadge(u.Severity), esc(u.IP), esc(u.Host), u.Port, esc(u.Service), esc(u.Detail))
			}
			sb.WriteString(`</table>`)
		}
		sb.WriteString(`</details>`)
	}
	if len(e.IPv6) > 0 || e.IPv6Note != "" {
		fmt.Fprintf(&sb, `<details><summary><b>Parité IPv4 / IPv6</b> - %d nom(s) avec des écarts</summary>`, len(e.IPv6))
		if e.IPv6Note != "" {
			fmt.Fprintf(&sb, `<p>%s</p>`, esc(e.IPv6Note))
		}
		if len(e.IPv6) > 0 {
			sb.WriteString(`<table><tr><th>Nom</th><th>IPv4</th><th>IPv6</th><th>Ouverts en IPv6 seulement</th><th>Ouverts en IPv4 seulement</th></tr>`)
			for _, d := range e.IPv6 {
				v6 := ints(d.V6Only)
				if v6 != "" {
					v6 = sevBadge("haute") + " " + v6
				}
				fmt.Fprintf(&sb, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					esc(d.Host), esc(d.IPv4), esc(d.IPv6), v6, ints(d.V4Only))
			}
			sb.WriteString(`</table>`)
		}
		sb.WriteString(`</details>`)
	}
	if len(e.GitHub) > 0 || e.GitHubNote != "" {
		fmt.Fprintf(&sb, `<details><summary><b>Code public (GitHub)</b> - %d fichier(s) citant les domaines</summary>`, len(e.GitHub))
		if e.GitHubNote != "" {
			fmt.Fprintf(&sb, `<p>%s</p>`, esc(e.GitHubNote))
		}
		if len(e.GitHub) > 0 {
			sb.WriteString(`<p>Fichiers non téléchargés : à relire pour y chercher des identifiants, des clés ou des URL internes.</p>`)
			sb.WriteString(`<table><tr><th>Dépôt</th><th>Fichier</th><th>Recherche</th></tr>`)
			for _, h := range e.GitHub {
				fmt.Fprintf(&sb, `<tr><td>%s</td><td><a href="%s" target="_blank" rel="noopener">%s</a></td><td>%s</td></tr>`,
					esc(h.Repo), esc(h.URL), esc(h.Path), esc(h.Query))
			}
			sb.WriteString(`</table>`)
		}
		sb.WriteString(`</details>`)
	}
	return sb.String()
}

func ints(list []int) string {
	s := make([]string, len(list))
	for i, v := range list {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ", ")
}

// extraRows: one line per finding (discovery.csv and the "Découverte" sheet).
func extraRows(e *Extra) [][]string {
	if e == nil {
		return nil
	}
	var rows [][]string
	for _, p := range append(append([]PivotName{}, e.CertNames...), e.OrgDomains...) {
		rows = append(rows, []string{"nom", p.Name, p.Via, addedMark(p), ""})
	}
	for _, b := range e.Netblocks {
		rows = append(rows, []string{"bloc IP", b.CIDR, b.Name + " / " + b.Org, "indice " + b.Match + ", vu depuis " + b.FromIP,
			fmt.Sprintf("%d / %d IP scannées", b.Scanned, b.Size)})
	}
	for _, u := range e.UDP {
		rows = append(rows, []string{"udp", u.IP, fmt.Sprintf("%d/udp %s", u.Port, u.Service), u.Detail, u.Severity})
	}
	for _, d := range e.IPv6 {
		rows = append(rows, []string{"ipv6", d.Host, d.IPv4 + " / " + d.IPv6, "IPv6 seulement : " + ints(d.V6Only),
			"IPv4 seulement : " + ints(d.V4Only)})
	}
	for _, h := range e.GitHub {
		rows = append(rows, []string{"github", h.Repo, h.Path, h.URL, h.Query})
	}
	return rows
}

var extraHeader = []string{"type", "item", "detail", "finding", "extra"}

// resolveTargets maps every target IPv4 address to its names (256 names resolved at most).
func resolveTargets(ctx context.Context, hosts []string) map[string][]string {
	out := map[string][]string{}
	n := 0
	for _, h := range hosts {
		h = strings.Trim(h, "[]")
		if ip := net.ParseIP(h); ip != nil {
			if _, ok := out[h]; !ok && ip.To4() != nil {
				out[h] = nil
			}
			continue
		}
		if n >= 256 || ctx.Err() != nil {
			continue
		}
		n++
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(lctx, h)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IP.To4() != nil {
				out[a.IP.String()] = appendUnique(out[a.IP.String()], h)
			}
		}
	}
	return out
}

// runExtraChecks runs the post-scan checks of discover.go and writes discovery.csv.
func runExtraChecks(ctx context.Context, opt Options, hosts, ownDomains []string, results []Result, exps []*Exposure,
	cloud *CloudReport, ext *Extra, logf func(string, ...any)) {
	if ctx.Err() != nil {
		return
	}
	var ipHosts map[string][]string
	if opt.Pivot || opt.UDP {
		ipHosts = resolveTargets(ctx, hosts)
	}
	if opt.Pivot && len(ipHosts) > 0 {
		cloudIPs := map[string]bool{}
		if cloud != nil {
			for _, x := range cloud.IPs {
				cloudIPs[x.IP] = true
			}
		}
		var public []string
		for ip := range ipHosts {
			if !isInternalIP(net.ParseIP(ip)) {
				public = append(public, ip)
			}
		}
		sort.Strings(public)
		own := map[string]bool{}
		for _, d := range ownDomains {
			own[d] = true
		}
		findNetblocks(ctx, public, cloudIPs, orgTerms(ext, cloud, own), ext, logf)
	}
	if opt.UDP {
		if opt.Proxy != nil {
			ext.UDPNote = "sondes UDP impossibles à travers le proxy : non lancées"
			logf("[udp] %s", ext.UDPNote)
		} else if len(ipHosts) > 0 {
			probeUDP(ctx, ipHosts, ext, logf)
		}
	}
	if opt.IPv6Parity && opt.Proxy == nil {
		var names []string
		for _, h := range hosts {
			if net.ParseIP(strings.Trim(h, "[]")) == nil {
				names = append(names, h)
			}
		}
		if len(names) > 0 {
			checkParity(ctx, names, opt.Ports, opt.ConnectTimeout, ext, logf)
		}
	}
	if token := opt.Keys.get("github"); token != "" && len(ownDomains) > 0 && ctx.Err() == nil {
		searchGitHub(ctx, ownDomains, token, ext, logf)
	}
	if !ext.empty() {
		if f, err := os.Create(filepath.Join(opt.Output, "discovery.csv")); err == nil {
			w := csv.NewWriter(f)
			w.Write(extraHeader)
			for _, r := range extraRows(ext) {
				w.Write(r)
			}
			w.Flush()
			f.Close()
		}
	}
}
