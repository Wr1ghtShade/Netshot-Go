package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TLS / certificate analysis of an endpoint, in the spirit of sslscan:
//   - protocol versions and cipher suites are probed with hand-built ClientHello messages,
//     one suite at a time, so suites that Go itself cannot use (DHE, CAMELLIA, RC4, EXPORT,
//     NULL...) are still detected, and SSLv3 too;
//   - the certificate, chain, ALPN, OCSP stapling, SCTs, HSTS and the post-quantum key
//     exchange (X25519MLKEM768) are read with real crypto/tls handshakes.

type CipherInfo struct {
	Name     string `json:"name"`
	Strength string `json:"strength"` // insecure, weak, strong
}

type CertInfo struct {
	Subject     string   `json:"subject"`
	SANs        []string `json:"sans"`
	Issuer      string   `json:"issuer"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DaysLeft    int      `json:"days_left"`
	Key         string   `json:"key"`
	SigAlg      string   `json:"sig_alg"`
	Serial      string   `json:"serial"`
	SHA256      string   `json:"sha256"`
	SelfSigned  bool     `json:"self_signed"`
	Wildcard    bool     `json:"wildcard"`
	Trusted     bool     `json:"trusted"`
	TrustError  string   `json:"trust_error"`
	NameMatch   bool     `json:"name_match"`
	Chain       []string `json:"chain"`
	OCSPStapled bool     `json:"ocsp_stapled"`
	MustStaple  bool     `json:"must_staple"`
	SCT         bool     `json:"sct"`
	SCTEmbedded bool     `json:"sct_embedded"`
	CTPrecert   bool     `json:"-"`
	OCSPServers []string `json:"ocsp_servers"`
	CRLs        []string `json:"crls"`
}

type TLSResult struct {
	Target     string                  `json:"target"` // host:port as given
	Host       string                  `json:"host"`
	Port       int                     `json:"port"`
	IP         string                  `json:"ip"`
	SNI        string                  `json:"sni"`
	Error      string                  `json:"error"`
	Protocols  map[string]bool         `json:"protocols"`
	Ciphers    map[string][]CipherInfo `json:"ciphers"` // per protocol, server preference order
	Cert       *CertInfo               `json:"cert"`
	Negotiated string                  `json:"negotiated"` // default handshake: version + suite
	KeyGroup   string                  `json:"key_group"`  // key exchange group of the default handshake
	PQ         bool                    `json:"pq"`         // X25519MLKEM768 accepted
	ALPN       string                  `json:"alpn"`
	HSTS       string                  `json:"hsts"`
	Grade      string                  `json:"grade"`
	Findings   []string                `json:"findings"`
}

var protoOrder = []string{"SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}

var protoVersions = map[string]uint16{"SSLv3": 0x0300, "TLS1.0": 0x0301, "TLS1.1": 0x0302, "TLS1.2": 0x0303, "TLS1.3": 0x0304}

// cipherSuites lists the TLS 1.0-1.2 suites probed (IANA codes).
var cipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
	{0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"}, {0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
	{0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"}, {0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
	{0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"}, {0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
	{0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"}, {0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
	{0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"}, {0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"},
	{0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"}, {0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"},
	{0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
	{0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}, {0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
	{0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"}, {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
	{0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"}, {0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
	{0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"}, {0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
	{0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"}, {0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"},
	{0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"}, {0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
	{0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}, {0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM"},
	{0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM"}, {0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"},
	{0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"}, {0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},
	{0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"}, {0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"},
	{0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"}, {0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
	{0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"}, {0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"}, {0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"},
	{0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"}, {0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"},
	{0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"},
	{0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"}, {0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
	{0xC09C, "TLS_RSA_WITH_AES_128_CCM"}, {0xC09D, "TLS_RSA_WITH_AES_256_CCM"},
	{0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"}, {0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"},
	{0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"}, {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
	{0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"}, {0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"},
	{0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"}, {0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	{0x0005, "TLS_RSA_WITH_RC4_128_SHA"}, {0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
	{0x0009, "TLS_RSA_WITH_DES_CBC_SHA"}, {0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
	{0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"}, {0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x003B, "TLS_RSA_WITH_NULL_SHA256"}, {0x0002, "TLS_RSA_WITH_NULL_SHA"}, {0x0001, "TLS_RSA_WITH_NULL_MD5"},
	{0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"}, {0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"},
	{0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"}, {0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"},
	{0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"}, {0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"},
	{0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"}, {0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"},
	{0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"}, {0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"},
}

var tls13Suites = []struct {
	ID   uint16
	Name string
}{
	{0x1301, "TLS_AES_128_GCM_SHA256"}, {0x1302, "TLS_AES_256_GCM_SHA384"},
	{0x1303, "TLS_CHACHA20_POLY1305_SHA256"}, {0x1304, "TLS_AES_128_CCM_SHA256"}, {0x1305, "TLS_AES_128_CCM_8_SHA256"},
}

func cipherName(id uint16) string {
	for _, c := range cipherSuites {
		if c.ID == id {
			return c.Name
		}
	}
	for _, c := range tls13Suites {
		if c.ID == id {
			return c.Name
		}
	}
	return fmt.Sprintf("0x%04X", id)
}

// cipherStrength: insecure (broken or no encryption / authentication), weak (no forward
// secrecy, CBC, 3DES, legacy algorithms) or strong (AEAD with forward secrecy, TLS 1.3).
func cipherStrength(name string) string {
	switch {
	case strings.Contains(name, "NULL"), strings.Contains(name, "EXPORT"), strings.Contains(name, "anon"),
		strings.Contains(name, "RC4"), strings.Contains(name, "_DES_CBC"), strings.Contains(name, "DES40"),
		strings.HasSuffix(name, "MD5"):
		return "insecure"
	case !strings.Contains(name, "_WITH_") && strings.HasPrefix(name, "TLS_"): // TLS 1.3 suites
		return "strong"
	case strings.Contains(name, "3DES"), strings.HasPrefix(name, "TLS_RSA_"), strings.HasPrefix(name, "TLS_ECDH_"),
		strings.Contains(name, "_CBC_"), strings.Contains(name, "SEED"), strings.Contains(name, "DSS"):
		return "weak"
	}
	return "strong"
}

// --- Raw ClientHello probes ---------------------------------------------------------------

func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

func ext(typ int, data []byte) []byte {
	return append(append(u16(typ), u16(len(data))...), data...)
}

// clientHello builds a ClientHello record offering the given suites for one protocol version.
func clientHello(version uint16, suites []uint16, sni string) []byte {
	legacy := version
	if version == 0x0304 {
		legacy = 0x0303
	}
	var body []byte
	body = append(body, u16(int(legacy))...)
	rnd := make([]byte, 32)
	rand.Read(rnd)
	body = append(body, rnd...)
	body = append(body, 0) // no session id
	var cs []byte
	for _, s := range suites {
		cs = append(cs, u16(int(s))...)
	}
	body = append(append(body, u16(len(cs))...), cs...)
	body = append(body, 1, 0) // compression: null only
	if version != 0x0300 {
		var exts []byte
		if sni != "" {
			name := append([]byte{0}, append(u16(len(sni)), sni...)...)
			exts = append(exts, ext(0, append(u16(len(name)), name...))...)
		}
		groups := []int{29, 23, 24, 25, 256, 257}
		var g []byte
		for _, x := range groups {
			g = append(g, u16(x)...)
		}
		exts = append(exts, ext(10, append(u16(len(g)), g...))...) // supported_groups
		exts = append(exts, ext(11, []byte{1, 0})...)              // ec_point_formats: uncompressed
		sigs := []int{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201, 0x0807}
		var sg []byte
		for _, x := range sigs {
			sg = append(sg, u16(x)...)
		}
		exts = append(exts, ext(13, append(u16(len(sg)), sg...))...) // signature_algorithms
		exts = append(exts, ext(0xff01, []byte{0})...)               // renegotiation_info
		if version == 0x0304 {
			exts = append(exts, ext(43, []byte{2, 0x03, 0x04})...) // supported_versions: TLS 1.3
			exts = append(exts, ext(45, []byte{1, 1})...)          // psk_key_exchange_modes
			key := make([]byte, 32)
			rand.Read(key)
			share := append(u16(29), append(u16(32), key...)...) // x25519
			exts = append(exts, ext(51, append(u16(len(share)), share...))...)
		}
		body = append(append(body, u16(len(exts))...), exts...)
	}
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	recVersion := uint16(0x0301)
	if version == 0x0300 {
		recVersion = 0x0300
	}
	return append(append([]byte{22}, append(u16(int(recVersion)), u16(len(hs))...)...), hs...)
}

type serverHello struct {
	version uint16
	suite   uint16
	certs   []*x509.Certificate // TLS <= 1.2 only (plaintext Certificate message)
}

// probe sends a ClientHello and reads the server's answer. ok=false means refused.
func probe(ctx context.Context, addr, sni string, version uint16, suites []uint16, wantCerts bool) (serverHello, bool, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return serverHello{}, false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := conn.Write(clientHello(version, suites, sni)); err != nil {
		return serverHello{}, false, err
	}
	r := bufio.NewReader(conn)
	var hsBuf []byte
	var sh serverHello
	gotHello := false
	for i := 0; i < 64; i++ {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return sh, gotHello, nil // closed: refusal (or end of what we need)
		}
		n := int(binary.BigEndian.Uint16(hdr[3:]))
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return sh, gotHello, nil
		}
		if hdr[0] == 21 { // alert
			return sh, gotHello, nil
		}
		if hdr[0] != 22 {
			return sh, gotHello, nil
		}
		hsBuf = append(hsBuf, payload...)
		for len(hsBuf) >= 4 {
			mlen := int(hsBuf[1])<<16 | int(hsBuf[2])<<8 | int(hsBuf[3])
			if len(hsBuf) < 4+mlen {
				break
			}
			msg := hsBuf[4 : 4+mlen]
			typ := hsBuf[0]
			hsBuf = hsBuf[4+mlen:]
			switch typ {
			case 2: // ServerHello
				if len(msg) < 38 {
					return sh, false, errors.New("short ServerHello")
				}
				sh.version = binary.BigEndian.Uint16(msg)
				sidLen := int(msg[34])
				if len(msg) < 35+sidLen+3 {
					return sh, false, errors.New("short ServerHello")
				}
				sh.suite = binary.BigEndian.Uint16(msg[35+sidLen:])
				// TLS 1.3: the real version is in supported_versions
				rest := msg[35+sidLen+3:]
				if len(rest) >= 2 {
					exts := rest[2:]
					for len(exts) >= 4 {
						et := binary.BigEndian.Uint16(exts)
						el := int(binary.BigEndian.Uint16(exts[2:]))
						if 4+el > len(exts) {
							break
						}
						if et == 43 && el == 2 {
							sh.version = binary.BigEndian.Uint16(exts[4:])
						}
						exts = exts[4+el:]
					}
				}
				gotHello = true
				if !wantCerts || sh.version >= 0x0304 {
					return sh, true, nil
				}
			case 11: // Certificate (TLS <= 1.2)
				if len(msg) >= 3 {
					list := msg[3:]
					for len(list) >= 3 {
						cl := int(list[0])<<16 | int(list[1])<<8 | int(list[2])
						if 3+cl > len(list) {
							break
						}
						if c, err := x509.ParseCertificate(list[3 : 3+cl]); err == nil {
							sh.certs = append(sh.certs, c)
						}
						list = list[3+cl:]
					}
				}
				return sh, gotHello, nil
			case 14: // ServerHelloDone
				return sh, gotHello, nil
			}
		}
	}
	return sh, gotHello, nil
}

// enumerate finds the suites accepted for one version: offer the remaining list,
// the server picks one, remove it, repeat. The order found is the server preference.
func enumerate(ctx context.Context, addr, sni string, version uint16) ([]CipherInfo, *serverHello) {
	var remaining []uint16
	if version == 0x0304 {
		for _, c := range tls13Suites {
			remaining = append(remaining, c.ID)
		}
	} else {
		for _, c := range cipherSuites {
			remaining = append(remaining, c.ID)
		}
	}
	var out []CipherInfo
	var first *serverHello
	for len(remaining) > 0 && ctx.Err() == nil {
		sh, ok, _ := probe(ctx, addr, sni, version, remaining, first == nil)
		if !ok || sh.version != version {
			break
		}
		if first == nil {
			c := sh
			first = &c
		}
		idx := -1
		for i, s := range remaining {
			if s == sh.suite {
				idx = i
			}
		}
		if idx < 0 { // server picked a suite we did not offer: stop
			break
		}
		name := cipherName(sh.suite)
		out = append(out, CipherInfo{Name: name, Strength: cipherStrength(name)})
		remaining = append(remaining[:idx], remaining[idx+1:]...)
	}
	return out, first
}

// --- Certificate and handshake details ------------------------------------------------------

var (
	oidSCTList    = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidMustStaple = []int{1, 3, 6, 1, 5, 5, 7, 1, 24}
)

func oidEqual(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func keyDescription(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}

func describeCert(chain []*x509.Certificate, sni string, state *tls.ConnectionState) *CertInfo {
	if len(chain) == 0 {
		return nil
	}
	leaf := chain[0]
	sum := sha256.Sum256(leaf.Raw)
	ci := &CertInfo{
		Subject:     leaf.Subject.String(),
		SANs:        append(append([]string{}, leaf.DNSNames...), ipStrings(leaf.IPAddresses)...),
		Issuer:      leaf.Issuer.String(),
		NotBefore:   leaf.NotBefore.Format("2006-01-02"),
		NotAfter:    leaf.NotAfter.Format("2006-01-02"),
		DaysLeft:    int(time.Until(leaf.NotAfter).Hours() / 24),
		Key:         keyDescription(leaf),
		SigAlg:      leaf.SignatureAlgorithm.String(),
		Serial:      strings.ToUpper(leaf.SerialNumber.Text(16)),
		SHA256:      strings.ToUpper(hex.EncodeToString(sum[:])),
		OCSPServers: leaf.OCSPServer,
		CRLs:        leaf.CRLDistributionPoints,
	}
	for _, n := range leaf.DNSNames {
		if strings.HasPrefix(n, "*.") {
			ci.Wildcard = true
		}
	}
	for _, e := range leaf.Extensions {
		if oidEqual(e.Id, oidSCTList) {
			ci.SCTEmbedded = true
		}
		if oidEqual(e.Id, oidMustStaple) {
			ci.MustStaple = true
		}
	}
	// CheckSignature, not CheckSignatureFrom: a self-signed leaf is usually not marked as a CA
	ci.SelfSigned = bytes.Equal(leaf.RawIssuer, leaf.RawSubject) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	for _, c := range chain {
		ci.Chain = append(ci.Chain, c.Subject.CommonName+" ← "+c.Issuer.CommonName)
	}
	if state != nil {
		ci.OCSPStapled = len(state.OCSPResponse) > 0
		ci.SCT = ci.SCTEmbedded || len(state.SignedCertificateTimestamps) > 0
	} else {
		ci.SCT = ci.SCTEmbedded
	}
	// Trust: system store (Windows store on Windows, so internal CAs pushed by GPO are trusted)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Intermediates: inter}
	if _, err := leaf.Verify(opts); err != nil {
		ci.TrustError = err.Error()
	} else {
		ci.Trusted = true
	}
	ci.NameMatch = sni == "" || leaf.VerifyHostname(sni) == nil
	return ci
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func allGoSuites() []uint16 {
	var ids []uint16
	for _, c := range tls.CipherSuites() {
		ids = append(ids, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		ids = append(ids, c.ID)
	}
	return ids
}

// handshake runs a real crypto/tls handshake. Certificates are not verified here (done in
// describeCert) so that self-signed or expired ones can still be inspected.
func handshake(ctx context.Context, addr, sni string, cfg *tls.Config) (*tls.Conn, error) {
	cfg.InsecureSkipVerify = true
	cfg.ServerName = sni
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: cfg}
	hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	c, err := d.DialContext(hctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

// readHSTS sends a HEAD request over TLS and returns the Strict-Transport-Security header.
func readHSTS(ctx context.Context, addr, sni, host string) string {
	conn, err := handshake(ctx, addr, sni, &tls.Config{MinVersion: tls.VersionTLS10, NextProtos: []string{"http/1.1"},
		CipherSuites: allGoSuites()})
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	fmt.Fprintf(conn, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: netshot\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	return resp.Header.Get("Strict-Transport-Security")
}

// --- Main analysis ------------------------------------------------------------------------------

// analyzeTLS runs every check on one "host:port" target.
func analyzeTLS(ctx context.Context, target string) TLSResult {
	res := TLSResult{Target: target, Protocols: map[string]bool{}, Ciphers: map[string][]CipherInfo{}}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host, portStr = target, "443"
	}
	res.Host = strings.Trim(host, "[]")
	res.Port, _ = strconv.Atoi(portStr)
	addr := net.JoinHostPort(res.Host, strconv.Itoa(res.Port))
	if net.ParseIP(res.Host) == nil {
		res.SNI = res.Host
	}
	if ips, err := net.DefaultResolver.LookupIPAddr(ctx, res.Host); err == nil && len(ips) > 0 {
		res.IP = ips[0].IP.String()
	}

	// 1. Versions and suites (raw probes)
	var legacyCerts []*x509.Certificate
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, p := range protoOrder {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			ciphers, first := enumerate(ctx, addr, res.SNI, protoVersions[p])
			mu.Lock()
			defer mu.Unlock()
			res.Protocols[p] = first != nil
			if len(ciphers) > 0 {
				res.Ciphers[p] = ciphers
			}
			if first != nil && len(first.certs) > 0 && (legacyCerts == nil || p == "TLS1.2") {
				legacyCerts = first.certs
			}
		}(p)
	}
	wg.Wait()
	anyProto := false
	for _, ok := range res.Protocols {
		anyProto = anyProto || ok
	}

	// 2. Default handshake: certificate, negotiated parameters, ALPN, OCSP, SCT
	conn, err := handshake(ctx, addr, res.SNI, &tls.Config{MinVersion: tls.VersionTLS10,
		NextProtos: []string{"h2", "http/1.1"}, CipherSuites: allGoSuites()})
	if err == nil {
		st := conn.ConnectionState()
		conn.Close()
		res.Negotiated = tls.VersionName(st.Version) + " " + tls.CipherSuiteName(st.CipherSuite)
		res.KeyGroup = curveName(st)
		res.ALPN = st.NegotiatedProtocol
		res.Cert = describeCert(st.PeerCertificates, res.SNI, &st)
	} else if len(legacyCerts) > 0 {
		// Go cannot complete the handshake (legacy suites only): use the certificate read raw
		res.Cert = describeCert(legacyCerts, res.SNI, nil)
		res.Negotiated = "(handshake impossible avec Go : " + firstLine(err) + ")"
	} else if !anyProto {
		res.Error = "pas de TLS sur ce port (" + firstLine(err) + ")"
		res.Grade = "-"
		return res
	}

	// 3. Post-quantum hybrid key exchange
	if pq, err := handshake(ctx, addr, res.SNI, &tls.Config{MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}); err == nil {
		res.PQ = true
		pq.Close()
	}

	// 4. HSTS (only meaningful for HTTPS)
	hostHeader := res.Host
	if res.Port != 443 {
		hostHeader = net.JoinHostPort(res.Host, strconv.Itoa(res.Port))
	}
	res.HSTS = readHSTS(ctx, addr, res.SNI, hostHeader)

	res.Grade, res.Findings = gradeTLS(&res)
	return res
}

func curveName(st tls.ConnectionState) string {
	switch st.CurveID {
	case 0:
		return ""
	case tls.X25519MLKEM768:
		return "X25519MLKEM768 (hybride PQC)"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	}
	return st.CurveID.String()
}

// gradeTLS gives a letter like the usual TLS scanners and lists the findings.
//
//	F: SSLv3, insecure suite, expired or broken key    T: certificate not trusted
//	C: TLS 1.0 / 1.1 enabled                           B: weak suites (no forward secrecy, 3DES, CBC only...)
//	A: correct                                         A+: A + TLS 1.3 + HSTS
func gradeTLS(r *TLSResult) (string, []string) {
	var f []string
	grade := "A"
	worse := func(g string) {
		rank := map[string]int{"A+": 0, "A": 1, "B": 2, "C": 3, "T": 4, "F": 5}
		if rank[g] > rank[grade] {
			grade = g
		}
	}
	if r.Protocols["SSLv3"] {
		f = append(f, "⚠ SSLv3 accepté (POODLE)")
		worse("F")
	}
	if r.Protocols["TLS1.0"] || r.Protocols["TLS1.1"] {
		var v []string
		for _, p := range []string{"TLS1.0", "TLS1.1"} {
			if r.Protocols[p] {
				v = append(v, p)
			}
		}
		f = append(f, "⚠ "+strings.Join(v, " et ")+" encore accepté(s) (obsolètes depuis 2021)")
		worse("C")
	}
	if !r.Protocols["TLS1.2"] && !r.Protocols["TLS1.3"] {
		f = append(f, "⚠ Ni TLS 1.2 ni TLS 1.3")
		worse("F")
	}
	if r.Protocols["TLS1.3"] {
		f = append(f, "✓ TLS 1.3 disponible")
	} else {
		f = append(f, "Pas de TLS 1.3")
	}
	if r.PQ {
		f = append(f, "✓ PQC : échange de clés post-quantique (X25519MLKEM768)")
	} else {
		f = append(f, "Pas de PQC : échange de clés classique uniquement (pas de X25519MLKEM768)")
	}
	insecure, weak, noPFS := map[string]bool{}, map[string]bool{}, false
	for _, list := range r.Ciphers {
		for _, c := range list {
			switch c.Strength {
			case "insecure":
				insecure[c.Name] = true
			case "weak":
				weak[c.Name] = true
			}
			if strings.HasPrefix(c.Name, "TLS_RSA_") {
				noPFS = true
			}
		}
	}
	if len(insecure) > 0 {
		f = append(f, fmt.Sprintf("⚠ %d suite(s) non sûre(s) : RC4, DES, EXPORT, NULL ou anonyme", len(insecure)))
		worse("F")
	}
	if len(weak) > 0 {
		f = append(f, fmt.Sprintf("%d suite(s) faible(s) (CBC, 3DES ou sans confidentialité persistante)", len(weak)))
		worse("B")
	}
	if noPFS {
		f = append(f, "⚠ Échange de clés RSA accepté : pas de confidentialité persistante")
	}
	if c := r.Cert; c != nil {
		switch {
		case c.DaysLeft < 0:
			f = append(f, fmt.Sprintf("⚠ Certificat EXPIRÉ depuis %d jours (%s)", -c.DaysLeft, c.NotAfter))
			worse("F")
		case c.DaysLeft < 15:
			f = append(f, fmt.Sprintf("⚠ Expire dans %d jours (%s)", c.DaysLeft, c.NotAfter))
		case c.DaysLeft < 30:
			f = append(f, fmt.Sprintf("Expire dans %d jours (%s)", c.DaysLeft, c.NotAfter))
		}
		if !c.Trusted {
			msg := "⚠ Certificat non reconnu par le magasin de confiance"
			if c.SelfSigned {
				msg = "⚠ Certificat auto-signé"
			}
			f = append(f, msg)
			worse("T")
		}
		if !c.NameMatch {
			f = append(f, "⚠ Le nom "+r.SNI+" n'est pas dans le certificat")
			worse("T")
		}
		if strings.HasPrefix(c.Key, "RSA ") {
			if bits, _ := strconv.Atoi(strings.Fields(c.Key)[1]); bits < 2048 {
				f = append(f, "⚠ Clé RSA trop courte ("+c.Key+")")
				worse("F")
			}
		}
		if strings.Contains(c.SigAlg, "SHA1") || strings.Contains(c.SigAlg, "MD5") {
			f = append(f, "⚠ Signature "+c.SigAlg+" obsolète")
			worse("T")
		}
		if !c.SCT && c.Trusted && !c.SelfSigned {
			f = append(f, "Pas de preuve Certificate Transparency (SCT)")
		}
		if c.MustStaple && !c.OCSPStapled {
			f = append(f, "⚠ OCSP Must-Staple sans réponse OCSP agrafée")
		}
	}
	if r.HSTS == "" {
		f = append(f, "Pas d'en-tête HSTS")
	} else {
		f = append(f, "✓ HSTS : "+r.HSTS)
		if grade == "A" && r.Protocols["TLS1.3"] {
			grade = "A+"
		}
	}
	return grade, f
}

// analyzeTLSAll analyzes several targets in parallel, reporting each result as it ends.
func analyzeTLSAll(ctx context.Context, targets []string, logf func(string, ...any), each func(TLSResult)) []TLSResult {
	results := make([]TLSResult, len(targets))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t string) {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			r := analyzeTLS(ctx, t)
			results[i] = r
			if logf != nil {
				if r.Error != "" {
					logf("[tls] %s : %s", t, r.Error)
				} else {
					days := ""
					if r.Cert != nil {
						days = fmt.Sprintf(", expire dans %d j", r.Cert.DaysLeft)
					}
					logf("[tls] %s : note %s%s (%.0f s)", t, r.Grade, days, time.Since(start).Seconds())
				}
			}
			if each != nil {
				each(r)
			}
		}(i, t)
	}
	wg.Wait()
	return results
}

// tlsTargetsFromResults lists the https endpoints found by a scan, once each.
func tlsTargetsFromResults(results []Result) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		if r.File == "" || !strings.HasPrefix(r.URL, "https://") {
			continue
		}
		t := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// parseTLSTargets reads "host", "host:port" or "https://host:port/..." lines (default port 443).
func parseTLSTargets(lines []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range lines {
		item := cleanItem(raw)
		if item == "" {
			continue
		}
		if strings.Contains(item, "://") {
			item = urlHost(item) + portFromURL(item)
		}
		host, port, err := net.SplitHostPort(item)
		if err != nil {
			host, port = strings.Trim(item, "[]"), "443"
		}
		t := net.JoinHostPort(host, port)
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func portFromURL(raw string) string {
	rest := raw[strings.Index(raw, "://")+3:]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if _, p, err := net.SplitHostPort(rest); err == nil {
		return ":" + p
	}
	return ":443"
}
