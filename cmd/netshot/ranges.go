package main

import (
	"context"
	"encoding/csv"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var asnPattern = regexp.MustCompile(`^(?i)AS(\d+)$`)

// expandASNs replaces "AS1234" items with the IPv4 prefixes that the AS announces,
// read from RIPEstat (free, no key). Other items are kept unchanged.
func expandASNs(ctx context.Context, items []string, logf func(string, ...any)) []string {
	var out []string
	for _, raw := range items {
		item := cleanItem(raw)
		m := asnPattern.FindStringSubmatch(item)
		if m == nil {
			out = append(out, raw)
			continue
		}
		prefixes, err := ripePrefixes(ctx, m[1])
		if err != nil {
			logf("[asn] AS%s: %v", m[1], err)
			continue
		}
		logf("[asn] AS%s: %d IPv4 prefixes announced", m[1], len(prefixes))
		out = append(out, prefixes...)
	}
	return out
}

func ripePrefixes(ctx context.Context, asn string) ([]string, error) {
	var res struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	u := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + url.QueryEscape(asn)
	if err := getJSON(ctx, "ripestat", u, nil, &res); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range res.Data.Prefixes {
		if _, n, err := net.ParseCIDR(p.Prefix); err == nil && n.IP.To4() != nil {
			out = append(out, p.Prefix)
		}
	}
	return out, nil
}

// Columns that hold host names or addresses in common exports:
// Get-ADComputer (DNSHostName, IPv4Address), certutil / ADCS (Issued Common Name, SAN),
// CMDB and cloud inventories (hostname, fqdn, ip).
// Strong hints are all read together (Common Name and SAN of a certificate export);
// weak hints are used only when no strong one matches.
var hostColumnHints = [][]string{
	{"dnshostname", "hostname", "fqdn", "commonname", "dnsname", "subjectalternativename", "san",
		"ipv4address", "ipaddress"},
	{"ip", "host", "name", "address"},
}

var hostToken = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}\b|\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b`)

// targetsFromCSV extracts hosts and IPs from a CSV export. It reads the columns whose
// header looks like a host field; if none matches, it scans every cell.
func targetsFromCSV(lines []string) []string {
	// Comment or blank lines before the header would hide the header and its delimiter
	for len(lines) > 0 && (strings.TrimSpace(lines[0]) == "" || strings.HasPrefix(strings.TrimSpace(lines[0]), "#")) {
		lines = lines[1:]
	}
	if len(lines) == 0 {
		return nil
	}
	r := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	if strings.Count(lines[0], ";") > strings.Count(lines[0], ",") {
		r.Comma = ';' // Excel export with French settings
	}
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil
	}
	norm := func(s string) string {
		return strings.Map(func(c rune) rune {
			if c == ' ' || c == '_' || c == '-' || c == '"' || c == 0xFEFF { // 0xFEFF: byte order mark
				return -1
			}
			return c
		}, strings.ToLower(s))
	}
	var cols []int
	for _, tier := range hostColumnHints {
		for i, h := range rows[0] {
			for _, hint := range tier {
				if strings.Contains(norm(h), hint) {
					cols = append(cols, i)
					break
				}
			}
		}
		if len(cols) > 0 {
			break // DNSHostName wins over Name
		}
	}
	// With host columns, the first row is their header. Without, there may be no header at all
	// ("10.0.0.1,10.0.0.2"): every row is scanned, a real header holds no host token anyway.
	data := rows
	if len(cols) > 0 {
		data = rows[1:]
	}
	var out []string
	for _, row := range data {
		for i, cell := range row {
			if len(cols) > 0 && !containsInt(cols, i) {
				continue
			}
			// "DNS Name=a.b.c, DNS Name=d.e" (certutil SAN) and plain values alike
			for _, tok := range hostToken.FindAllString(cell, -1) {
				out = append(out, strings.ToLower(tok))
			}
		}
	}
	return out
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// looksLikeCSV reports whether a target file is a CSV export rather than a plain list.
func looksLikeCSV(lines []string) bool {
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		// A comma in a trailing comment ("10.0.0.1  # web, prod") does not make a CSV
		l = cleanItem(l)
		return strings.Count(l, ",") >= 1 || strings.Count(l, ";") >= 1
	}
	return false
}
