package main

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

var defaultPorts = []int{80, 443, 8000, 8080, 8443}

var httpsPorts = map[int]bool{443: true, 8443: true, 9443: true, 4443: true, 10443: true}

const maxHostsDefault = 65536

// cleanItem drops comments ('#') and spaces.
func cleanItem(raw string) string {
	if i := strings.Index(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

func readTargetFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20) // long CSV lines (certificate SAN lists)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if sc.Err() != nil {
		return nil, sc.Err()
	}
	return importTargets(lines), nil
}

// importTargets accepts a plain list (one target per line) or a CSV export
// (Active Directory, ADCS, CMDB...) from which hosts and IPs are extracted.
func importTargets(lines []string) []string {
	if looksLikeCSV(lines) {
		return targetsFromCSV(lines)
	}
	return lines
}

// countTargets returns how many addresses the items expand to (before expansion).
func countTargets(items []string) float64 {
	total := 0.0
	for _, raw := range items {
		item := cleanItem(raw)
		if item == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(item); err == nil {
			ones, bits := n.Mask.Size()
			total += math.Pow(2, float64(bits-ones))
		} else {
			total++
		}
	}
	return total
}

// parseTargets expands IPs, CIDRs and hostnames into unique hosts, order kept.
func parseTargets(items []string) []string {
	var hosts []string
	seen := map[string]bool{}
	add := func(h string) {
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	for _, raw := range items {
		item := cleanItem(raw)
		if item == "" {
			continue
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			if ip := net.ParseIP(item); ip != nil {
				add(ip.String())
			} else {
				add(item) // hostname
			}
			continue
		}
		ones, bits := n.Mask.Size()
		// IPv4 below /31: skip network and broadcast addresses
		skipEnds := bits == 32 && bits-ones >= 2
		ip := append(net.IP{}, n.IP...)
		var list []string
		for ; n.Contains(ip); ip = nextIP(ip) {
			list = append(list, ip.String())
			if isLastIP(ip) {
				break
			}
		}
		if skipEnds && len(list) > 2 {
			list = list[1 : len(list)-1]
		}
		for _, h := range list {
			add(h)
		}
	}
	return hosts
}

func nextIP(ip net.IP) net.IP {
	next := append(net.IP{}, ip...)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func isLastIP(ip net.IP) bool {
	for _, b := range ip {
		if b != 0xff {
			return false
		}
	}
	return true
}

// parsePorts reads "80,443,8000-8010".
func parsePorts(text string) ([]int, error) {
	set := map[int]bool{}
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			// Only 1-65535 is kept below: bound the loop so "1-999999999" stays instant
			for p := max(a, 1); p <= min(b, 65535); p++ {
				set[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			set[p] = true
		}
	}
	var ports []int
	for p := range set {
		if p > 0 && p < 65536 {
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports, nil
}

func portsString(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}
