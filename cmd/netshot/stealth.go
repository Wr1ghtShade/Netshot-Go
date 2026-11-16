package main

// Stealth mode (-stealth): the slowest, quietest scan NetShot can run, to stay under the
// thresholds of an IDS / WAF / SOC during an authorised test of their detection.
//   - one check at a time, a random pause before every TCP connection (-stealth-delay, 3-8 s by
//     default) and at least the longest pause between two page loads;
//   - hosts and ports tested in random order (no sequential sweep of a host);
//   - one ordinary browser User-Agent (Chrome on Windows) instead of the headless browser's own,
//     which says "HeadlessChrome"; no bot User-Agent;
//   - every request that is not a plain visit is dropped: folders, sensitive files, WAF probe, UDP,
//     TLS analysis (dozens of handshakes per service), IPv6 parity, certificate pivot.
// The lookups that never reach the target (enrichment, reputation, cloud footprint, crt.sh, RDAP)
// stay on.

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// StealthDelay is the range of the random pause before each TCP connection.
type StealthDelay struct{ Min, Max time.Duration }

var defaultStealthDelay = StealthDelay{3 * time.Second, 8 * time.Second}

// parseStealthDelay reads "3-8" or "5" (seconds).
func parseStealthDelay(s string) (StealthDelay, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultStealthDelay, nil
	}
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		hi = lo
	}
	a, err1 := strconv.ParseFloat(strings.TrimSpace(lo), 64)
	b, err2 := strconv.ParseFloat(strings.TrimSpace(hi), 64)
	if err1 != nil || err2 != nil || a < 0 || b < a {
		return StealthDelay{}, fmt.Errorf("délai furtif invalide %q (exemple : 3-8)", s)
	}
	return StealthDelay{time.Duration(a * float64(time.Second)), time.Duration(b * float64(time.Second))}, nil
}

func (d StealthDelay) pick() time.Duration {
	if d.Max <= d.Min {
		return d.Min
	}
	return d.Min + time.Duration(rand.Int63n(int64(d.Max-d.Min)))
}

// applyStealth turns the options into their quiet version and says what changed.
func applyStealth(opt *Options, logf func(string, ...any)) {
	if opt.StealthDelay.Max == 0 {
		opt.StealthDelay = defaultStealthDelay
	}
	var off []string
	if opt.Concurrency > 1 {
		opt.Concurrency = 1
	}
	if opt.Delay < opt.StealthDelay.Max {
		opt.Delay = opt.StealthDelay.Max
	}
	if opt.Dirs != nil {
		opt.Dirs, off = nil, append(off, "dossiers")
	}
	if opt.Files != nil {
		opt.Files, off = nil, append(off, "fichiers sensibles")
	}
	if opt.WAFProbe {
		opt.WAFProbe, off = false, append(off, "sonde WAF")
	}
	if opt.UDP {
		opt.UDP, off = false, append(off, "UDP")
	}
	if opt.TLS {
		opt.TLS, off = false, append(off, "analyse TLS")
	}
	if opt.IPv6Parity {
		opt.IPv6Parity, off = false, append(off, "parité IPv6")
	}
	opt.UAs = []UA{{Name: "default", Value: browserUAs[0].Value}}
	msg := fmt.Sprintf("[furtif] 1 vérification à la fois, pause aléatoire de %s à %s avant chaque connexion, ordre aléatoire, User-Agent Chrome Windows",
		fmtSeconds(opt.StealthDelay.Min), fmtSeconds(opt.StealthDelay.Max))
	if len(off) > 0 {
		msg += " ; désactivés : " + strings.Join(off, ", ")
	}
	logf("%s", msg)
}

func fmtSeconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) + " s"
}

// fmtDuration: "45 s", "12 min", "3 h 20 min".
func fmtDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%d h %02d min", int(d.Hours()), int(d.Minutes())%60)
}

// stealthEstimate: rough duration of the TCP checks alone.
func stealthEstimate(checks int, d StealthDelay) time.Duration {
	return time.Duration(checks) * (d.Min + d.Max) / 2
}
