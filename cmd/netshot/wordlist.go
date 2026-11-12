package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"
)

// DNS brute force: try the most common subdomain labels against the domain.
// This is an active test (one DNS query per word, through the system resolver), to use on
// domains you are allowed to test.

//go:embed subdomains.txt
var builtinWordlist string

// customWordlist replaces the built-in list when -wordlist is given.
var customWordlist []string

func wordlistWords() []string {
	src := strings.Split(builtinWordlist, "\n")
	if len(customWordlist) > 0 {
		src = customWordlist
	}
	var out []string
	seen := map[string]bool{}
	for _, w := range src {
		w = strings.ToLower(strings.Trim(strings.TrimSpace(w), "."))
		if w == "" || strings.HasPrefix(w, "#") || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	return out
}

func lookupIPs(ctx context.Context, name string) []string {
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lctx, name)
	if err != nil {
		return nil
	}
	ips := make([]string, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP.String()
	}
	return ips
}

// wildcardIPs resolves two random names: if they answer, the zone has a wildcard and
// every name pointing only to those addresses is a false positive.
func wildcardIPs(ctx context.Context, domain string) map[string]bool {
	set := map[string]bool{}
	for i := 0; i < 2; i++ {
		b := make([]byte, 8)
		rand.Read(b)
		for _, ip := range lookupIPs(ctx, "nx-"+hex.EncodeToString(b)+"."+domain) {
			set[ip] = true
		}
	}
	return set
}

// fetchWordlist is the "wordlist" source: every label of the list is resolved, 64 at a time.
func fetchWordlist(ctx context.Context, domain, _ string) ([]string, error) {
	wild := wildcardIPs(ctx, domain)
	words := wordlistWords()
	found := make([]string, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, w := range words {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			ips := lookupIPs(ctx, name)
			if len(ips) == 0 {
				return
			}
			onlyWildcard := len(wild) > 0
			for _, ip := range ips {
				if !wild[ip] {
					onlyWildcard = false
				}
			}
			if !onlyWildcard {
				mu.Lock()
				found = append(found, name)
				mu.Unlock()
			}
		}(w + "." + domain)
	}
	wg.Wait()
	return found, ctx.Err()
}
