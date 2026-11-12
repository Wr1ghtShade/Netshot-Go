package main

import (
	"fmt"
	"strings"
)

// UA is a named User-Agent. An empty Value means "keep the browser's own UA".
// Only the User-Agent header changes: pages are still rendered by Edge/Chrome.
type UA struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Bot   bool   `json:"bot"`
}

var browserUAs = []UA{
	{"chrome-windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36", false},
	{"firefox-windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0", false},
	{"edge-windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0", false},
	{"safari-macos", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15", false},
	{"chrome-android", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36", false},
	{"safari-iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1", false},
}

var botUAs = []UA{
	{"curl", "curl/8.10.1", true},
	{"wget", "Wget/1.24.5", true},
	{"python-requests", "python-requests/2.32.3", true},
	{"python-urllib", "Python-urllib/3.12", true},
	{"go-http", "Go-http-client/1.1", true},
	{"powershell", "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.26100; en-US) PowerShell/7.4.6", true},
	{"googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
	{"bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", true},
	{"nmap", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", true},
}

func allUAs() []UA {
	return append(append([]UA{}, browserUAs...), botUAs...)
}

// resolveUAs turns -u values into a UA list. Accepts names, "browsers", "bots", "all",
// "default", or any other text as a literal User-Agent. Empty input = browser's own UA.
func resolveUAs(values []string) []UA {
	if len(values) == 0 {
		return []UA{{Name: "default"}}
	}
	byName := map[string]UA{}
	for _, u := range allUAs() {
		byName[u.Name] = u
	}
	var out []UA
	custom := 0
	for _, v := range values {
		v = strings.TrimSpace(v)
		switch {
		case v == "":
		case v == "all":
			out = append(out, allUAs()...)
		case v == "browsers":
			out = append(out, browserUAs...)
		case v == "bots":
			out = append(out, botUAs...)
		case v == "default":
			out = append(out, UA{Name: "default"})
		default:
			if u, ok := byName[v]; ok {
				out = append(out, u)
			} else {
				custom++
				out = append(out, UA{Name: fmt.Sprintf("custom%d", custom), Value: v})
			}
		}
	}
	seen := map[string]bool{}
	var uniq []UA
	for _, u := range out {
		if !seen[u.Name] {
			seen[u.Name] = true
			uniq = append(uniq, u)
		}
	}
	if len(uniq) == 0 {
		return []UA{{Name: "default"}}
	}
	return uniq
}
