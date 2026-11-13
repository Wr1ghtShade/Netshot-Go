// netshot - screenshots of web services found on an internal network.
//
// Without arguments: opens the graphical interface (local web page, 127.0.0.1 only).
// With arguments: command line mode.
//
//	netshot 192.168.1.0/24
//	netshot -f targets.txt -p 80,443,8080,8443 -o shots
//	netshot 10.0.0.0/24 -d 2 -u browsers -u bots
//	netshot -list-ua
//	netshot -ct example.com -ct-private          (hostnames from passive sources)
//	netshot -ct example.com -ct-only > names.txt
//	netshot AS3215 -p 443                        (prefixes announced by an AS, via RIPEstat)
//	netshot -f ad_computers.csv                  (CSV export: AD, ADCS, CMDB...)
//	netshot -key domscan=XXXX -save-keys         (store a free API key)
//	netshot -dns example.com [-dns-server 1.1.1.1]   (DNS records, like dig)
//	netshot -whois example.com -whois 8.8.8.8 -whois AS3215   (owner: RDAP + WHOIS)
//	netshot -tls example.com -tls intranet:8443      (certificate and TLS setup, like sslscan)
//	netshot 10.0.0.0/24 -tls-scan                    (scan, then analyze every https service)
//
// Needs Edge or Chrome on the machine (present by default on Windows 10/11).
// Use only on networks you are authorized to scan.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	ensureKeysFile() // empty keys.json template next to the exe, only when no keys file exists at all
	if len(os.Args) == 1 {
		exitOnErr(runGUI("", true))
		return
	}

	fs := flag.NewFlagSet("netshot", flag.ExitOnError)
	var files, uas multiFlag
	fs.Var(&files, "f", "file with one target per line, or a CSV export (AD, ADCS, CMDB) (repeatable)")
	ports := fs.String("p", portsString(defaultPorts), "ports, e.g. 80,443,8000-8010, or presets: web (~100 web ports), services (SSH, FTP, SMTP, RDP, databases...), default; mixable: web,services,8443")
	output := fs.String("o", "screenshots_"+time.Now().Format("20060102_150405"), "output folder")
	concurrency := fs.Int("c", 10, "parallel checks")
	connectTimeout := fs.Float64("connect-timeout", 1.5, "TCP timeout in seconds")
	pageTimeout := fs.Float64("page-timeout", 15, "page load timeout in seconds")
	delay := fs.Float64("d", 0, "minimum seconds between two page loads, e.g. 2 (0 = no limit)")
	fs.Var(&uas, "u", "user agent: name from -list-ua, browsers, bots, all, or a literal string (repeatable)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	listUA := fs.Bool("list-ua", false, "list the built-in user agents and exit")
	width := fs.Int("width", 1920, "viewport width")
	height := fs.Int("height", 1080, "viewport height")
	maxHosts := fs.Float64("max-hosts", maxHostsDefault, "refuse above this many addresses")
	browser := fs.String("browser", "", "path to msedge.exe / chrome.exe (default: auto-detect)")
	var ctDomains, keyFlags multiFlag
	fs.Var(&ctDomains, "ct", "domain to enumerate with passive sources (CT logs, passive DNS, archives); found hostnames are added to the targets (repeatable)")
	ctSourcesFlag := fs.String("ct-sources", "default", "sources: default, all, or a list among "+strings.Join(subSourceNames(), ", "))
	ctKey := fs.String("ct-key", "", "Cert Spotter API key (same as -key certspotter=...)")
	ctAll := fs.Bool("ct-all", false, "keep names even when they do not resolve in DNS")
	ctPrivate := fs.Bool("ct-private", false, "keep only names that resolve to a private IP")
	ctOnly := fs.Bool("ct-only", false, "print the hostnames found and exit, without scanning")
	listSources := fs.Bool("list-sources", false, "list the passive sources and the keys configured, and exit")
	fs.Var(&keyFlags, "key", "API key as source=KEY, e.g. domscan=abc (repeatable)")
	saveKeysFlag := fs.Bool("save-keys", false, "store the -key values in "+keysPath())
	noLabel := fs.Bool("no-label", false, "do not write host:port, URL, status and date at the bottom of the screenshots")
	noEnrich := fs.Bool("no-enrich", false, "do not enrich the IPs found (Shodan InternetDB, LeakIX, CISA KEV, EPSS), look up the CVEs of the versions found (NVD) nor check the reputation of the host names (block lists, URLhaus, VirusTotal, Safe Browsing)")
	noAnalyze := fs.Bool("no-analyze", false, "do not analyse the pages (technologies, sensitive pages, headers, favicon, similar pages, JS, robots, banners, takeover)")
	dirsFlag := fs.Bool("dirs", false, "test the common folders of dirs.txt on every web service and capture the directory listings found ('Index of'); extra requests")
	dirsWordlist := fs.String("dirs-wordlist", "", "folder list for -dirs, one path per line (implies -dirs)")
	filesFlag := fs.Bool("files", false, "test the sensitive files of files.txt (.env, .git/HEAD, backups, phpinfo, actuator...) on every web service; each answer is checked against a signature")
	filesWordlist := fs.String("files-wordlist", "", "file list for -files: path<TAB>severity<TAB>regex per line (implies -files)")
	wafProbe := fs.Bool("waf-probe", false, "send one request with a harmless attack-like string (XSS / SQL / ../) per web service to see whether a WAF blocks it; active test")
	var excludeFlags, excludeFiles multiFlag
	fs.Var(&excludeFlags, "exclude", "out-of-scope targets never scanned: IP, CIDR, host name or *.domain, comma separated (repeatable)")
	fs.Var(&excludeFiles, "exclude-file", "file of out-of-scope targets, one per line (repeatable)")
	proxyFlag := fs.String("proxy", "", "proxy for the pages: http://127.0.0.1:8080 (Burp) or socks5://host:1080, optional user:password@ (http only)")
	dnsDomain := fs.String("dns", "", "show the DNS records of a domain (like dig: ANY, then type by type) and exit")
	dnsServer := fs.String("dns-server", "", "DNS server for -dns, e.g. 1.1.1.1 or 10.0.0.1:53 (default: system resolvers)")
	wordlistFile := fs.String("wordlist", "", "word list for the 'wordlist' source (DNS brute force), one label per line (default: built-in 1,000 words)")
	var whoisQueries multiFlag
	fs.Var(&whoisQueries, "whois", "who owns a domain, an IP or an AS (RDAP + WHOIS port 43), then exit (repeatable)")
	var tlsTargets multiFlag
	fs.Var(&tlsTargets, "tls", "analyze the certificate and TLS setup of host[:port] (default port 443) and exit (repeatable)")
	tlsScan := fs.Bool("tls-scan", false, "after the scan, analyze the certificate and TLS setup of every https service found")
	gui := fs.Bool("gui", false, "open the graphical interface")
	noOpen := fs.Bool("no-open", false, "with -gui: only print the interface URL, do not open a window")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: netshot [options] <IP | CIDR | hostname>...\n       netshot            (no argument: graphical interface)\n\n")
		fs.PrintDefaults()
	}

	// Allow flags and targets in any order: Go's flag package stops at the first positional
	var targets []string
	args := os.Args[1:]
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		targets = append(targets, fs.Arg(0))
		args = fs.Args()[1:]
	}

	if *showVersion {
		fmt.Println("NetShot " + version)
		return
	}
	if *listUA {
		for _, g := range []struct {
			name string
			list []UA
		}{{"browsers", browserUAs}, {"bots", botUAs}} {
			fmt.Printf("[%s]\n", g.name)
			for _, u := range g.list {
				fmt.Printf("  %-16s %s\n", u.Name, u.Value)
			}
		}
		return
	}
	if *wordlistFile != "" {
		lines, err := readTargetFile(*wordlistFile)
		exitOnErr(err)
		customWordlist = lines
	}
	keys := loadKeys()
	if *ctKey != "" {
		keyFlags = append(keyFlags, "certspotter="+*ctKey)
	}
	typed := Keys{}
	for _, kv := range keyFlags {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			exitOnErr(fmt.Errorf("-key expects source=KEY, got %q", kv))
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		keys[name] = value
		if value != "" {
			typed[name] = value
		}
	}
	if *saveKeysFlag {
		exitOnErr(updateKeys(typed)) // only the -key values, merged into the file on disk
		fmt.Fprintln(os.Stderr, "keys saved to", keysPath())
		if len(targets) == 0 && len(files) == 0 && len(ctDomains) == 0 {
			return
		}
	}
	if *listSources {
		fmt.Println("Subdomain sources (-ct-sources):")
		for _, s := range subSources {
			state := "no key needed"
			switch {
			case s.Key != "" && keys.get(s.Name) != "":
				state = "key configured"
			case s.Key == "required":
				state = "KEY REQUIRED (free account)"
			case s.Key == "optional":
				state = "works without key, more with one"
			}
			def := ""
			if s.Default {
				def = " [default]"
			}
			fmt.Printf("  %-15s %-32s %s%s\n", s.Name, state, s.Help, def)
		}
		fmt.Println("\nEnrichment of the IPs found: Shodan host API (with key, else the free InternetDB), LeakIX (key), CISA KEV, FIRST EPSS.")
		fmt.Println("Reputation of the public host names: filtering DNS resolvers (Quad9, Cloudflare, OpenDNS, AdGuard), URLhaus (key abusech), VirusTotal (key), Google Safe Browsing (key safebrowsing).")
		fmt.Println("Targets: AS<number> expands to the prefixes announced by the AS (RIPEstat).")
		fmt.Println("Keys file:", keysPath())
		return
	}
	if *gui {
		exitOnErr(runGUI(*browser, !*noOpen))
		return
	}
	if *dnsDomain != "" {
		fmt.Print(formatDig(dnsLookup(context.Background(), *dnsDomain, *dnsServer)))
		return
	}
	if len(whoisQueries) > 0 {
		for _, q := range whoisQueries {
			fmt.Println(formatWhois(whoisLookup(context.Background(), q)))
		}
		return
	}
	if len(tlsTargets) > 0 {
		for _, r := range analyzeTLSAll(context.Background(), parseTLSTargets(tlsTargets), nil, nil) {
			fmt.Print(formatTLS(r))
		}
		return
	}

	// Ctrl+C stops the CT lookup or the scan; a stopped scan still writes its report
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	logStderr := func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
	items := append([]string{}, targets...)
	for _, f := range files {
		lines, err := readTargetFile(f)
		exitOnErr(err)
		items = append(items, lines...)
	}
	items = expandASNs(ctx, items, logStderr)
	if len(ctDomains) > 0 {
		names := ctLookup(ctx, ctDomains, ctOptions{
			Sources:     resolveSourceNames(strings.Split(*ctSourcesFlag, ","), keys),
			Keys:        keys,
			Resolve:     !*ctAll,
			PrivateOnly: *ctPrivate,
		}, logStderr)
		if *ctOnly {
			for _, n := range names {
				fmt.Println(n)
			}
			return
		}
		items = append(items, names...)
	}
	if len(items) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	if n := countTargets(items); n > *maxHosts {
		exitOnErr(fmt.Errorf("%.0f addresses > -max-hosts %.0f. Narrow the range or raise -max-hosts", n, *maxHosts))
	}
	portList, err := parsePorts(*ports)
	exitOnErr(err)
	hosts := parseTargets(items)
	uaList := resolveUAs(uas)
	fmt.Printf("%d hosts x %d ports x %d user agents\n", len(hosts), len(portList), len(uaList))

	opt := Options{
		Ports:          portList,
		Concurrency:    *concurrency,
		ConnectTimeout: seconds(*connectTimeout),
		PageTimeout:    seconds(*pageTimeout),
		Delay:          seconds(*delay),
		UAs:            uaList,
		Width:          *width,
		Height:         *height,
		Output:         *output,
		Browser:        *browser,
		Enrich:         !*noEnrich,
		Label:          !*noLabel,
		TLS:            *tlsScan,
		Keys:           keys,
		Analyze:        !*noAnalyze,
		WAFProbe:       *wafProbe,
	}
	if *dirsFlag || *dirsWordlist != "" {
		var custom []string
		if *dirsWordlist != "" {
			lines, err := readLines(*dirsWordlist)
			exitOnErr(err)
			custom = lines
		}
		opt.Dirs = dirWords(custom)
		fmt.Fprintf(os.Stderr, "-dirs: %d folders per web service\n", len(opt.Dirs))
	}
	if *filesFlag || *filesWordlist != "" {
		var custom []string
		if *filesWordlist != "" {
			lines, err := readLines(*filesWordlist)
			exitOnErr(err)
			custom = lines
		}
		opt.Files = fileRules(custom)
		fmt.Fprintf(os.Stderr, "-files: %d files per web service\n", len(opt.Files))
	}
	opt.Proxy, err = parseProxy(*proxyFlag)
	exitOnErr(err)
	opt.Exclusions, err = readExclusions(excludeFlags, excludeFiles)
	exitOnErr(err)
	lastPrint := time.Now()
	_, err = Run(ctx, hosts, opt, Callbacks{
		Log: func(s string) { fmt.Println(s) },
		Progress: func(done, total, found int) {
			if time.Since(lastPrint) >= 5*time.Second {
				lastPrint = time.Now()
				fmt.Fprintf(os.Stderr, "    ... %d/%d checked, %d found\n", done, total, found)
			}
		},
	})
	exitOnErr(err)
}

// readLines reads a word list as is (no CSV detection, unlike the target files).
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(strings.TrimPrefix(string(data), "\ufeff"), "\r", ""), "\n"), nil
}

func seconds(f float64) time.Duration { return time.Duration(f * float64(time.Second)) }

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
