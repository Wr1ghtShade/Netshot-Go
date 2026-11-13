package main

// Checks inspired by web-check (web-check.xyz), done on the page already loaded in the browser:
//   - mixed content: resources or forms in http:// on an https page
//   - SRI: third-party scripts and style sheets loaded without an integrity attribute
//   - trackers and third parties: analytics, advertising, social pixels, consent banners, fonts…
//   - WAF / protective CDN, read in the headers and cookies (passive), and with -waf-probe one
//     request carrying a harmless test string to see whether a filter blocks it (active)
// The only extra requests are those of -waf-probe.

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// pageResourcesJS lists, from the live DOM, the resources and forms of the page (absolute URLs, with
// their integrity attribute) and the URLs actually loaded (Resource Timing).
const pageResourcesJS = `(() => {
  const out = {el: [], res: []};
  const add = (t, u, i, r) => { if (u && out.el.length < 800) out.el.push({t: t, u: String(u), i: i || '', r: r || ''}); };
  document.querySelectorAll('script[src]').forEach(e => add('script', e.src, e.integrity));
  document.querySelectorAll('link[href]').forEach(e => {
    const r = (e.rel || '').toLowerCase();
    if (/stylesheet|preload|modulepreload|icon/.test(r)) add('link', e.href, e.integrity, r);
  });
  document.querySelectorAll('img[src],iframe[src],audio[src],video[src],source[src],embed[src],track[src]')
    .forEach(e => add(e.tagName.toLowerCase(), e.src));
  document.querySelectorAll('object[data]').forEach(e => add('object', e.data));
  document.querySelectorAll('form[action]').forEach(e => add('form', e.action));
  try { performance.getEntriesByType('resource').slice(0, 800).forEach(p => out.res.push(p.name)); } catch (e) {}
  return JSON.stringify(out);
})()`

type pageElement struct {
	Tag       string `json:"t"`
	URL       string `json:"u"`
	Integrity string `json:"i"`
	Rel       string `json:"r"`
}

type pageResources struct {
	Elements  []pageElement `json:"el"`
	Resources []string      `json:"res"`
}

// PageChecks is what the resources of a page reveal.
type PageChecks struct {
	MixedContent []string // "script http://…"
	NoSRI        []string // third-party scripts / style sheets without integrity
	Trackers     []string // "Google Analytics (mesure d'audience)"
	ThirdParty   []string // distinct third-party host names
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// analyzeResources reads the JSON returned by pageResourcesJS for the page finalURL.
func analyzeResources(finalURL, raw string) PageChecks {
	var pr pageResources
	var out PageChecks
	if json.Unmarshal([]byte(raw), &pr) != nil {
		return out
	}
	https := strings.HasPrefix(strings.ToLower(finalURL), "https://")
	seenMixed, seenSRI := map[string]bool{}, map[string]bool{}
	for _, el := range pr.Elements {
		low := strings.ToLower(el.URL)
		if https && strings.HasPrefix(low, "http://") && !seenMixed[el.URL] && len(out.MixedContent) < 50 {
			seenMixed[el.URL] = true
			kind := el.Tag
			if el.Tag == "form" {
				kind = "formulaire"
			}
			out.MixedContent = append(out.MixedContent, kind+" "+el.URL)
		}
		isCode := el.Tag == "script" || (el.Tag == "link" && (strings.Contains(el.Rel, "stylesheet") || strings.Contains(el.Rel, "modulepreload")))
		if isCode && strings.HasPrefix(low, "http") && el.Integrity == "" && !sameSite(el.URL, finalURL) &&
			!seenSRI[el.URL] && len(out.NoSRI) < 50 {
			seenSRI[el.URL] = true
			out.NoSRI = append(out.NoSRI, el.URL)
		}
	}
	thirds, trackers := map[string]bool{}, map[string]bool{}
	check := func(u string) {
		low := strings.ToLower(u)
		if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
			return
		}
		h := hostOf(u)
		if h == "" || sameSite(u, finalURL) {
			return
		}
		thirds[h] = true
		if t := trackerFor(h); t != "" {
			trackers[t] = true
		}
	}
	for _, el := range pr.Elements {
		if el.Tag != "form" {
			check(el.URL)
		}
	}
	for _, u := range pr.Resources {
		check(u)
	}
	out.ThirdParty = sortedKeys(thirds)
	if len(out.ThirdParty) > 100 {
		out.ThirdParty = out.ThirdParty[:100]
	}
	out.Trackers = sortedKeys(trackers)
	return out
}

// pageIssues sums the checks up in the same list as the header findings.
func pageIssues(pc PageChecks) []string {
	var out []string
	if n := len(pc.MixedContent); n > 0 {
		forms := 0
		for _, m := range pc.MixedContent {
			if strings.HasPrefix(m, "formulaire ") {
				forms++
			}
		}
		s := fmt.Sprintf("contenu mixte : %d ressource(s) en HTTP sur une page HTTPS", n)
		if forms > 0 {
			s += fmt.Sprintf(" (dont %d formulaire(s))", forms)
		}
		out = append(out, s)
	}
	if n := len(pc.NoSRI); n > 0 {
		out = append(out, fmt.Sprintf("SRI absent : %d script(s) / feuille(s) de style tiers sans attribut integrity", n))
	}
	return out
}

// --- Trackers ------------------------------------------------------------------------------------

// trackerDomains maps a domain (and its subdomains) to "name|category".
var trackerDomains = map[string]string{
	"google-analytics.com":         "Google Analytics|mesure d'audience",
	"analytics.google.com":         "Google Analytics|mesure d'audience",
	"googletagmanager.com":         "Google Tag Manager|gestionnaire de balises",
	"doubleclick.net":              "Google Ads (DoubleClick)|publicité",
	"googlesyndication.com":        "Google AdSense|publicité",
	"googleadservices.com":         "Google Ads|publicité",
	"adservice.google.com":         "Google Ads|publicité",
	"fonts.googleapis.com":         "Google Fonts|polices (IP transmise à Google)",
	"fonts.gstatic.com":            "Google Fonts|polices (IP transmise à Google)",
	"recaptcha.net":                "Google reCAPTCHA|anti-robot",
	"youtube.com":                  "YouTube|vidéo intégrée",
	"youtube-nocookie.com":         "YouTube (sans cookie)|vidéo intégrée",
	"ytimg.com":                    "YouTube|vidéo intégrée",
	"connect.facebook.net":         "Meta Pixel|réseau social / publicité",
	"facebook.com":                 "Facebook|réseau social",
	"snap.licdn.com":               "LinkedIn Insight|réseau social / publicité",
	"ads.linkedin.com":             "LinkedIn Ads|publicité",
	"platform.linkedin.com":        "LinkedIn|réseau social",
	"static.ads-twitter.com":       "X (Twitter) Ads|publicité",
	"analytics.twitter.com":        "X (Twitter) Analytics|réseau social / publicité",
	"platform.twitter.com":         "X (Twitter)|réseau social",
	"analytics.tiktok.com":         "TikTok Pixel|réseau social / publicité",
	"sc-static.net":                "Snapchat Pixel|réseau social / publicité",
	"ct.pinterest.com":             "Pinterest Tag|réseau social / publicité",
	"bat.bing.com":                 "Microsoft Advertising (UET)|publicité",
	"clarity.ms":                   "Microsoft Clarity|analyse comportementale",
	"hotjar.com":                   "Hotjar|analyse comportementale",
	"hotjar.io":                    "Hotjar|analyse comportementale",
	"contentsquare.net":            "Contentsquare|analyse comportementale",
	"fullstory.com":                "FullStory|analyse comportementale",
	"mouseflow.com":                "Mouseflow|analyse comportementale",
	"crazyegg.com":                 "Crazy Egg|analyse comportementale",
	"matomo.cloud":                 "Matomo Cloud|mesure d'audience",
	"piwik.pro":                    "Piwik PRO|mesure d'audience",
	"xiti.com":                     "AT Internet / Piano|mesure d'audience",
	"ati-host.net":                 "AT Internet / Piano|mesure d'audience",
	"eulerian.net":                 "Eulerian|mesure d'audience",
	"mixpanel.com":                 "Mixpanel|mesure d'audience",
	"segment.com":                  "Segment|mesure d'audience",
	"segment.io":                   "Segment|mesure d'audience",
	"amplitude.com":                "Amplitude|mesure d'audience",
	"heapanalytics.com":            "Heap|mesure d'audience",
	"plausible.io":                 "Plausible|mesure d'audience",
	"mc.yandex.ru":                 "Yandex Metrica|mesure d'audience",
	"hm.baidu.com":                 "Baidu Tongji|mesure d'audience",
	"scorecardresearch.com":        "Comscore|mesure d'audience",
	"quantserve.com":               "Quantcast|publicité",
	"criteo.com":                   "Criteo|publicité",
	"criteo.net":                   "Criteo|publicité",
	"taboola.com":                  "Taboola|publicité",
	"outbrain.com":                 "Outbrain|publicité",
	"adnxs.com":                    "Xandr (AppNexus)|publicité",
	"omtrdc.net":                   "Adobe Analytics|mesure d'audience",
	"demdex.net":                   "Adobe Audience Manager|publicité",
	"2o7.net":                      "Adobe Analytics|mesure d'audience",
	"hs-scripts.com":               "HubSpot|marketing",
	"hs-analytics.net":             "HubSpot|marketing",
	"hsforms.net":                  "HubSpot|marketing",
	"marketo.net":                  "Marketo|marketing",
	"pardot.com":                   "Salesforce Pardot|marketing",
	"js-agent.newrelic.com":        "New Relic|monitoring",
	"nr-data.net":                  "New Relic|monitoring",
	"browser.sentry-cdn.com":       "Sentry|monitoring",
	"sentry.io":                    "Sentry|monitoring",
	"browser-intake-datadoghq.com": "Datadog RUM|monitoring",
	"browser-intake-datadoghq.eu":  "Datadog RUM|monitoring",
	"cookielaw.org":                "OneTrust|consentement",
	"onetrust.com":                 "OneTrust|consentement",
	"didomi.io":                    "Didomi|consentement",
	"axeptio.eu":                   "Axeptio|consentement",
	"cookiebot.com":                "Cookiebot|consentement",
	"consentmanager.net":           "consentmanager|consentement",
	"trustcommander.net":           "Commanders Act|consentement",
	"tagcommander.com":             "Commanders Act|gestionnaire de balises",
	"widget.intercom.io":           "Intercom|chat",
	"intercomcdn.com":              "Intercom|chat",
	"zdassets.com":                 "Zendesk|chat",
	"client.crisp.chat":            "Crisp|chat",
	"tawk.to":                      "Tawk.to|chat",
}

// trackerFor returns "name (category)" when host is a known tracker or third party.
func trackerFor(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for h := host; h != ""; {
		if v, ok := trackerDomains[h]; ok {
			name, cat, _ := strings.Cut(v, "|")
			return name + " (" + cat + ")"
		}
		_, rest, ok := strings.Cut(h, ".")
		if !ok || !strings.Contains(rest, ".") {
			break
		}
		h = rest
	}
	return ""
}

// --- WAF / protective CDN --------------------------------------------------------------------------

// wafRules use the same patterns as the technologies (header:<name>, cookie, html).
var wafRules = []techRule{
	tr("Cloudflare", nil, false, "header:cf-ray", `.`, "header:server", `^cloudflare`, "cookie", `^(__cf_bm|__cflb|cf_clearance)$`),
	tr("Akamai", nil, false, "header:server", `AkamaiGHost|AkamaiNetStorage`, "header:x-akamai-transformed", `.`, "cookie", `^(ak_bmsc|bm_sz|_abck)$`),
	tr("Imperva / Incapsula", nil, false, "header:x-iinfo", `.`, "header:x-cdn", `Incapsula|Imperva`, "cookie", `^(incap_ses_|visid_incap_|nlbi_)`),
	tr("Sucuri", nil, false, "header:x-sucuri-id", `.`, "header:x-sucuri-cache", `.`, "header:server", `Sucuri`),
	tr("F5 BIG-IP ASM", nil, false, "cookie", `^TS[0-9a-f]{6,}$`, "header:x-wa-info", `.`),
	tr("AWS WAF", nil, false, "cookie", `^aws-waf-token$`, "header:x-amzn-waf-action", `.`),
	tr("AWS CloudFront", nil, false, "header:x-amz-cf-id", `.`, "header:via", `CloudFront`),
	tr("Azure Front Door", nil, false, "header:x-azure-ref", `.`),
	tr("Azure Application Gateway", nil, false, "header:server", `Microsoft-Azure-Application-Gateway`),
	tr("Fortinet FortiWeb", nil, false, "cookie", `^FORTIWAFSID$`, "header:server", `FortiWeb`),
	tr("Barracuda", nil, false, "cookie", `^(barra_counter_session|BNI__BARRACUDA_LB_COOKIE)$`, "header:server", `Barracuda`),
	tr("Citrix NetScaler AppFirewall", nil, false, "cookie", `^(ns_af|citrix_ns_id)`, "header:via", `NS-CACHE`, "header:cneonction", `.`, "header:nncoection", `.`),
	tr("ModSecurity", nil, false, "header:server", `Mod_Security|NOYB`),
	tr("Fastly", nil, false, "header:x-fastly-request-id", `.`, "header:x-served-by", `^cache-`),
	tr("DDoS-Guard", nil, false, "header:server", `ddos-guard`, "cookie", `^__ddg`),
	tr("Wallarm", nil, false, "header:server", `nginx-wallarm`),
	tr("Reblaze", nil, false, "cookie", `^rbzid$`, "header:server", `Reblaze`),
	tr("Radware", nil, false, "header:x-sl-compstate", `.`),
}

// wafBlockRules recognize the block page returned to the -waf-probe request.
var wafBlockRules = []techRule{
	tr("Cloudflare", nil, false, "html", `Attention Required! \| Cloudflare|cf-error-details|Cloudflare Ray ID`),
	tr("Imperva / Incapsula", nil, false, "html", `Incapsula incident ID|_Incapsula_Resource`),
	tr("Akamai", nil, false, "html", `Access Denied.{0,200}Reference #`),
	tr("AWS WAF", nil, false, "html", `Request blocked\..{0,400}(CloudFront|AWS)`),
	tr("F5 BIG-IP ASM", nil, false, "html", `The requested URL was rejected\. Please consult with your administrator`),
	tr("ModSecurity", nil, false, "html", `Mod_Security|This error was generated by Mod_Security|ModSecurity Action`),
	tr("Sucuri", nil, false, "html", `Sucuri WebSite Firewall|sucuri\.net/privacy-policy`),
	tr("Fortinet FortiWeb", nil, false, "html", `FortiWeb|\.fgd_icon|Web Page Blocked`),
	tr("Barracuda", nil, false, "html", `Barracuda Networks|barra_counter_session`),
	tr("Citrix NetScaler AppFirewall", nil, false, "html", `NS Transaction ID|AppFW Session ID`),
	tr("Wordfence", nil, false, "html", `Generated by Wordfence|wordfence\.com`),
	tr("NAXSI", nil, false, "html", `naxsi`),
	tr("Wallarm", nil, false, "html", `nginx-wallarm`),
	tr("DDoS-Guard", nil, false, "html", `DDoS-Guard`),
}

// matchRules returns the names of the rules that match (no version).
func matchRules(rules []techRule, hs []Header, page string) []string {
	found := detectWith(rules, hs, page, "")
	var out []string
	for _, t := range found {
		if !containsStr(out, t.Name) {
			out = append(out, t.Name)
		}
	}
	return out
}

// detectWAF reads the protections visible in the headers and cookies of a page.
func detectWAF(hs []Header) []string {
	return matchRules(wafRules, hs, "")
}

// wafProbeValue is harmless (nothing is executed nor read) but looks like XSS, SQL injection and path
// traversal, which any WAF blocks.
const wafProbeValue = `<script>alert(1)</script>' OR '1'='1 ../../../../etc/passwd`

// probeWAF compares a normal request with one carrying wafProbeValue in the query string.
// It returns a one-line verdict, or "" when the service does not answer.
func (w *webState) probeWAF(ctx context.Context, base, ua string) string {
	get := func(raw string) (int, []Header, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return 0, nil, "", err
		}
		if ua == "" {
			ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
		}
		req.Header.Set("User-Agent", ua)
		client := *w.client
		client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) > 2 {
				return http.ErrUseLastResponse
			}
			return nil
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRead))
		var hs []Header
		for k, vs := range resp.Header {
			for _, v := range vs {
				hs = append(hs, Header{k, v})
			}
		}
		return resp.StatusCode, hs, string(body), nil
	}
	st0, _, body0, err := get(base)
	if err != nil {
		return ""
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	st1, hs1, body1, err := get(base + sep + "netshot_waf_test=" + url.QueryEscape(wafProbeValue))
	if err != nil {
		return fmt.Sprintf("bloqué (connexion coupée : %s)", truncate(firstLine(err), 80))
	}
	names := matchRules(wafBlockRules, nil, body1)
	for _, n := range matchRules(wafBlockRules, nil, body0) { // a signature already on the normal page proves nothing
		names = removeStr(names, n)
	}
	for _, n := range detectWAF(hs1) {
		if !containsStr(names, n) {
			names = append(names, n)
		}
	}
	blockCodes := map[int]bool{400: true, 403: true, 406: true, 418: true, 429: true, 501: true, 503: true, 999: true}
	blocked := (st1 != st0 && blockCodes[st1]) || len(matchRules(wafBlockRules, nil, body1)) > len(matchRules(wafBlockRules, nil, body0))
	who := ""
	if len(names) > 0 {
		who = " : " + strings.Join(names, ", ")
	}
	if blocked {
		return fmt.Sprintf("bloqué (%d au lieu de %d)%s", st1, st0, who)
	}
	return fmt.Sprintf("non bloqué (%d, comme la page normale)", st1)
}

func removeStr(list []string, v string) []string {
	var out []string
	for _, s := range list {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

// --- Report -------------------------------------------------------------------------------------------

// pageChecksSection: mixed content, SRI, trackers and WAF, one row per service.
func pageChecksSection(results []Result) string {
	e := html.EscapeString
	var wafRows, mixRows, trackRows []string
	trackCount := map[string]int{}
	seen := map[string]bool{}
	nWAF, nMixed, nSRI := 0, 0, 0
	for _, r := range results {
		if r.File == "" || seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		if len(r.WAF) > 0 || r.WAFProbe != "" {
			if len(r.WAF) > 0 || strings.HasPrefix(r.WAFProbe, "bloqué") {
				nWAF++
			}
			wafRows = append(wafRows, fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`,
				urlLinks([]string{r.URL}, 1), e(strings.Join(r.WAF, ", ")), e(r.WAFProbe)))
		}
		if len(r.MixedContent) > 0 || len(r.NoSRI) > 0 {
			if len(r.MixedContent) > 0 {
				nMixed++
			}
			if len(r.NoSRI) > 0 {
				nSRI++
			}
			esc := func(list []string) string {
				var parts []string
				for i, x := range list {
					if i == 10 {
						parts = append(parts, fmt.Sprintf("+%d", len(list)-10))
						break
					}
					parts = append(parts, e(x))
				}
				return strings.Join(parts, "<br>")
			}
			mixRows = append(mixRows, fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`,
				urlLinks([]string{r.URL}, 1), esc(r.MixedContent), esc(r.NoSRI)))
		}
		if len(r.Trackers) > 0 || len(r.ThirdParty) > 0 {
			for _, t := range r.Trackers {
				trackCount[t]++
			}
			trackRows = append(trackRows, fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d</td></tr>`,
				urlLinks([]string{r.URL}, 1), e(strings.Join(r.Trackers, ", ")), len(r.ThirdParty)))
		}
	}
	var sb strings.Builder
	if len(wafRows) > 0 {
		fmt.Fprintf(&sb, `<details><summary><b>WAF / CDN de protection</b> - %d service(s) protégé(s)</summary>`+
			`<table><tr><th>URL</th><th>Vu dans les en-têtes / cookies</th><th>Test actif (-waf-probe)</th></tr>%s</table></details>`,
			nWAF, strings.Join(wafRows, ""))
	}
	if len(mixRows) > 0 {
		fmt.Fprintf(&sb, `<details><summary><b>Contenu mixte et SRI</b> - %d page(s) avec contenu mixte, %d avec des scripts tiers sans SRI</summary>`+
			`<table><tr><th>URL</th><th>Contenu mixte (HTTP sur page HTTPS)</th><th>Scripts / styles tiers sans integrity</th></tr>%s</table></details>`,
			nMixed, nSRI, strings.Join(mixRows, ""))
	}
	if len(trackRows) > 0 {
		names := make([]string, 0, len(trackCount))
		for k := range trackCount {
			names = append(names, k)
		}
		sort.SliceStable(names, func(i, j int) bool {
			if trackCount[names[i]] != trackCount[names[j]] {
				return trackCount[names[i]] > trackCount[names[j]]
			}
			return names[i] < names[j]
		})
		var sum []string
		for _, n := range names {
			sum = append(sum, fmt.Sprintf("%s : %d", n, trackCount[n]))
		}
		fmt.Fprintf(&sb, `<details><summary><b>Traqueurs et tiers</b> - %d traqueur(s) connu(s)%s</summary>`+
			`<table><tr><th>URL</th><th>Traqueurs / services tiers connus</th><th>Hôtes tiers</th></tr>%s</table></details>`,
			len(names), map[bool]string{true: " : " + e(truncate(strings.Join(sum, ", "), 300)), false: ""}[len(sum) > 0], strings.Join(trackRows, ""))
	}
	return sb.String()
}
