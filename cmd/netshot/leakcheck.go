package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// LeakCheck Pro API v2: breach records for an email, username, phone, domain...
//
//	GET https://leakcheck.io/api/v2/query/{query}?type=&limit=&offset=
//	Header X-API-Key (key "leakcheck" in keys.json, or NETSHOT_KEY_LEAKCHECK)
//
// Answer: {"success", "found", "quota", "result": [row, ...]}. Each row has a "source" object
// (name, breach_date, unverified, passwordless, compilation), a "fields" list naming the data
// present, and the data itself (email, username, password, first_name, ...). Info-stealer rows
// carry "collected" instead of a breach date. Rows are kept as generic maps so that a field
// LeakCheck adds later still reaches the table.
//
// Only the query (email, domain...) is sent to LeakCheck.

const leakCheckURL = "https://leakcheck.io/api/v2/query/"

// leakSearchTypes: without type, LeakCheck detects email, username, phone and hash itself.
var leakSearchTypes = []string{"auto", "email", "domain", "keyword", "username", "phone", "hash", "phash", "origin", "password"}

type LeakAnswer struct {
	Success bool             `json:"success"`
	Found   int              `json:"found"`
	Quota   int              `json:"quota"`
	Result  []map[string]any `json:"result"`
	Error   string           `json:"error,omitempty"`
}

// leakLookup queries LeakCheck. The key goes in a header, never in the URL.
func leakLookup(ctx context.Context, query, key, qtype string, limit int) (*LeakAnswer, error) {
	if key == "" {
		return nil, errors.New("leakcheck: API key required (key 'leakcheck' in keys.json)")
	}
	query = strings.TrimSpace(query)
	if len([]rune(query)) < 3 {
		return nil, errors.New("leakcheck: query must be at least 3 characters")
	}
	params := url.Values{}
	params.Set("limit", strconv.Itoa(clampInt(limit, 1, 1000)))
	if qtype != "" && qtype != "auto" {
		params.Set("type", qtype)
	}
	u := leakCheckURL + url.PathEscape(query) + "?" + params.Encode()
	body, status, err := ctGet(ctx, u, map[string]string{"X-API-Key": key})
	if err != nil {
		return nil, fmt.Errorf("leakcheck: %w", err)
	}
	var ans LeakAnswer
	jerr := json.Unmarshal(body, &ans)
	if status != http.StatusOK || jerr != nil || !ans.Success {
		msg := ans.Error
		if msg == "" {
			msg = truncate(strings.TrimSpace(string(body)), 150)
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden:
			msg = "key refused (" + msg + ")"
		case http.StatusTooManyRequests:
			msg = "rate limit or quota reached (" + msg + ")"
		}
		return nil, fmt.Errorf("leakcheck: HTTP %d: %s", status, msg)
	}
	return &ans, nil
}
