package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestKeysFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	old := keysPath
	keysPath = func() string { return path }
	defer func() { keysPath = old }()

	// 1. missing: empty template created with every source
	ensureKeysFile()
	var k Keys
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &k) != nil || len(k) != len(keySources) {
		t.Fatalf("template not created: %v %s", err, data)
	}

	// 2. existing file never overwritten
	os.WriteFile(path, []byte(`{"shodan":"SECRET"}`), 0o600)
	ensureKeysFile()
	if data, _ := os.ReadFile(path); string(data) != `{"shodan":"SECRET"}` {
		t.Fatalf("existing file changed: %s", data)
	}

	// 3. saving merges into the file on disk (hand edits kept) and keeps a backup
	os.WriteFile(path, []byte(`{"leakix":"U","virustotal":"EDITED_BY_HAND"}`), 0o600)
	if err := updateKeys(Keys{"shodan": "NEW"}); err != nil {
		t.Fatal(err)
	}
	k = loadKeys()
	if k.get("shodan") != "NEW" || k.get("virustotal") != "EDITED_BY_HAND" || k.get("leakix") != "U" {
		t.Fatalf("keys lost by save: %v", k)
	}
	if data, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "keys.json.bak")); string(data) != `{"leakix":"U","virustotal":"EDITED_BY_HAND"}` {
		t.Fatalf("no backup: %s", data)
	}

	// 4. removal ("-" in the GUI) only drops that key
	updateKeys(Keys{"leakix": ""})
	if k = loadKeys(); k.get("leakix") != "" || k.get("virustotal") != "EDITED_BY_HAND" {
		t.Fatalf("removal wrong: %v", k)
	}

	// 5. invalid JSON (hand edit typo): never rewritten
	os.WriteFile(path, []byte(`{"shodan":"X",`), 0o600)
	if updateKeys(Keys{"urlscan": "Y"}) == nil {
		t.Fatal("invalid file accepted")
	}
	if data, _ := os.ReadFile(path); string(data) != `{"shodan":"X",` {
		t.Fatalf("invalid file rewritten: %s", data)
	}
}
