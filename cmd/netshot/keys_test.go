package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureKeysFile(t *testing.T) {
	dir := t.TempDir()
	portable := filepath.Join(dir, "app", "keys.json")
	user := filepath.Join(dir, "appdata", "netshot", "keys.json")
	os.MkdirAll(filepath.Dir(portable), 0o700)
	oldP, oldU := portableKeysPath, userKeysPath
	portableKeysPath = func() string { return portable }
	userKeysPath = func() string { return user }
	defer func() { portableKeysPath, userKeysPath = oldP, oldU }()

	// 1. no file anywhere: template created with every source empty
	ensureKeysFile()
	var k Keys
	data, err := os.ReadFile(portable)
	if err != nil || json.Unmarshal(data, &k) != nil || len(k) != len(keySources) {
		t.Fatalf("template not created: %v %s", err, data)
	}

	// 2. existing portable file kept as is
	os.WriteFile(portable, []byte(`{"shodan":"SECRET"}`), 0o600)
	if loadKeys().get("shodan") != "SECRET" {
		t.Fatal("portable key lost")
	}
	if data, _ := os.ReadFile(portable); string(data) != `{"shodan":"SECRET"}` {
		t.Fatalf("portable file changed: %s", data)
	}

	// 3. only the former user file: copied next to the exe, original left in place
	os.Remove(portable)
	os.MkdirAll(filepath.Dir(user), 0o700)
	os.WriteFile(user, []byte(`{"leakix":"U"}`), 0o600)
	if loadKeys().get("leakix") != "U" {
		t.Fatal("user key lost")
	}
	if data, _ := os.ReadFile(portable); string(data) != `{"leakix":"U"}` {
		t.Fatalf("user file not copied next to the exe: %s", data)
	}
	if data, _ := os.ReadFile(user); string(data) != `{"leakix":"U"}` {
		t.Fatalf("user file changed: %s", data)
	}

	// 4. saving merges into the file on disk, next to the exe, never in the former user file
	os.WriteFile(portable, []byte(`{"leakix":"U","virustotal":"EDITED_BY_HAND"}`), 0o600)
	if err := updateKeys(Keys{"shodan": "NEW"}); err != nil {
		t.Fatal(err)
	}
	k = loadKeys()
	if k.get("shodan") != "NEW" || k.get("virustotal") != "EDITED_BY_HAND" || k.get("leakix") != "U" {
		t.Fatalf("keys lost by save: %v", k)
	}
	if data, _ := os.ReadFile(filepath.Join(filepath.Dir(portable), "keys.json.bak")); string(data) != `{"leakix":"U","virustotal":"EDITED_BY_HAND"}` {
		t.Fatalf("no backup: %s", data)
	}
	if data, _ := os.ReadFile(user); string(data) != `{"leakix":"U"}` {
		t.Fatalf("user file changed by save: %s", data)
	}

	// 5. removal ("-" in the GUI) only drops that key
	updateKeys(Keys{"leakix": ""})
	if k = loadKeys(); k.get("leakix") != "" || k.get("virustotal") != "EDITED_BY_HAND" {
		t.Fatalf("removal wrong: %v", k)
	}

	// 6. invalid JSON (hand edit typo): never rewritten
	os.WriteFile(portable, []byte(`{"shodan":"X",`), 0o600)
	if updateKeys(Keys{"urlscan": "Y"}) == nil {
		t.Fatal("invalid file accepted")
	}
	if data, _ := os.ReadFile(portable); string(data) != `{"shodan":"X",` {
		t.Fatalf("invalid file rewritten: %s", data)
	}
}
