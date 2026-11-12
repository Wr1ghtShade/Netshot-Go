package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Interface settings (the theme), saved in settings.json next to keys.json.
//
// The page cannot keep them itself: each launch serves it on a new random port, so the browser
// sees a new site every time and its localStorage starts empty.

var guiThemes = map[string]bool{"auto": true, "light": true, "dark": true, "terminal": true, "orange": true, "nord": true}

func settingsPath() string { return filepath.Join(filepath.Dir(keysPath()), "settings.json") }

func loadSettings() map[string]any {
	s := map[string]any{}
	if data, err := os.ReadFile(settingsPath()); err == nil {
		json.Unmarshal(data, &s)
	}
	return s
}

// savedTheme returns the saved theme, "auto" when none (or one no longer offered).
func savedTheme() string {
	if t, ok := loadSettings()["theme"].(string); ok && guiThemes[t] {
		return t
	}
	return "auto"
}

func saveTheme(theme string) error {
	s := loadSettings()
	s["theme"] = theme
	if err := os.MkdirAll(filepath.Dir(settingsPath()), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(settingsPath(), data, 0o600)
}
