//go:build !windows

package main

// maximizeWindow: on Linux and macOS, --start-maximized given to the browser is enough.
func maximizeWindow(title string) {}
