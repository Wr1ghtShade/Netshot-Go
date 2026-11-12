//go:build windows

package main

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32         = windows.NewLazySystemDLL("user32.dll")
	procFindWindow = user32.NewProc("FindWindowW")
	procShowWindow = user32.NewProc("ShowWindow")
	procIsZoomed   = user32.NewProc("IsZoomed")
)

// maximizeWindow waits up to 15 s for the interface window (title "NetShot") and maximizes it.
// Edge ignores --start-maximized when it is already running, so the window is maximized here.
func maximizeWindow(title string) {
	t, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		hwnd, _, _ := procFindWindow.Call(0, uintptr(unsafe.Pointer(t)))
		if hwnd == 0 {
			continue
		}
		if zoomed, _, _ := procIsZoomed.Call(hwnd); zoomed == 0 {
			procShowWindow.Call(hwnd, 3) // SW_MAXIMIZE
		}
		return
	}
}
