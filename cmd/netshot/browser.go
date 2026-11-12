package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/chromedp"
)

// startBrowser launches headless Edge/Chrome on a fixed debugging port and connects to it.
//
// chromedp's own launcher reads the DevTools URL from the process output. Edge sometimes
// relaunches itself into a child process and exits, which chromedp reports as
// "chrome failed to start" while the real browser keeps running. Polling the debugging
// port works whatever process ends up serving it.
func startBrowser(path string, width, height int) (context.Context, func(), error) {
	port, err := freePort()
	if err != nil {
		return nil, nil, err
	}
	profile, err := os.MkdirTemp("", "netshot-browser-")
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(path,
		"--headless",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--remote-debugging-address=127.0.0.1",
		"--user-data-dir="+profile,
		fmt.Sprintf("--window-size=%d,%d", width, height),
		"--ignore-certificate-errors",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-default-apps",
		"--disable-popup-blocking",
		"--disable-features=Translate,msEdgeSidebarV2,EdgeCollections",
		"--mute-audio",
		"--hide-scrollbars",
		"about:blank",
	)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(profile)
		return nil, nil, err
	}

	wsURL, err := waitDevTools(port, 20*time.Second)
	if err != nil {
		cmd.Process.Kill()
		os.RemoveAll(profile)
		return nil, nil, err
	}

	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(context.Background(), wsURL)
	// Discard CDP decode warnings: a browser newer than the library emits unknown event values
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithErrorf(func(string, ...any) {}))
	if err := chromedp.Run(browserCtx); err != nil {
		cancelBrowser()
		cancelAlloc()
		cmd.Process.Kill()
		os.RemoveAll(profile)
		return nil, nil, err
	}

	closeFn := func() {
		// Browser.close ends the real browser even if Edge relaunched itself
		ctx, cancel := context.WithTimeout(browserCtx, 5*time.Second)
		chromedp.Run(ctx, browser.Close())
		cancel()
		cancelBrowser()
		cancelAlloc()
		exited := make(chan struct{})
		go func() { cmd.Wait(); close(exited) }()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
		}
		// The profile folder stays locked for a moment after exit
		for i := 0; i < 10 && os.RemoveAll(profile) != nil; i++ {
			time.Sleep(300 * time.Millisecond)
		}
	}
	return browserCtx, closeFn, nil
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// waitDevTools polls /json/version until the browser answers and returns its WebSocket URL.
func waitDevTools(port int, timeout time.Duration) (string, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/json/version", port)
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			var info struct {
				WS string `json:"webSocketDebuggerUrl"`
			}
			err = json.NewDecoder(resp.Body).Decode(&info)
			resp.Body.Close()
			if err == nil && info.WS != "" {
				return info.WS, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", errors.New("browser did not open its debugging port (blocked by a policy or antivirus?)")
}
