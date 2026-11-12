//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemDNSServers lists the DNS servers of the network adapters that are up.
func systemDNSServers() []string {
	size := uint32(15000)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|
			windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var out []string
		seen := map[string]bool{}
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				ip := d.Address.IP()
				// skip IPv6 site-local placeholders (fec0::) that Windows lists when no DNS is set
				if ip == nil || (ip.To4() == nil && ip[0] == 0xfe && ip[1]&0xc0 == 0xc0) {
					continue
				}
				if s := ip.String(); !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}
