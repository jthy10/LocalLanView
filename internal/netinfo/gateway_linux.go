package netinfo

import (
	"net/netip"
	"os"
)

// Gateway returns the IPv4 default gateway on iface, if there is one.
func Gateway(iface string) (netip.Addr, bool) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, false
	}
	defer f.Close()
	return parseProcRoute(f, iface)
}
