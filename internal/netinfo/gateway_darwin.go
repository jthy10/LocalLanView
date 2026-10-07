package netinfo

import (
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// Gateway returns the IPv4 default gateway, if there is one.
func Gateway(string) (netip.Addr, bool) {
	b, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return netip.Addr{}, false
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			continue
		}
		if gw, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr); ok {
			return netip.AddrFrom4(gw.IP), true
		}
	}
	return netip.Addr{}, false
}
