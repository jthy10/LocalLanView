package arptable

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

const supported = true

// Read returns the current ARP cache from the kernel routing table
// (the same data `arp -an` shows).
func Read() ([]Entry, error) {
	b, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, syscall.RTF_LLINFO)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		la, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || len(la.Addr) != 6 {
			continue
		}
		mac := make(net.HardwareAddr, 6)
		copy(mac, la.Addr)
		out = append(out, Entry{IP: netip.AddrFrom4(dst.IP), MAC: mac, IfIndex: la.Index})
	}
	return out, nil
}
