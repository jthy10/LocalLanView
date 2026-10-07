// Package netinfo figures out which interface and subnet to scan, and keeps
// every probe inside that subnet.
package netinfo

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// MaxHosts caps the size of a scanned subnet (a /16).
const MaxHosts = 1 << 16

// Network is the segment LocalLanView is attached to.
type Network struct {
	Iface  net.Interface
	IP     netip.Addr   // our own address on the interface
	Prefix netip.Prefix // the subnet we scan
}

// Detect picks the interface and subnet to scan. iface and subnet override
// auto-detection; either may be empty/zero.
func Detect(iface string, subnet netip.Prefix) (*Network, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var candidates []net.Interface
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("interface %q not found (available: %s)", iface, names(ifs))
		}
		candidates = []net.Interface{*ifi}
	} else {
		candidates = preferRouted(ifs)
	}

	for _, ifi := range candidates {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			attached := netip.PrefixFrom(ip, ones).Masked()
			n := &Network{Iface: ifi, IP: ip, Prefix: attached}
			if subnet.IsValid() {
				if !subnet.Addr().Is4() || subnet.Bits() < attached.Bits() || !attached.Contains(subnet.Addr()) {
					continue
				}
				n.Prefix = subnet
			}
			if err := n.check(); err != nil {
				return nil, err
			}
			return n, nil
		}
	}
	switch {
	case subnet.IsValid():
		return nil, fmt.Errorf("subnet %s isn't inside a network this machine is attached to; only the local segment can be scanned", subnet)
	case iface != "":
		return nil, fmt.Errorf("interface %q has no usable IPv4 address", iface)
	default:
		return nil, errors.New("no active network interface with an IPv4 address found; use -interface to pick one")
	}
}

func (n *Network) check() error {
	if n.Prefix.Bits() < 16 {
		return fmt.Errorf("subnet %s is larger than a /16; use -subnet to pick a smaller range on this network", n.Prefix)
	}
	return nil
}

// InScope reports whether ip may be probed: inside the subnet, and not the
// network or broadcast address.
func (n *Network) InScope(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !n.Prefix.Contains(ip) {
		return false
	}
	if n.Prefix.Bits() >= 31 {
		return true
	}
	return ip != n.Prefix.Addr() && ip != Broadcast(n.Prefix)
}

// Hosts lists every probe-able address in the subnet except our own.
func (n *Network) Hosts() []netip.Addr {
	var out []netip.Addr
	for ip := n.Prefix.Addr(); n.Prefix.Contains(ip) && len(out) < MaxHosts; ip = ip.Next() {
		if ip != n.IP && n.InScope(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// Broadcast returns the last address of an IPv4 prefix.
func Broadcast(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= ^uint32(0) >> p.Bits()
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// preferRouted puts the interface holding the default route first. A UDP
// "dial" only asks the kernel for a route; no packet is sent.
func preferRouted(ifs []net.Interface) []net.Interface {
	c, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1, never actually contacted
	if err != nil {
		return ifs
	}
	local := c.LocalAddr().(*net.UDPAddr).IP
	c.Close()
	for i, ifi := range ifs {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(local) {
				out := append([]net.Interface{ifi}, ifs[:i]...)
				return append(out, ifs[i+1:]...)
			}
		}
	}
	return ifs
}

func names(ifs []net.Interface) string {
	s := ""
	for i, ifi := range ifs {
		if i > 0 {
			s += ", "
		}
		s += ifi.Name
	}
	return s
}
