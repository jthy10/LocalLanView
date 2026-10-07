package arpsweep

import (
	"encoding/binary"
	"net"
	"net/netip"
)

const (
	etherTypeARP = 0x0806
	frameLen     = 42 // 14 byte Ethernet header + 28 byte ARP payload
)

// BuildRequest returns a broadcast Ethernet frame asking "who has dst?".
func BuildRequest(srcMAC net.HardwareAddr, srcIP, dst netip.Addr) []byte {
	b := make([]byte, frameLen)
	copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(b[6:12], srcMAC)
	binary.BigEndian.PutUint16(b[12:], etherTypeARP)
	a := b[14:]
	binary.BigEndian.PutUint16(a[0:], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(a[2:], 0x0800) // protocol: IPv4
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:], 1) // request
	copy(a[8:14], srcMAC)
	s := srcIP.As4()
	copy(a[14:18], s[:])
	// target MAC stays zero
	d := dst.As4()
	copy(a[24:28], d[:])
	return b
}

// ParseReply extracts the sender of an ARP reply (or announcement) frame.
func ParseReply(b []byte) (netip.Addr, net.HardwareAddr, bool) {
	if len(b) < frameLen || binary.BigEndian.Uint16(b[12:]) != etherTypeARP {
		return netip.Addr{}, nil, false
	}
	a := b[14:]
	if binary.BigEndian.Uint16(a[0:]) != 1 || binary.BigEndian.Uint16(a[2:]) != 0x0800 || a[4] != 6 || a[5] != 4 {
		return netip.Addr{}, nil, false
	}
	op := binary.BigEndian.Uint16(a[6:])
	if op != 1 && op != 2 {
		return netip.Addr{}, nil, false
	}
	mac := net.HardwareAddr(append([]byte(nil), a[8:14]...))
	ip := netip.AddrFrom4([4]byte(a[14:18]))
	if !ip.IsValid() || ip.IsUnspecified() {
		return netip.Addr{}, nil, false
	}
	return ip, mac, true
}
