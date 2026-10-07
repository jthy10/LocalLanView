package arptable

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
)

// parseProcNetARP parses Linux's /proc/net/arp:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.1.1      0x1         0x2         a0:b1:c2:d3:e4:f5     *        eth0
func parseProcNetARP(r io.Reader) []Entry {
	var out []Entry
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		if f[2] == "0x0" { // incomplete
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		mac, err := net.ParseMAC(f[3])
		if err != nil {
			continue
		}
		out = append(out, Entry{IP: ip, MAC: mac, IfName: f[5]})
	}
	return out
}

// parseIPNetTable decodes the buffer filled by Windows' GetIpNetTable:
// a uint32 count followed by MIB_IPNETROW structs of 24 bytes each
// (index, physAddrLen, physAddr[8], addr, type).
func parseIPNetTable(b []byte) []Entry {
	if len(b) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b))
	const rowSize = 24
	var out []Entry
	for i := 0; i < n; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(b) {
			break
		}
		row := b[off : off+rowSize]
		idx := binary.LittleEndian.Uint32(row[0:])
		plen := binary.LittleEndian.Uint32(row[4:])
		typ := binary.LittleEndian.Uint32(row[20:])
		if plen != 6 || typ == 2 { // 2 = invalid
			continue
		}
		mac := make(net.HardwareAddr, 6)
		copy(mac, row[8:14])
		ip := netip.AddrFrom4([4]byte(row[16:20])) // stored in network byte order
		out = append(out, Entry{IP: ip, MAC: mac, IfIndex: int(idx)})
	}
	return out
}
