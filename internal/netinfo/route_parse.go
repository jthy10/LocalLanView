package netinfo

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"strings"
)

// parseProcRoute reads the default route for iface from Linux's
// /proc/net/route format.
func parseProcRoute(r io.Reader, iface string) (netip.Addr, bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[0] != iface || f[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(f[2])
		if err != nil || len(b) != 4 {
			continue
		}
		// /proc/net/route prints addresses in host (little-endian) order.
		v := binary.LittleEndian.Uint32(b)
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], v)
		ip := netip.AddrFrom4(a)
		if !ip.IsUnspecified() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}
