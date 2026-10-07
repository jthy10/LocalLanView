package arptable

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/scan"
)

const procSample = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a0:b1:c2:d3:e4:f5     *        eth0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.77     0x1         0x2         da:a1:19:12:34:56     *        eth0
10.8.0.1         0x1         0x2         11:22:33:44:55:66     *        tun0
`

func TestParseProcNetARP(t *testing.T) {
	es := parseProcNetARP(strings.NewReader(procSample))
	if len(es) != 3 {
		t.Fatalf("got %d entries: %+v", len(es), es)
	}
	if es[0].IP.String() != "192.168.1.1" || es[0].MAC.String() != "a0:b1:c2:d3:e4:f5" || es[0].IfName != "eth0" {
		t.Fatalf("bad first entry %+v", es[0])
	}
}

func TestParseIPNetTable(t *testing.T) {
	buf := make([]byte, 4+24*2)
	binary.LittleEndian.PutUint32(buf, 2)
	row := buf[4:]
	binary.LittleEndian.PutUint32(row[0:], 7)
	binary.LittleEndian.PutUint32(row[4:], 6)
	copy(row[8:], []byte{0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5})
	copy(row[16:], []byte{192, 168, 1, 1})
	binary.LittleEndian.PutUint32(row[20:], 3)
	row = buf[28:]
	binary.LittleEndian.PutUint32(row[4:], 6)
	binary.LittleEndian.PutUint32(row[20:], 2) // invalid, skipped
	es := parseIPNetTable(buf)
	if len(es) != 1 || es[0].IP.String() != "192.168.1.1" || es[0].IfIndex != 7 || es[0].MAC.String() != "a0:b1:c2:d3:e4:f5" {
		t.Fatalf("got %+v", es)
	}
}

func TestRunFilters(t *testing.T) {
	env := &scan.Env{Net: &netinfo.Network{
		Iface:  net.Interface{Index: 2, Name: "eth0"},
		IP:     netip.MustParseAddr("192.168.1.10"),
		Prefix: netip.MustParsePrefix("192.168.1.0/24"),
	}}
	c := &Collector{Source: func() ([]Entry, error) { return parseProcNetARP(strings.NewReader(procSample)), nil }}
	var got []scan.Observation
	if err := c.Run(context.Background(), env, func(o scan.Observation) { got = append(got, o) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 in-scope entries, got %+v", got)
	}
	for _, o := range got {
		if o.Source != "arp" || !env.Net.InScope(o.IP) {
			t.Fatalf("bad observation %+v", o)
		}
	}
}
