package netbios

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/scan"
)

func nameEntry(name string, suffix byte, group bool) []byte {
	b := make([]byte, 18)
	copy(b, []byte(name + "               ")[:15])
	b[15] = suffix
	if group {
		b[16] = 0x84
	} else {
		b[16] = 0x04
	}
	return b
}

func response(id uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0)
	b = append(b, Request(id)[12:46]...) // echo the encoded name
	b = append(b, 0, 0x21, 0, 1, 0, 0, 0, 0)
	names := [][]byte{
		nameEntry("DESKTOP-7Q1", 0x00, false),
		nameEntry("WORKGROUP", 0x00, true),
		nameEntry("DESKTOP-7Q1", 0x20, false),
	}
	rd := []byte{byte(len(names))}
	for _, n := range names {
		rd = append(rd, n...)
	}
	rd = append(rd, 0x00, 0x15, 0x5d, 0x01, 0x02, 0x03)
	rd = append(rd, make([]byte, 40)...) // statistics
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	return append(b, rd...)
}

func TestParse(t *testing.T) {
	r, err := Parse(response(1))
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "DESKTOP-7Q1" || r.Workgroup != "WORKGROUP" || !r.Server || r.MAC.String() != "00:15:5d:01:02:03" {
		t.Fatalf("got %+v", r)
	}
	if _, err := Parse([]byte{1, 2, 3}); err == nil {
		t.Fatal("short packet should fail")
	}
	if _, err := Parse(Request(1)); err == nil {
		t.Fatal("a request is not a response")
	}
}

func TestRequestEncoding(t *testing.T) {
	q := Request(7)
	if len(q) != 50 || q[12] != 0x20 || string(q[13:15]) != "CK" || q[47] != 0x21 {
		t.Fatalf("bad request % x", q)
	}
}

func TestCollector(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			srv.WriteToUDP(response(binary.BigEndian.Uint16(buf[:n])), from)
		}
	}()
	env := &scan.Env{
		Net:       &netinfo.Network{IP: netip.MustParseAddr("127.0.0.1"), Prefix: netip.MustParsePrefix("127.0.0.0/24")},
		Limiter:   scan.NewLimiter(1000),
		LiveHosts: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} },
	}
	c := &Collector{Port: srv.LocalAddr().(*net.UDPAddr).Port, Wait: 300 * time.Millisecond}
	var got []scan.Observation
	c.Run(context.Background(), env, func(o scan.Observation) { got = append(got, o) })
	if len(got) != 1 || got[0].Hostname != "DESKTOP-7Q1" || got[0].Attrs["netbios.workgroup"] != "WORKGROUP" {
		t.Fatalf("got %+v", got)
	}
}
