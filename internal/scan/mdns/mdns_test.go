package mdns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/scan"
)

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

// fakeResponder answers every query with a Chromecast-like record set.
func fakeResponder(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			hdr := func(n string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
				return dnsmessage.ResourceHeader{Name: name(n), Type: typ, Class: dnsmessage.ClassINET, TTL: 120}
			}
			resp := dnsmessage.Message{
				Header: dnsmessage.Header{Response: true, Authoritative: true},
				Answers: []dnsmessage.Resource{
					{Header: hdr("_googlecast._tcp.local.", dnsmessage.TypePTR), Body: &dnsmessage.PTRResource{PTR: name("Living Room TV._googlecast._tcp.local.")}},
				},
				Additionals: []dnsmessage.Resource{
					{Header: hdr("Living Room TV._googlecast._tcp.local.", dnsmessage.TypeSRV), Body: &dnsmessage.SRVResource{Target: name("chromecast-1234.local."), Port: 8009}},
					{Header: hdr("Living Room TV._googlecast._tcp.local.", dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{"md=Chromecast Ultra", "fn=Living Room TV"}}},
					{Header: hdr("chromecast-1234.local.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}},
				},
			}
			b, _ := resp.Pack()
			conn.WriteToUDP(b, from)
		}
	}()
	return conn
}

func TestDiscover(t *testing.T) {
	resp := fakeResponder(t)
	defer resp.Close()

	env := &scan.Env{
		Net: &netinfo.Network{
			IP:     netip.MustParseAddr("127.0.0.1"),
			Prefix: netip.MustParsePrefix("127.0.0.0/24"),
		},
		Limiter: scan.NewLimiter(1000),
	}
	c := &Collector{Group: resp.LocalAddr().String(), Wait: 500 * time.Millisecond}
	var got []scan.Observation
	if err := c.Run(context.Background(), env, func(o scan.Observation) { got = append(got, o) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 observation, got %+v", got)
	}
	o := got[0]
	if o.IP.String() != "127.0.0.1" || o.Hostname != "chromecast-1234" {
		t.Fatalf("bad observation %+v", o)
	}
	if len(o.Services) != 1 {
		t.Fatalf("services: %+v", o.Services)
	}
	s := o.Services[0]
	if s.Type != "_googlecast._tcp" || s.Name != "Living Room TV" || s.Port != 8009 || s.Info["md"] != "Chromecast Ultra" {
		t.Fatalf("bad service %+v", s)
	}
}

func TestHelpers(t *testing.T) {
	if got := guessType("Office._ipp._tcp.local."); got != "_ipp._tcp.local." {
		t.Errorf("guessType = %q", got)
	}
	ip := netip.MustParseAddr("192.168.1.20")
	back, ok := parseReverse(reverseName(ip))
	if !ok || back != ip {
		t.Errorf("reverse round trip: %v %v", back, ok)
	}
}
