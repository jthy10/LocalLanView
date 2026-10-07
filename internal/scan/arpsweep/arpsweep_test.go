package arpsweep

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/scan"
)

func TestPacketRoundTrip(t *testing.T) {
	src, _ := net.ParseMAC("02:00:00:00:00:01")
	f := BuildRequest(src, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.9"))
	if len(f) != 42 || f[0] != 0xff || f[12] != 0x08 || f[13] != 0x06 {
		t.Fatalf("bad frame % x", f)
	}
	ip, mac, ok := ParseReply(f)
	if !ok || ip.String() != "10.0.0.2" || mac.String() != src.String() {
		t.Fatalf("parse: %v %v %v", ip, mac, ok)
	}
	if _, _, ok := ParseReply(f[:20]); ok {
		t.Fatal("short frame parsed")
	}
}

// fakeLAN answers ARP requests for a fixed set of hosts.
type fakeLAN struct {
	mu    sync.Mutex
	hosts map[netip.Addr]net.HardwareAddr
	queue [][]byte
}

func (f *fakeLAN) Send(frame []byte) error {
	dst := netip.AddrFrom4([4]byte(frame[38:42]))
	f.mu.Lock()
	defer f.mu.Unlock()
	if mac, ok := f.hosts[dst]; ok {
		reply := BuildRequest(mac, dst, netip.AddrFrom4([4]byte(frame[28:32])))
		reply[21] = 2 // op = reply
		f.queue = append(f.queue, reply)
	}
	return nil
}

func (f *fakeLAN) Recv(timeout time.Duration) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		time.Sleep(time.Millisecond)
		return nil, errors.New("timeout")
	}
	fr := f.queue[0]
	f.queue = f.queue[1:]
	return fr, nil
}

func (f *fakeLAN) Close() error { return nil }

func TestSweep(t *testing.T) {
	if resolverOnly {
		t.Skip("uses SendARP on this OS")
	}
	m1, _ := net.ParseMAC("a0:b1:c2:00:00:01")
	m2, _ := net.ParseMAC("a0:b1:c2:00:00:02")
	lan := &fakeLAN{hosts: map[netip.Addr]net.HardwareAddr{
		netip.MustParseAddr("192.168.5.1"):  m1,
		netip.MustParseAddr("192.168.5.20"): m2,
	}}
	own, _ := net.ParseMAC("02:aa:bb:cc:dd:ee")
	env := &scan.Env{
		Net: &netinfo.Network{
			Iface:  net.Interface{HardwareAddr: own},
			IP:     netip.MustParseAddr("192.168.5.10"),
			Prefix: netip.MustParsePrefix("192.168.5.0/27"),
		},
		Limiter:  scan.NewLimiter(10000),
		Elevated: true,
	}
	c := &Collector{T: lan, Wait: 100 * time.Millisecond}
	if ok, why := c.Available(true); !ok {
		t.Fatal(why)
	}
	var mu sync.Mutex
	got := map[string]string{}
	c.Run(context.Background(), env, func(o scan.Observation) {
		mu.Lock()
		got[o.IP.String()] = o.MAC.String()
		mu.Unlock()
	})
	if len(got) != 2 || got["192.168.5.1"] != m1.String() || got["192.168.5.20"] != m2.String() {
		t.Fatalf("got %v", got)
	}
}

func TestUnavailableWithoutRights(t *testing.T) {
	if resolverOnly {
		t.Skip()
	}
	if ok, _ := (&Collector{}).Available(false); ok {
		t.Fatal("should need elevation")
	}
}
