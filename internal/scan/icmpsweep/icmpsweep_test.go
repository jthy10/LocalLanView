package icmpsweep

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/scan"
)

type fakeConn struct {
	mu    sync.Mutex
	up    map[netip.Addr]bool
	queue []netip.Addr
}

func (f *fakeConn) Send(ip netip.Addr, seq int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.up[ip] {
		f.queue = append(f.queue, ip)
	}
	return nil
}

func (f *fakeConn) Recv(time.Duration) (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		time.Sleep(time.Millisecond)
		return netip.Addr{}, errors.New("timeout")
	}
	ip := f.queue[0]
	f.queue = f.queue[1:]
	return ip, nil
}

func (f *fakeConn) Close() error { return nil }

func env() *scan.Env {
	return &scan.Env{
		Net:     &netinfo.Network{IP: netip.MustParseAddr("10.1.0.5"), Prefix: netip.MustParsePrefix("10.1.0.0/27")},
		Limiter: scan.NewLimiter(10000),
	}
}

func TestSweepAsync(t *testing.T) {
	fc := &fakeConn{up: map[netip.Addr]bool{netip.MustParseAddr("10.1.0.1"): true, netip.MustParseAddr("10.1.0.30"): true}}
	c := &Collector{C: fc, Wait: 50 * time.Millisecond}
	var n int
	c.Run(context.Background(), env(), func(o scan.Observation) { n++ })
	if n != 2 {
		t.Fatalf("want 2 replies, got %d", n)
	}
}

func TestSweepSync(t *testing.T) {
	c := &Collector{Ping: func(ip netip.Addr, _ time.Duration) bool { return ip.String() == "10.1.0.9" }}
	var mu sync.Mutex
	var got []string
	c.Run(context.Background(), env(), func(o scan.Observation) { mu.Lock(); got = append(got, o.IP.String()); mu.Unlock() })
	if len(got) != 1 || got[0] != "10.1.0.9" {
		t.Fatalf("got %v", got)
	}
}

func TestUnavailable(t *testing.T) {
	ok, why := (&Collector{OpenErr: errors.New("nope")}).Available(false)
	if ok || why != "nope" {
		t.Fatalf("%v %q", ok, why)
	}
}
