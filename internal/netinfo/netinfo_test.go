package netinfo

import (
	"net/netip"
	"testing"
)

func TestInScope(t *testing.T) {
	n := &Network{IP: netip.MustParseAddr("192.168.1.10"), Prefix: netip.MustParsePrefix("192.168.1.0/24")}
	tests := map[string]bool{
		"192.168.1.1":   true,
		"192.168.1.254": true,
		"192.168.1.0":   false,
		"192.168.1.255": false,
		"192.168.2.1":   false,
		"8.8.8.8":       false,
		"10.0.0.1":      false,
	}
	for s, want := range tests {
		if got := n.InScope(netip.MustParseAddr(s)); got != want {
			t.Errorf("InScope(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestHosts(t *testing.T) {
	n := &Network{IP: netip.MustParseAddr("10.0.0.2"), Prefix: netip.MustParsePrefix("10.0.0.0/29")}
	hosts := n.Hosts()
	// .1 .3 .4 .5 .6 (skips network .0, self .2, broadcast .7)
	if len(hosts) != 5 || hosts[0].String() != "10.0.0.1" || hosts[4].String() != "10.0.0.6" {
		t.Fatalf("got %v", hosts)
	}
}

func TestBroadcast(t *testing.T) {
	for p, want := range map[string]string{
		"192.168.1.0/24": "192.168.1.255",
		"10.0.0.0/8":     "10.255.255.255",
		"172.16.4.0/22":  "172.16.7.255",
	} {
		if got := Broadcast(netip.MustParsePrefix(p)); got.String() != want {
			t.Errorf("Broadcast(%s) = %s, want %s", p, got, want)
		}
	}
}

func TestTooLarge(t *testing.T) {
	n := &Network{Prefix: netip.MustParsePrefix("10.0.0.0/8")}
	if n.check() == nil {
		t.Fatal("a /8 should be rejected")
	}
}
