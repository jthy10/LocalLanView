package netinfo

import (
	"net"
	"net/netip"
	"strings"
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

func TestParseProcRoute(t *testing.T) {
	const sample = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
	ip, ok := parseProcRoute(strings.NewReader(sample), "eth0")
	if !ok || ip.String() != "192.168.1.1" {
		t.Fatalf("got %v %v", ip, ok)
	}
	if _, ok := parseProcRoute(strings.NewReader(sample), "wlan0"); ok {
		t.Fatal("wrong interface matched")
	}
}

func TestPick(t *testing.T) {
	ipnet := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	ifi := net.Interface{Name: "eth0"}
	tests := []struct {
		name   string
		addrs  []net.Addr
		subnet string
		want   string // "" = no match, "err" = error
	}{
		{"attached subnet", []net.Addr{ipnet("192.168.1.20/24")}, "", "192.168.1.20 192.168.1.0/24"},
		{"skips IPv6 and link-local", []net.Addr{ipnet("fe80::1/64"), ipnet("169.254.3.4/16"), ipnet("10.0.0.5/24")}, "", "10.0.0.5 10.0.0.0/24"},
		{"skips loopback", []net.Addr{ipnet("127.0.0.1/8")}, "", ""},
		{"non-IPNet ignored", []net.Addr{&net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}}, "", ""},
		{"narrower override", []net.Addr{ipnet("192.168.1.20/24")}, "192.168.1.0/26", "192.168.1.20 192.168.1.0/26"},
		{"override outside the segment", []net.Addr{ipnet("192.168.1.20/24")}, "192.168.2.0/24", ""},
		{"override wider than the segment", []net.Addr{ipnet("192.168.1.20/24")}, "192.168.0.0/16", ""},
		{"IPv6 override", []net.Addr{ipnet("192.168.1.20/24")}, "2001:db8::/64", ""},
		{"too large", []net.Addr{ipnet("10.1.2.3/8")}, "", "err"},
		{"too large made small", []net.Addr{ipnet("10.1.2.3/8")}, "10.1.2.0/24", "10.1.2.3 10.1.2.0/24"},
	}
	for _, tt := range tests {
		var sub netip.Prefix
		if tt.subnet != "" {
			sub = netip.MustParsePrefix(tt.subnet)
		}
		n, err := pick(ifi, tt.addrs, sub)
		got := ""
		switch {
		case err != nil:
			got = "err"
		case n != nil:
			got = n.IP.String() + " " + n.Prefix.String()
		}
		if got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestDetectUnknownInterface(t *testing.T) {
	if _, err := Detect("no-such-iface0", netip.Prefix{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestAutoOrder(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	up := net.FlagUp | net.FlagBroadcast
	ifs := []net.Interface{
		{Name: "lo", Flags: up | net.FlagLoopback},
		{Name: "docker0", Flags: up, HardwareAddr: mac},
		{Name: "br-1a2b3c", Flags: up, HardwareAddr: mac},
		{Name: "enp5s0", Flags: up, HardwareAddr: mac},
		{Name: "wlp3s0", Flags: up, HardwareAddr: mac},
		{Name: "tun0", Flags: up | net.FlagPointToPoint},
		{Name: "wg0", Flags: up},
		{Name: "vEthernet (WSL)", Flags: up, HardwareAddr: mac},
		{Name: "tailscale0", Flags: up},
	}
	names := func(ifs []net.Interface) string {
		var s []string
		for _, i := range ifs {
			s = append(s, i.Name)
		}
		return strings.Join(s, ",")
	}
	gw := func(name string) bool { return name == "wlp3s0" }

	// The VPN holds the default route; the Wi-Fi with a gateway wins.
	got, skipped := autoOrder(ifs, "tun0", gw, false)
	if names(got) != "wlp3s0,enp5s0" {
		t.Errorf("order with VPN route: %s", names(got))
	}
	if strings.Join(skipped, ",") != "docker0,br-1a2b3c,tun0,wg0,vEthernet (WSL),tailscale0" {
		t.Errorf("skipped: %v", skipped)
	}
	// The routed physical interface comes first.
	if got, _ := autoOrder(ifs, "enp5s0", gw, false); names(got) != "enp5s0,wlp3s0" {
		t.Errorf("order with wired route: %s", names(got))
	}
	// An explicit -subnet may live on a bridge, so keep them, last.
	if got, _ := autoOrder(ifs, "", gw, true); !strings.HasPrefix(names(got), "wlp3s0,enp5s0,docker0") || len(got) != 8 {
		t.Errorf("order with -subnet: %s", names(got))
	}
}
