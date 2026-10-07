package ports

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/scan"
)

func port(t *testing.T, addr net.Addr) int { return addr.(*net.TCPAddr).Port }

func TestScan(t *testing.T) {
	// SSH-like banner service
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprint(c, "SSH-2.0-OpenSSH_9.6\r\n")
			c.Close()
		}
	}()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "lighttpd/1.4")
	}))
	defer web.Close()
	webPort := port(t, web.Listener.Addr())
	httpPorts[webPort] = true
	defer delete(httpPorts, webPort)

	closed, _ := net.Listen("tcp4", "127.0.0.1:0")
	closedPort := port(t, closed.Addr())
	closed.Close()

	sshPort := port(t, ln.Addr())
	env := &scan.Env{
		Net:       &netinfo.Network{IP: netip.MustParseAddr("127.0.0.1"), Prefix: netip.MustParsePrefix("127.0.0.0/24")},
		Limiter:   scan.NewLimiter(1000),
		LiveHosts: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} },
	}
	c := &Collector{Ports: map[int]string{sshPort: "ssh", webPort: "http", closedPort: "closed"}}
	var got []scan.Observation
	if err := c.Run(context.Background(), env, func(o scan.Observation) { got = append(got, o) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].PortScan {
		t.Fatalf("got %+v", got)
	}
	ps := got[0].Ports
	if len(ps) != 2 {
		t.Fatalf("want 2 open ports, got %+v", ps)
	}
	banners := map[int]string{}
	for _, p := range ps {
		banners[p.Port] = p.Banner
	}
	if banners[sshPort] != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("ssh banner %q", banners[sshPort])
	}
	if !strings.Contains(banners[webPort], "Server: lighttpd/1.4") {
		t.Errorf("http banner %q", banners[webPort])
	}
}

func TestClean(t *testing.T) {
	if got := Clean("\xff\xfb\x01Login:\r\n\r\n  "); got != "Login:" {
		t.Errorf("Clean = %q", got)
	}
	if len(Clean(strings.Repeat("a", 500))) != 200 {
		t.Error("banner not truncated")
	}
}

func TestDisabled(t *testing.T) {
	if ok, _ := (&Collector{Disabled: true}).Available(true); ok {
		t.Fatal("disabled collector reported available")
	}
}
