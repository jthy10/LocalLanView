package ssdp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/scan"
)

const descXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>[TV] Samsung Q60</friendlyName>
    <manufacturer>Samsung Electronics</manufacturer>
    <modelName>QN55Q60</modelName>
  </device>
</root>`

func TestDiscover(t *testing.T) {
	desc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, descXML)
	}))
	defer desc.Close()

	responder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := responder.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !strings.HasPrefix(string(buf[:n]), "M-SEARCH") {
				continue
			}
			resp := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n" +
				"LOCATION: " + desc.URL + "/dmr.xml\r\n" +
				"SERVER: Samsung/1.0 UPnP/1.0\r\n" +
				"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n" +
				"USN: uuid:1234::upnp:rootdevice\r\n\r\n"
			responder.WriteToUDP([]byte(resp), from)
		}
	}()

	env := &scan.Env{
		Net:     &netinfo.Network{IP: netip.MustParseAddr("127.0.0.1"), Prefix: netip.MustParsePrefix("127.0.0.0/24")},
		Limiter: scan.NewLimiter(1000),
	}
	c := &Collector{Group: responder.LocalAddr().String(), Wait: 500 * time.Millisecond}
	var got []scan.Observation
	if err := c.Run(context.Background(), env, func(o scan.Observation) { got = append(got, o) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	o := got[0]
	if o.Attrs["ssdp.server"] != "Samsung/1.0 UPnP/1.0" || len(o.Services) != 1 {
		t.Fatalf("bad observation %+v", o)
	}
	s := o.Services[0]
	if s.Name != "[TV] Samsung Q60" || s.Info["manufacturer"] != "Samsung Electronics" || !strings.Contains(s.Type, "MediaRenderer") {
		t.Fatalf("bad service %+v", s)
	}
}

func TestOutOfScopeLocationIgnored(t *testing.T) {
	env := &scan.Env{
		Net:     &netinfo.Network{IP: netip.MustParseAddr("192.168.1.2"), Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		Limiter: scan.NewLimiter(1000),
	}
	_, _, err := fetchDescription(context.Background(), http.DefaultClient, env, "http://203.0.113.5/desc.xml")
	if err == nil {
		t.Fatal("expected out-of-scope location to be refused")
	}
}
