// Package integration runs the whole discovery pipeline against a fake
// network made of in-process responders on loopback addresses.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/jthy10/LocalLanView/internal/alert"
	"github.com/jthy10/LocalLanView/internal/auth"
	"github.com/jthy10/LocalLanView/internal/fingerprint"
	"github.com/jthy10/LocalLanView/internal/inventory"
	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/oui"
	"github.com/jthy10/LocalLanView/internal/scan"
	"github.com/jthy10/LocalLanView/internal/scan/arptable"
	"github.com/jthy10/LocalLanView/internal/scan/mdns"
	"github.com/jthy10/LocalLanView/internal/scan/netbios"
	"github.com/jthy10/LocalLanView/internal/scan/ports"
	"github.com/jthy10/LocalLanView/internal/scan/ssdp"
	"github.com/jthy10/LocalLanView/internal/store"
	"github.com/jthy10/LocalLanView/internal/web"
	"github.com/jthy10/LocalLanView/ui"
)

const (
	printerIP = "127.0.0.2"
	castIP    = "127.0.0.3"
	pcIP      = "127.0.0.4"
)

func udp(t *testing.T, ip string, port int) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	if err != nil {
		t.Skipf("can't bind %s on this OS (needs the whole 127.0.0.0/8 on loopback): %v", ip, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func serveUDP(c *net.UDPConn, reply func(req []byte) []byte) {
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if b := reply(buf[:n]); b != nil {
				c.WriteToUDP(b, from)
			}
		}
	}()
}

// fakeMDNS answers like a Brother printer and a Chromecast.
func fakeMDNS(t *testing.T) string {
	c := udp(t, "127.0.0.1", 0)
	name := dnsmessage.MustNewName
	hdr := func(n string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: name(n), Type: typ, Class: dnsmessage.ClassINET, TTL: 120}
	}
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{Header: hdr("_ipp._tcp.local.", dnsmessage.TypePTR), Body: &dnsmessage.PTRResource{PTR: name("Brother HL-L2350DW._ipp._tcp.local.")}},
			{Header: hdr("_googlecast._tcp.local.", dnsmessage.TypePTR), Body: &dnsmessage.PTRResource{PTR: name("Living Room TV._googlecast._tcp.local.")}},
		},
		Additionals: []dnsmessage.Resource{
			{Header: hdr("Brother HL-L2350DW._ipp._tcp.local.", dnsmessage.TypeSRV), Body: &dnsmessage.SRVResource{Target: name("BRN3C2AF4.local."), Port: 631}},
			{Header: hdr("Brother HL-L2350DW._ipp._tcp.local.", dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{"ty=Brother HL-L2350DW series", "usb_MFG=Brother"}}},
			{Header: hdr("BRN3C2AF4.local.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 2}}},
			{Header: hdr("Living Room TV._googlecast._tcp.local.", dnsmessage.TypeSRV), Body: &dnsmessage.SRVResource{Target: name("Chromecast-Ultra-1a2b.local."), Port: 8009}},
			{Header: hdr("Living Room TV._googlecast._tcp.local.", dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{"md=Chromecast Ultra", "fn=Living Room TV"}}},
			{Header: hdr("Chromecast-Ultra-1a2b.local.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 3}}},
		},
	}
	b, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	serveUDP(c, func([]byte) []byte { return b })
	return c.LocalAddr().String()
}

// fakeSSDP makes the Chromecast answer M-SEARCH with a device description.
func fakeSSDP(t *testing.T) string {
	ln, err := net.Listen("tcp4", castIP+":0")
	if err != nil {
		t.Skip(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<root><device><deviceType>urn:dial-multiscreen-org:device:dial:1</deviceType>`+
			`<friendlyName>Living Room TV</friendlyName><manufacturer>Google Inc.</manufacturer><modelName>Eureka Dongle</modelName></device></root>`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	loc := "http://" + ln.Addr().String() + "/ssdp/device-desc.xml"

	c := udp(t, castIP, 0)
	serveUDP(c, func(req []byte) []byte {
		if !strings.HasPrefix(string(req), "M-SEARCH") {
			return nil
		}
		return []byte("HTTP/1.1 200 OK\r\nLOCATION: " + loc + "\r\nSERVER: Linux/3.8 UPnP/1.0 GUPnP/1.0\r\n" +
			"ST: urn:dial-multiscreen-org:service:dial:1\r\nUSN: uuid:abc\r\n\r\n")
	})
	return c.LocalAddr().String()
}

// fakeNetBIOS answers node status queries for a Windows PC.
func fakeNetBIOS(t *testing.T) int {
	c := udp(t, pcIP, 0)
	serveUDP(c, func(req []byte) []byte {
		entry := func(n string, suffix byte, group bool) []byte {
			b := make([]byte, 18)
			copy(b, []byte(n + "               ")[:15])
			b[15] = suffix
			if group {
				b[16] = 0x84
			}
			return b
		}
		b := append([]byte{req[0], req[1], 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}, req[12:46]...)
		b = append(b, 0, 0x21, 0, 1, 0, 0, 0, 0)
		rd := append([]byte{2}, entry("GAMING-PC", 0, false)...)
		rd = append(rd, entry("WORKGROUP", 0, true)...)
		rd = append(rd, 0, 0, 0, 0, 0, 0)
		return append(append(b, byte(len(rd)>>8), byte(len(rd))), rd...)
	})
	return c.LocalAddr().(*net.UDPAddr).Port
}

// fakeSSH listens on the PC and sends an SSH banner.
func fakeSSH(t *testing.T) int {
	ln, err := net.Listen("tcp4", pcIP+":0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprint(c, "SSH-2.0-OpenSSH_for_Windows_9.5\r\n")
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestPipelineEndToEnd(t *testing.T) {
	mdnsAddr := fakeMDNS(t)
	ssdpAddr := fakeSSDP(t)
	nbPort := fakeNetBIOS(t)
	sshPort := fakeSSH(t)

	st, err := store.Open(filepath.Join(t.TempDir(), "it.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	hub := alert.NewHub()
	var alerts []store.Event
	inv := &inventory.Inventory{
		Store: st, OUI: oui.Default(), FP: fingerprint.Default(), Self: netip.MustParseAddr("127.0.0.1"),
		OnEvent: func(e store.Event, _ *store.Device) { alerts = append(alerts, e) },
	}
	nw := &netinfo.Network{IP: netip.MustParseAddr("127.0.0.1"), Prefix: netip.MustParsePrefix("127.0.0.0/24")}
	env := &scan.Env{
		Net:       nw,
		Limiter:   scan.NewLimiter(2000),
		LiveHosts: func() []netip.Addr { return inv.LiveHosts(time.Hour) },
	}
	arp := func() ([]arptable.Entry, error) {
		mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
		return []arptable.Entry{
			{IP: netip.MustParseAddr(printerIP), MAC: mac("3c:2a:f4:11:22:33")}, // Brother
			{IP: netip.MustParseAddr(castIP), MAC: mac("54:60:09:aa:bb:cc")},    // Google
			{IP: netip.MustParseAddr(pcIP), MAC: mac("d8:bb:c1:01:02:03")},      // Micro-Star (MSI)
		}, nil
	}
	engine := &scan.Engine{
		Env:  env,
		Emit: inv.Observe,
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Collectors: []scan.Collector{
			&arptable.Collector{Source: arp},
			&mdns.Collector{Group: mdnsAddr, UnicastPort: 1, Wait: 400 * time.Millisecond},
			&ssdp.Collector{Group: ssdpAddr, Wait: 400 * time.Millisecond},
			&netbios.Collector{Port: nbPort, Wait: 300 * time.Millisecond},
			&ports.Collector{Ports: map[int]string{sshPort: "ssh"}, DialTimeout: 300 * time.Millisecond},
		},
	}
	engine.Cycle(context.Background())

	// Talk to the result through the real HTTP API.
	hash, _ := auth.HashPassword("Integration-Test-1")
	st.SetCredentials(context.Background(), store.Credentials{User: "admin", Hash: hash})
	srv := httptest.NewServer((&web.Server{
		Store: st, Sessions: auth.NewSessions(false), Limiter: auth.NewLoginLimiter(), Hub: hub,
		Static: ui.FS(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Status: func(context.Context) any { return nil }, ScanNow: func() {},
	}).Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{"user":"admin","password":"Integration-Test-1"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("login: %v %v", err, resp.Status)
	}
	resp.Body.Close()
	resp, err = c.Get(srv.URL + "/api/devices")
	if err != nil {
		t.Fatal(err)
	}
	var devices []store.Device
	json.NewDecoder(resp.Body).Decode(&devices)
	resp.Body.Close()

	byIP := map[string]store.Device{}
	for _, d := range devices {
		byIP[d.IP] = d
	}
	if len(byIP) != 3 {
		t.Fatalf("want 3 devices, got %d: %+v", len(byIP), devices)
	}

	p := byIP[printerIP]
	if p.Type != "Printer" || p.Hostname != "BRN3C2AF4" || !strings.Contains(p.Vendor, "Brother") || p.Model != "Brother HL-L2350DW series" {
		t.Errorf("printer: %+v", p)
	}
	cc := byIP[castIP]
	if cc.Type != "Streaming Device" || cc.TypeConfidence != "high" || !strings.HasPrefix(cc.Vendor, "Google") || cc.Attrs["ssdp.server"] == "" {
		t.Errorf("chromecast: %+v", cc)
	}
	pc := byIP[pcIP]
	if pc.Hostname != "GAMING-PC" || pc.Type != "Windows PC" || pc.TypeConfidence != "high" || pc.Attrs["netbios.workgroup"] != "WORKGROUP" || len(pc.OpenPorts) != 1 || pc.OpenPorts[0] != sshPort {
		t.Errorf("pc: %+v", pc)
	}

	// Device detail exposes the banner and both discovery protocols.
	resp, _ = c.Get(fmt.Sprintf("%s/api/devices/%d", srv.URL, pc.ID))
	var detail struct {
		Ports []store.Port `json:"ports"`
	}
	json.NewDecoder(resp.Body).Decode(&detail)
	resp.Body.Close()
	if len(detail.Ports) != 1 || detail.Ports[0].Banner != "SSH-2.0-OpenSSH_for_Windows_9.5" {
		t.Errorf("pc ports: %+v", detail.Ports)
	}
	resp, _ = c.Get(fmt.Sprintf("%s/api/devices/%d", srv.URL, cc.ID))
	var ccDetail struct {
		Services []store.Service `json:"services"`
	}
	json.NewDecoder(resp.Body).Decode(&ccDetail)
	resp.Body.Close()
	sources := map[string]bool{}
	for _, s := range ccDetail.Services {
		sources[s.Source] = true
	}
	if !sources["mdns"] || !sources["ssdp"] {
		t.Errorf("chromecast services: %+v", ccDetail.Services)
	}

	if len(alerts) != 3 {
		t.Errorf("want 3 new-device alerts, got %d", len(alerts))
	}

	// A second cycle finds nothing new.
	alerts = nil
	engine.Cycle(context.Background())
	if len(alerts) != 0 {
		t.Errorf("second scan raised %d alerts: %+v", len(alerts), alerts)
	}
}
