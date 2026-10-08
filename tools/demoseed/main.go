// Command demoseed fills a database with made-up devices so the dashboard
// can be worked on without a real network:
//
//	go run ./tools/demoseed -data-dir ./demo
//	go run ./cmd/locallanview -data-dir ./demo -mode std
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/jthy10/LocalLanView/internal/fingerprint"
	"github.com/jthy10/LocalLanView/internal/inventory"
	"github.com/jthy10/LocalLanView/internal/oui"
	"github.com/jthy10/LocalLanView/internal/scan"
	"github.com/jthy10/LocalLanView/internal/store"
)

type demo struct {
	ip, mac, host, src string
	svcs               []scan.Service
	ports              []scan.Port
	ago                time.Duration
	attrs              map[string]string
}

func main() {
	dir := flag.String("data-dir", "demo", "data directory to create the database in")
	flag.Parse()
	st, err := store.Open(filepath.Join(*dir, "locallanview.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	inv := &inventory.Inventory{Store: st, OUI: oui.Default(), FP: fingerprint.Default(),
		Gateway: netip.MustParseAddr("192.168.1.1")}

	devices := []demo{
		{ip: "192.168.1.1", mac: "e4:f4:c6:10:20:30", src: "ssdp",
			svcs:  []scan.Service{{Source: "ssdp", Type: "urn:schemas-upnp-org:device:InternetGatewayDevice:1", Name: "NETGEAR Nighthawk", Info: map[string]string{"manufacturer": "NETGEAR", "model": "R7000"}}},
			ports: []scan.Port{{Port: 53, Service: "dns"}, {Port: 80, Service: "http", Banner: "HTTP/1.0 401 Unauthorized | Server: httpd"}, {Port: 443, Service: "https", Banner: "TLS cert CN=routerlogin.net (self-signed)"}}},
		{ip: "192.168.1.20", mac: "3c:2a:f4:11:22:33", host: "BRN3C2AF4", src: "mdns",
			svcs:  []scan.Service{{Source: "mdns", Type: "_ipp._tcp", Name: "Brother HL-L2350DW series", Port: 631, Info: map[string]string{"ty": "Brother HL-L2350DW series"}}},
			ports: []scan.Port{{Port: 80, Service: "http", Banner: "HTTP/1.1 200 OK | Server: debut/1.30"}, {Port: 631, Service: "ipp"}, {Port: 9100, Service: "jetdirect"}}},
		{ip: "192.168.1.31", mac: "54:60:09:aa:bb:cc", host: "Chromecast-Ultra", src: "mdns",
			svcs:  []scan.Service{{Source: "mdns", Type: "_googlecast._tcp", Name: "Living Room TV", Port: 8009, Info: map[string]string{"md": "Chromecast Ultra", "fn": "Living Room TV"}}},
			ports: []scan.Port{{Port: 8008, Service: "chromecast"}, {Port: 8009, Service: "cast"}}},
		{ip: "192.168.1.32", mac: "48:a6:b8:01:02:03", host: "Sonos-Kitchen", src: "mdns",
			svcs:  []scan.Service{{Source: "mdns", Type: "_sonos._tcp", Name: "Kitchen", Port: 1443}},
			ports: []scan.Port{{Port: 1400, Service: "sonos", Banner: "HTTP/1.1 200 OK | Server: Linux UPnP/1.0 Sonos/80.1"}}},
		{ip: "192.168.1.44", mac: "da:a1:19:5e:77:01", host: "iPhone", src: "mdns",
			svcs:  []scan.Service{{Source: "mdns", Type: "_companion-link._tcp", Name: "iPhone"}},
			ports: []scan.Port{{Port: 62078, Service: "iphone-sync"}}, ago: 50 * time.Minute},
		{ip: "192.168.1.50", mac: "d8:bb:c1:01:02:03", host: "GAMING-PC", src: "netbios",
			attrs: map[string]string{"netbios.workgroup": "WORKGROUP"},
			ports: []scan.Port{{Port: 135, Service: "msrpc"}, {Port: 139, Service: "netbios-ssn"}, {Port: 445, Service: "smb"}, {Port: 3389, Service: "rdp"}}},
		{ip: "192.168.1.51", mac: "f0:18:98:44:55:66", host: "MacBook-Pro", src: "mdns",
			svcs:  []scan.Service{{Source: "mdns", Type: "_device-info._tcp", Name: "MacBook-Pro", Info: map[string]string{"model": "Mac15,7"}}, {Source: "mdns", Type: "_sftp-ssh._tcp", Name: "MacBook-Pro", Port: 22}},
			ports: []scan.Port{{Port: 22, Service: "ssh", Banner: "SSH-2.0-OpenSSH_9.8"}}},
		{ip: "192.168.1.60", mac: "00:11:32:9a:bc:de", host: "DiskStation", src: "mdns",
			svcs:  []scan.Service{{Source: "mdns", Type: "_smb._tcp", Name: "DiskStation", Port: 445}, {Source: "mdns", Type: "_adisk._tcp", Name: "DiskStation"}},
			ports: []scan.Port{{Port: 445, Service: "smb"}, {Port: 5000, Service: "upnp/http"}, {Port: 5001, Service: "https-alt", Banner: "TLS cert CN=synology (self-signed)"}}},
		{ip: "192.168.1.70", mac: "44:19:b6:12:34:56", src: "ssdp",
			ports: []scan.Port{{Port: 80, Service: "http"}, {Port: 554, Service: "rtsp"}, {Port: 23, Service: "telnet", Banner: "login:"}}},
		{ip: "192.168.1.80", mac: "84:f3:eb:aa:00:11", host: "esp-garage-door", src: "mdns",
			svcs: []scan.Service{{Source: "mdns", Type: "_esphomelib._tcp", Name: "garage-door", Port: 6053}}},
		{ip: "192.168.1.90", mac: "dc:a6:32:01:23:45", host: "pihole", src: "mdns",
			ports: []scan.Port{{Port: 22, Service: "ssh", Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"}, {Port: 53, Service: "dns"}, {Port: 80, Service: "http"}}},
		{ip: "192.168.1.101", mac: "a8:23:fe:66:77:88", host: "LG-webOS-TV", src: "mdns",
			svcs:  []scan.Service{{Source: "mdns", Type: "_airplay._tcp", Name: "[LG] webOS TV OLED55C3"}},
			ports: []scan.Port{{Port: 3000, Service: "http-dev"}}, ago: 26 * time.Hour},
		{ip: "192.168.1.120", mac: "6e:3f:01:aa:bb:cc", src: "arp"},
	}

	ctx := context.Background()
	inv.SetBaseline(true)
	for _, d := range devices {
		t := time.Now().Add(-d.ago)
		mac, _ := net.ParseMAC(d.mac)
		ip := netip.MustParseAddr(d.ip)
		inv.Observe(scan.Observation{Source: "arp", Time: t.Add(-72 * time.Hour), IP: ip, MAC: mac})
		inv.Observe(scan.Observation{Source: d.src, Time: t, IP: ip, Hostname: d.host, Services: d.svcs, Attrs: d.attrs})
		inv.Observe(scan.Observation{Source: "ports", Time: t, IP: ip, Ports: d.ports, PortScan: true})
	}
	inv.SetBaseline(false)
	st.SetSetting(ctx, "baseline_done", "1")

	// A newcomer, so the alerts page has something to show.
	mac, _ := net.ParseMAC("b0:be:76:01:02:03")
	inv.Observe(scan.Observation{Source: "arp", IP: netip.MustParseAddr("192.168.1.133"), MAC: mac})
	log.Printf("seeded %d devices into %s", len(devices)+1, st.Path())
}
