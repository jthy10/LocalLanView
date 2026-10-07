package inventory

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jthy10/LocalLanView/internal/fingerprint"
	"github.com/jthy10/LocalLanView/internal/oui"
	"github.com/jthy10/LocalLanView/internal/scan"
	"github.com/jthy10/LocalLanView/internal/store"
)

func newInv(t *testing.T) (*Inventory, *[]store.Event) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var events []store.Event
	return &Inventory{
		Store:   s,
		OUI:     oui.Default(),
		FP:      fingerprint.Default(),
		OnEvent: func(e store.Event, _ *store.Device) { events = append(events, e) },
	}, &events
}

var ip = netip.MustParseAddr

func TestNewDeviceAndMerge(t *testing.T) {
	inv, events := newInv(t)
	ctx := context.Background()
	now := time.Now()

	// mDNS sees the host before ARP does.
	inv.Observe(scan.Observation{Source: "mdns", Time: now, IP: ip("192.168.1.30"), Hostname: "office-printer",
		Services: []scan.Service{{Source: "mdns", Type: "_ipp._tcp", Name: "Office", Info: map[string]string{"ty": "Brother HL-L2350DW"}}}})
	inv.Observe(scan.Observation{Source: "arp", Time: now, IP: ip("192.168.1.30"), MAC: MustMAC("00:80:77:12:34:56")})

	ds, _ := inv.Store.Devices(ctx)
	if len(ds) != 1 {
		t.Fatalf("want 1 device after merge, got %d", len(ds))
	}
	d := ds[0]
	if d.Key != "mac:00:80:77:12:34:56" || d.Hostname != "office-printer" || d.Type != "Printer" || d.Model != "Brother HL-L2350DW" {
		t.Fatalf("device %+v", d)
	}
	if d.Vendor == "" {
		t.Errorf("vendor lookup missing")
	}
	if len(*events) != 1 || (*events)[0].Kind != store.EventNewDevice {
		t.Fatalf("events %+v", *events)
	}
}

func TestBaselineSuppressesAlerts(t *testing.T) {
	inv, events := newInv(t)
	inv.SetBaseline(true)
	inv.Observe(scan.Observation{Source: "arp", IP: ip("10.0.0.2"), MAC: MustMAC("00:11:22:33:44:55")})
	if len(*events) != 0 {
		t.Fatal("baseline scan should not alert")
	}
	n, _ := inv.Store.UnacknowledgedCount(context.Background())
	if n != 0 {
		t.Fatal("baseline events should be pre-acknowledged")
	}
}

func TestPrivateMAC(t *testing.T) {
	inv, _ := newInv(t)
	inv.Observe(scan.Observation{Source: "arp", IP: ip("10.0.0.3"), MAC: MustMAC("da:a1:19:00:00:01"), Hostname: ""})
	ds, _ := inv.Store.Devices(context.Background())
	if !ds[0].PrivateMAC || ds[0].Vendor != "" || Label(ds[0]) != "Device with private MAC" {
		t.Fatalf("got %+v", ds[0])
	}
}

func TestNewPortAlert(t *testing.T) {
	inv, events := newInv(t)
	mac := MustMAC("00:11:22:33:44:66")
	inv.Observe(scan.Observation{Source: "arp", IP: ip("10.0.0.4"), MAC: mac})
	inv.Observe(scan.Observation{Source: "ports", IP: ip("10.0.0.4"), PortScan: true, Ports: []scan.Port{{Port: 22}}})
	inv.Observe(scan.Observation{Source: "ports", IP: ip("10.0.0.4"), PortScan: true, Ports: []scan.Port{{Port: 22}, {Port: 23}}})
	var kinds []string
	for _, e := range *events {
		kinds = append(kinds, e.Kind)
	}
	if len(kinds) != 2 || kinds[1] != store.EventNewPort || (*events)[1].Data["ports"] != "23" {
		t.Fatalf("events %+v", *events)
	}
}

func TestMACChangeAlert(t *testing.T) {
	inv, events := newInv(t)
	now := time.Now()
	inv.Observe(scan.Observation{Source: "arp", Time: now, IP: ip("10.0.0.1"), MAC: MustMAC("00:11:22:00:00:01")})
	inv.Observe(scan.Observation{Source: "arp", Time: now.Add(time.Minute), IP: ip("10.0.0.1"), MAC: MustMAC("00:11:22:00:00:02")})
	found := false
	for _, e := range *events {
		if e.Kind == store.EventMACChanged && e.Data["oldMac"] == "00:11:22:00:00:01" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected MAC change event, got %+v", *events)
	}
}

func TestHostnamePriority(t *testing.T) {
	inv, _ := newInv(t)
	mac := MustMAC("00:11:22:33:44:77")
	inv.Observe(scan.Observation{Source: "arp", IP: ip("10.0.0.5"), MAC: mac})
	inv.Observe(scan.Observation{Source: "mdns", IP: ip("10.0.0.5"), Hostname: "Jakes-MacBook-Pro"})
	inv.Observe(scan.Observation{Source: "netbios", IP: ip("10.0.0.5"), Hostname: "JAKESMBP"})
	d, _ := inv.Store.DeviceByKey(context.Background(), "mac:"+mac.String())
	if d.Hostname != "Jakes-MacBook-Pro" {
		t.Fatalf("mDNS name should win, got %q", d.Hostname)
	}
	h, _ := inv.Store.HostnameHistory(context.Background(), d.ID)
	if len(h) != 2 {
		t.Fatalf("history %+v", h)
	}
}

func TestLiveHosts(t *testing.T) {
	inv, _ := newInv(t)
	inv.Observe(scan.Observation{Source: "arp", Time: time.Now(), IP: ip("10.0.0.9"), MAC: MustMAC("00:11:22:33:44:88")})
	inv.Observe(scan.Observation{Source: "arp", Time: time.Now().Add(-time.Hour), IP: ip("10.0.0.8"), MAC: MustMAC("00:11:22:33:44:99")})
	got := inv.LiveHosts(10 * time.Minute)
	if len(got) != 1 || got[0].String() != "10.0.0.9" {
		t.Fatalf("got %v", got)
	}
}

func MustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}
