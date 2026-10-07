// Package inventory merges observations from every collector into devices,
// keeps their history, re-runs fingerprinting and raises change events.
package inventory

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jthy10/LocalLanView/internal/fingerprint"
	"github.com/jthy10/LocalLanView/internal/oui"
	"github.com/jthy10/LocalLanView/internal/scan"
	"github.com/jthy10/LocalLanView/internal/store"
)

// Inventory is safe for concurrent use; observations are applied one at a
// time.
type Inventory struct {
	Store *store.Store
	OUI   *oui.DB
	FP    *fingerprint.Engine
	Log   *slog.Logger

	// OnEvent is called for alert-worthy events (not during the baseline scan).
	OnEvent func(store.Event, *store.Device)
	// OnChange is called after any device is updated.
	OnChange func(deviceID int64)

	mu       sync.Mutex
	baseline bool
}

// SetBaseline marks the first ever scan: devices are recorded but no "new
// device" alerts fire, since everything would be new.
func (inv *Inventory) SetBaseline(b bool) {
	inv.mu.Lock()
	inv.baseline = b
	inv.mu.Unlock()
}

// hostnameRank decides which source's name wins.
var hostnameRank = map[string]int{"mdns": 4, "netbios": 3, "llmnr": 3}

// macChangeWindow: if another MAC held the same IP this recently, flag it.
const macChangeWindow = 10 * time.Minute

// Observe applies one observation.
func (inv *Inventory) Observe(o scan.Observation) {
	if !o.IP.IsValid() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv.mu.Lock()
	defer inv.mu.Unlock()
	id, err := inv.apply(ctx, o)
	if err != nil {
		if inv.Log != nil {
			inv.Log.Error("applying observation", "source", o.Source, "ip", o.IP, "err", err)
		}
		return
	}
	if inv.OnChange != nil && id != 0 {
		inv.OnChange(id)
	}
}

func (inv *Inventory) apply(ctx context.Context, o scan.Observation) (int64, error) {
	if o.Time.IsZero() {
		o.Time = time.Now()
	}
	ip := o.IP.Unmap().String()
	var events []store.Event

	d, isNew, err := inv.resolve(ctx, o, ip, &events)
	if err != nil || d == nil {
		return 0, err
	}

	if o.Time.After(d.LastSeen) {
		d.LastSeen = o.Time
	}
	d.IP = ip
	if _, err := inv.Store.TouchIP(ctx, d.ID, ip, o.Time); err != nil {
		return 0, err
	}
	if len(o.MAC) == 6 {
		r := inv.OUI.Lookup(o.MAC)
		d.Vendor, d.VendorRegistry, d.PrivateMAC = r.Vendor, r.Registry, r.Private
	}
	if !contains(d.Sources, o.Source) {
		d.Sources = append(d.Sources, o.Source)
		sort.Strings(d.Sources)
	}
	for k, v := range o.Attrs {
		d.Attrs[k] = v
	}
	if h := strings.TrimSpace(o.Hostname); h != "" {
		if err := inv.Store.TouchHostname(ctx, d.ID, h, o.Source, o.Time); err != nil {
			return 0, err
		}
		if d.Hostname == "" || hostnameRank[o.Source] >= hostnameRank[d.HostnameSource] {
			d.Hostname, d.HostnameSource = h, o.Source
		}
	}
	for _, s := range o.Services {
		if _, err := inv.Store.UpsertService(ctx, d.ID, store.Service{
			Source: s.Source, Type: s.Type, Name: s.Name, Port: s.Port, Info: s.Info,
		}, o.Time); err != nil {
			return 0, err
		}
	}
	if o.PortScan {
		scanned, _ := inv.Store.HasPortScan(ctx, d.ID)
		ports := make([]store.Port, 0, len(o.Ports))
		for _, p := range o.Ports {
			ports = append(ports, store.Port{Port: p.Port, Service: p.Service, Banner: p.Banner})
		}
		added, err := inv.Store.SetPorts(ctx, d.ID, ports, o.Time)
		if err != nil {
			return 0, err
		}
		if scanned && !isNew && len(added) > 0 {
			events = append(events, store.Event{
				Kind:    store.EventNewPort,
				Message: fmt.Sprintf("%s opened new port(s): %s", Label(d), joinInts(added)),
				Data:    map[string]string{"ports": joinInts(added)},
			})
		}
	}

	if err := inv.classify(ctx, d); err != nil {
		return 0, err
	}
	if err := inv.Store.SaveDiscovered(ctx, d); err != nil {
		return 0, err
	}

	if isNew {
		msg := "New device: " + Label(d)
		if d.IP != "" && Label(d) != d.IP {
			msg += " (" + d.IP + ")"
		}
		events = append([]store.Event{{Kind: store.EventNewDevice, Message: msg}}, events...)
	}
	for _, e := range events {
		e.Time = o.Time
		e.DeviceID = d.ID
		e.Acknowledged = inv.baseline
		if err := inv.Store.AddEvent(ctx, &e); err != nil {
			return 0, err
		}
		if !inv.baseline && inv.OnEvent != nil {
			inv.OnEvent(e, d)
		}
	}
	return d.ID, nil
}

// resolve finds or creates the device an observation belongs to. Devices
// are keyed by MAC; an IP-only key is used until a MAC shows up.
func (inv *Inventory) resolve(ctx context.Context, o scan.Observation, ip string, events *[]store.Event) (*store.Device, bool, error) {
	ipKey := "ip:" + ip
	if len(o.MAC) == 6 {
		mac := o.MAC.String()
		key := "mac:" + mac
		d, err := inv.Store.DeviceByKey(ctx, key)
		if err != nil && err != store.ErrNotFound {
			return nil, false, err
		}
		ipDev, err := inv.Store.DeviceByKey(ctx, ipKey)
		if err != nil && err != store.ErrNotFound {
			return nil, false, err
		}
		isNew := false
		prevIP := ""
		if d != nil {
			prevIP = d.IP
		}
		switch {
		case d == nil && ipDev != nil:
			// First time we learn this device's MAC: promote it.
			d = ipDev
			d.Key, d.MAC = key, mac
			prevIP = ip
		case d != nil && ipDev != nil:
			if err := inv.Store.MergeInto(ctx, ipDev.ID, d.ID); err != nil {
				return nil, false, err
			}
			d, _ = inv.Store.DeviceByKey(ctx, key)
		case d == nil:
			nd := &store.Device{Key: key, MAC: mac, IP: ip, FirstSeen: o.Time, LastSeen: o.Time}
			id, err := inv.Store.InsertDevice(ctx, nd)
			if err != nil {
				return nil, false, err
			}
			if d, err = inv.Store.DeviceByKey(ctx, key); err != nil {
				return nil, false, err
			}
			_ = id
			isNew = true
		}
		inv.checkMACChange(ctx, d, prevIP, ip, o.Time, events)
		return d, isNew, nil
	}

	others, err := inv.Store.DevicesByIP(ctx, ip)
	if err != nil {
		return nil, false, err
	}
	if len(others) > 0 {
		return others[0], false, nil
	}
	nd := &store.Device{Key: ipKey, IP: ip, FirstSeen: o.Time, LastSeen: o.Time}
	if _, err := inv.Store.InsertDevice(ctx, nd); err != nil {
		return nil, false, err
	}
	d, err := inv.Store.DeviceByKey(ctx, ipKey)
	return d, true, err
}

// checkMACChange flags an IP that recently belonged to a different MAC.
// That's usually a DHCP lease moving, but can also be ARP spoofing.
func (inv *Inventory) checkMACChange(ctx context.Context, d *store.Device, prevIP, ip string, t time.Time, events *[]store.Event) {
	if prevIP == ip {
		return
	}
	others, err := inv.Store.DevicesByIP(ctx, ip)
	if err != nil {
		return
	}
	for _, other := range others {
		if other.ID == d.ID || other.MAC == "" || t.Sub(other.LastSeen) > macChangeWindow {
			continue
		}
		*events = append(*events, store.Event{
			Kind: store.EventMACChanged,
			Message: fmt.Sprintf("%s is now answered by %s (was %s %s minutes ago). This can be a DHCP change, or ARP spoofing.",
				ip, d.MAC, other.MAC, fmt.Sprint(int(t.Sub(other.LastSeen).Minutes()))),
			Data: map[string]string{"ip": ip, "oldMac": other.MAC, "newMac": d.MAC},
		})
		return
	}
}

func (inv *Inventory) classify(ctx context.Context, d *store.Device) error {
	sig := fingerprint.Signals{Vendor: d.Vendor, Private: d.PrivateMAC}
	hosts, err := inv.Store.HostnameHistory(ctx, d.ID)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		sig.Hostnames = append(sig.Hostnames, h.Value)
	}
	svcs, err := inv.Store.Services(ctx, d.ID)
	if err != nil {
		return err
	}
	model := ""
	for _, s := range svcs {
		switch s.Source {
		case "mdns":
			sig.MDNS = append(sig.MDNS, s.Type)
			if s.Name != "" {
				sig.MDNSText = append(sig.MDNSText, s.Name)
			}
			for _, k := range []string{"md", "model", "am", "ty", "usb_mdl", "product"} {
				if v := s.Info[k]; v != "" {
					sig.MDNSText = append(sig.MDNSText, v)
					if model == "" {
						model = v
					}
				}
			}
		case "ssdp":
			sig.SSDP = append(sig.SSDP, s.Type, s.Name, s.Info["manufacturer"], s.Info["model"], s.Info["description"])
			if model == "" && s.Info["model"] != "" {
				model = strings.TrimSpace(s.Info["manufacturer"] + " " + s.Info["model"])
			}
		}
	}
	if v := d.Attrs["ssdp.server"]; v != "" {
		sig.SSDP = append(sig.SSDP, v)
	}
	ports, err := inv.Store.Ports(ctx, d.ID)
	if err != nil {
		return err
	}
	for _, p := range ports {
		if p.Open {
			sig.Ports = append(sig.Ports, p.Port)
			if p.Banner != "" {
				sig.Banners = append(sig.Banners, p.Banner)
			}
		}
	}
	g := inv.FP.Classify(sig)
	d.Type, d.TypeConfidence, d.TypeReasons = g.Type, g.Confidence, g.Reasons
	if model != "" {
		d.Model = model
	}
	return nil
}

// LiveHosts returns IPs of devices seen within window.
func (inv *Inventory) LiveHosts(window time.Duration) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ds, err := inv.Store.Devices(ctx)
	if err != nil {
		return nil
	}
	cutoff := time.Now().Add(-window)
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, d := range ds {
		if d.LastSeen.Before(cutoff) {
			continue
		}
		if ip, err := netip.ParseAddr(d.IP); err == nil && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Label is the best human name for a device.
func Label(d *store.Device) string {
	switch {
	case d.CustomName != "":
		return d.CustomName
	case d.Hostname != "":
		return d.Hostname
	case d.Model != "":
		return d.Model
	case d.Vendor != "":
		return d.Vendor + " device"
	case d.PrivateMAC:
		return "Device with private MAC"
	case d.IP != "":
		return d.IP
	default:
		return d.Key
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
}
