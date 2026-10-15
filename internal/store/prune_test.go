package store

import (
	"context"
	"testing"
	"time"
)

func TestPrune(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.Now()
	day := 24 * time.Hour
	add := func(key string, private bool, lastSeen time.Time) int64 {
		t.Helper()
		id, err := s.InsertDevice(ctx, &Device{Key: key, IP: "10.0.0.9", PrivateMAC: private, FirstSeen: lastSeen, LastSeen: lastSeen})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	recent := add("mac:00:11:22:33:44:01", false, now.Add(-40*day))
	oldPrivate := add("mac:da:a1:19:00:00:01", true, now.Add(-40*day))
	oldIPOnly := add("ip:10.0.0.50", false, now.Add(-40*day))
	ancient := add("mac:00:11:22:33:44:02", false, now.Add(-400*day))
	named := add("mac:00:11:22:33:44:03", false, now.Add(-400*day))
	name := "Grandma's printer"
	if err := s.UpdateUser(ctx, named, UserFields{CustomName: &name}); err != nil {
		t.Fatal(err)
	}
	s.SetPorts(ctx, oldPrivate, []Port{{Port: 22}}, now.Add(-40*day))

	s.TouchIP(ctx, recent, "10.0.0.9", now.Add(-300*day)) // current IP, kept
	s.TouchIP(ctx, recent, "10.0.0.7", now.Add(-300*day)) // old IP, dropped
	s.TouchIP(ctx, recent, "10.0.0.8", now.Add(-10*day))
	s.UpsertService(ctx, recent, Service{Source: "mdns", Type: "_old._tcp"}, now.Add(-300*day))
	s.SetPorts(ctx, recent, []Port{{Port: 80}}, now.Add(-300*day))
	s.SetPorts(ctx, recent, []Port{{Port: 443}}, now.Add(-10*day)) // closes 80

	s.AddEvent(ctx, &Event{Time: now.Add(-100 * day), Kind: EventNewDevice, Message: "old"})
	s.AddEvent(ctx, &Event{Time: now.Add(-1 * day), Kind: EventNewDevice, Message: "new"})

	st, err := s.Prune(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.Devices != 3 || st.Events != 1 {
		t.Fatalf("stats %+v", st)
	}
	for id, want := range map[int64]bool{recent: true, oldPrivate: false, oldIPOnly: false, ancient: false, named: true} {
		if _, err := s.Device(ctx, id); (err == nil) != want {
			t.Errorf("device %d kept=%v, want %v", id, err == nil, want)
		}
	}
	ips, _ := s.IPHistory(ctx, recent)
	if len(ips) != 2 {
		t.Errorf("ip history %+v", ips)
	}
	if svcs, _ := s.Services(ctx, recent); len(svcs) != 0 {
		t.Errorf("services %+v", svcs)
	}
	if ports, _ := s.Ports(ctx, recent); len(ports) != 1 || ports[0].Port != 443 {
		t.Errorf("ports %+v", ports)
	}
	if evs, _ := s.Events(ctx, 0, 0); len(evs) != 1 || evs[0].Message != "new" {
		t.Errorf("events %+v", evs)
	}
	if _, err := s.Setting(ctx, "portscan:"+itoa(int(oldPrivate))); err != ErrNotFound {
		t.Errorf("port scan marker of a pruned device kept: %v", err)
	}
}

// A deleted device's id can be reused; the new device must not inherit the
// "already port scanned" marker, or its first ports would raise alerts.
func TestDeleteForgetsPortScan(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.Now()
	id, _ := s.InsertDevice(ctx, &Device{Key: "mac:00:11:22:33:44:01", FirstSeen: now, LastSeen: now})
	s.SetPorts(ctx, id, []Port{{Port: 22}}, now)
	if err := s.DeleteDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	id2, _ := s.InsertDevice(ctx, &Device{Key: "mac:00:11:22:33:44:02", FirstSeen: now, LastSeen: now})
	if id2 != id {
		t.Skipf("id not reused (%d, %d)", id, id2)
	}
	if scanned, _ := s.HasPortScan(ctx, id2); scanned {
		t.Fatal("new device inherited the deleted device's port scan marker")
	}
}
