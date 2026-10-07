package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	s := openTemp(t)
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %v, want 0600", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(s.Path()))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v, want 0700", di.Mode().Perm())
	}
}

func TestDeviceLifecycle(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	id, err := s.InsertDevice(ctx, &Device{Key: "mac:aa:bb:cc:dd:ee:ff", MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.0.5", FirstSeen: now, LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertDevice(ctx, &Device{Key: "mac:aa:bb:cc:dd:ee:ff", FirstSeen: now, LastSeen: now}); err == nil {
		t.Fatal("duplicate key should fail")
	}

	isNew, _ := s.TouchIP(ctx, id, "10.0.0.5", now)
	again, _ := s.TouchIP(ctx, id, "10.0.0.5", now.Add(time.Minute))
	if !isNew || again {
		t.Fatalf("TouchIP new=%v again=%v", isNew, again)
	}
	s.TouchHostname(ctx, id, "printer", "mdns", now)

	added, err := s.SetPorts(ctx, id, []Port{{Port: 80, Service: "http"}, {Port: 631}}, now)
	if err != nil || len(added) != 2 {
		t.Fatalf("SetPorts: %v %v", added, err)
	}
	added, _ = s.SetPorts(ctx, id, []Port{{Port: 631}, {Port: 9100}}, now)
	if len(added) != 1 || added[0] != 9100 {
		t.Fatalf("second scan added %v", added)
	}
	ports, _ := s.Ports(ctx, id)
	open := 0
	for _, p := range ports {
		if p.Open {
			open++
		}
	}
	if len(ports) != 3 || open != 2 {
		t.Fatalf("ports %+v", ports)
	}

	name, trusted, tags := "Office printer", true, []string{"office", " office ", "", "Printers"}
	if err := s.UpdateUser(ctx, id, UserFields{CustomName: &name, Trusted: &trusted, Tags: &tags}); err != nil {
		t.Fatal(err)
	}
	d, err := s.Device(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.CustomName != name || !d.Trusted || len(d.Tags) != 2 || len(d.OpenPorts) != 2 {
		t.Fatalf("device %+v", d)
	}
	ips, _ := s.IPHistory(ctx, id)
	hosts, _ := s.HostnameHistory(ctx, id)
	if len(ips) != 1 || len(hosts) != 1 || !ips[0].LastSeen.Equal(now.Add(time.Minute)) {
		t.Fatalf("history %+v %+v", ips, hosts)
	}

	if err := s.DeleteDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Device(ctx, id); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if ips, _ := s.IPHistory(ctx, id); len(ips) != 0 {
		t.Fatal("history should cascade")
	}
}

func TestMerge(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.Now()
	a, _ := s.InsertDevice(ctx, &Device{Key: "ip:10.0.0.9", IP: "10.0.0.9", FirstSeen: now.Add(-time.Hour), LastSeen: now})
	b, _ := s.InsertDevice(ctx, &Device{Key: "mac:00:11:22:33:44:55", FirstSeen: now, LastSeen: now})
	s.TouchIP(ctx, a, "10.0.0.9", now)
	n := "Mystery box"
	s.UpdateUser(ctx, a, UserFields{CustomName: &n})
	if err := s.MergeInto(ctx, a, b); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Device(ctx, b)
	ips, _ := s.IPHistory(ctx, b)
	if d.CustomName != n || len(ips) != 1 || !d.FirstSeen.Before(now.Add(-time.Minute)) {
		t.Fatalf("merged %+v %+v", d, ips)
	}
}

func TestEventsAndAuth(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	e := &Event{Time: time.Now(), Kind: EventNewDevice, Message: "hello"}
	if err := s.AddEvent(ctx, e); err != nil || e.ID == 0 {
		t.Fatal(err)
	}
	if n, _ := s.UnacknowledgedCount(ctx); n != 1 {
		t.Fatalf("count %d", n)
	}
	s.AckEvents(ctx, 0)
	if n, _ := s.UnacknowledgedCount(ctx); n != 0 {
		t.Fatalf("count after ack %d", n)
	}

	if _, err := s.Credentials(ctx); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	s.SetCredentials(ctx, Credentials{User: "admin", Hash: "x", Generated: true})
	s.SetCredentials(ctx, Credentials{User: "jake", Hash: "y"})
	c, err := s.Credentials(ctx)
	if err != nil || c.User != "jake" || c.Generated {
		t.Fatalf("creds %+v %v", c, err)
	}
}

func TestReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	s, _ := Open(path)
	s.SetSetting(context.Background(), "k", "v")
	s.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, _ := s.Setting(context.Background(), "k"); v != "v" {
		t.Fatalf("got %q", v)
	}
}
