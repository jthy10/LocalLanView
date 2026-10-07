package oui

import (
	"net"
	"testing"
)

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLongestPrefix(t *testing.T) {
	db := &DB{}
	for i := range db.tables {
		db.tables[i] = map[uint64]string{}
	}
	db.Add(24, 0x70B3D5, "IEEE Registration Authority")
	db.Add(28, 0x70B3D51, "Medium Block Co")
	db.Add(36, 0x70B3D5022, "Small Block Co")

	tests := []struct {
		mac, vendor, reg string
	}{
		{"70:b3:d5:02:2a:bc", "Small Block Co", "MA-S"},
		{"70:b3:d5:1f:00:01", "Medium Block Co", "MA-M"},
		{"70:b3:d5:33:00:01", "IEEE Registration Authority", "MA-L"},
		{"00:11:22:33:44:55", "", ""},
	}
	for _, tt := range tests {
		r := db.Lookup(mustMAC(t, tt.mac))
		if r.Vendor != tt.vendor || r.Registry != tt.reg {
			t.Errorf("Lookup(%s) = %+v, want %s/%s", tt.mac, r, tt.vendor, tt.reg)
		}
	}
}

func TestPrivateMAC(t *testing.T) {
	tests := []struct {
		mac     string
		private bool
	}{
		{"da:a1:19:00:00:01", true}, // x2/x6/xA/xE second nibble
		{"02:00:00:00:00:01", true},
		{"a6:00:00:00:00:01", true},
		{"3e:00:00:00:00:01", true},
		{"00:03:93:00:00:01", false},
		{"f0:18:98:00:00:01", false},
	}
	for _, tt := range tests {
		r := Lookup(mustMAC(t, tt.mac))
		if r.Private != tt.private {
			t.Errorf("%s private = %v, want %v", tt.mac, r.Private, tt.private)
		}
		if tt.private && r.Label() != PrivateLabel {
			t.Errorf("%s label = %q, want %q", tt.mac, r.Label(), PrivateLabel)
		}
	}
}

func TestEmbeddedData(t *testing.T) {
	db := Default()
	if db.Len() < 30000 {
		t.Fatalf("embedded registry looks too small: %d entries", db.Len())
	}
	for i, n := range []int{len(db.tables[0]), len(db.tables[1]), len(db.tables[2])} {
		if n == 0 {
			t.Errorf("%s table is empty", blocks[i].reg)
		}
	}
	r := Lookup(mustMAC(t, "00:03:93:12:34:56"))
	if r.Vendor != "Apple, Inc." || r.Registry != "MA-L" {
		t.Errorf("Apple OUI lookup = %+v", r)
	}
	if got := Lookup(net.HardwareAddr{0, 0x11, 0x22}); got != (Result{}) {
		t.Errorf("short MAC should return empty result, got %+v", got)
	}
}

func TestLabelUnknown(t *testing.T) {
	if (Result{}).Label() != "Unknown vendor" {
		t.Fatal("unexpected label")
	}
}

func BenchmarkLookup(b *testing.B) {
	db := Default()
	mac, _ := net.ParseMAC("70:b3:d5:02:2a:bc")
	for i := 0; i < b.N; i++ {
		db.Lookup(mac)
	}
}
