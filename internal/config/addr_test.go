package config

import (
	"strings"
	"testing"
)

func TestParseAddr(t *testing.T) {
	tests := []struct {
		in       string
		want     string
		loopback bool
	}{
		{"8787", "127.0.0.1:8787", true},
		{":9000", "127.0.0.1:9000", true},
		{"127.0.0.1:8787", "127.0.0.1:8787", true},
		{"localhost:80", "127.0.0.1:80", true},
		{"[::1]:8787", "[::1]:8787", true},
		{"0.0.0.0:8787", "0.0.0.0:8787", false},
		{"[::]:8787", "[::]:8787", false},
		{"192.168.1.10:8080", "192.168.1.10:8080", false},
		{"[fe80::1%eth0]:8787", "[fe80::1%eth0]:8787", false},
		{" 8787 ", "127.0.0.1:8787", true},
		{"[::ffff:127.0.0.1]:1", "127.0.0.1:1", true},
	}
	for _, tt := range tests {
		a, err := ParseAddr(tt.in)
		if err != nil {
			t.Errorf("ParseAddr(%q) error: %v", tt.in, err)
			continue
		}
		if a.String() != tt.want {
			t.Errorf("ParseAddr(%q) = %s, want %s", tt.in, a, tt.want)
		}
		if a.IsLoopback() != tt.loopback {
			t.Errorf("ParseAddr(%q).IsLoopback() = %v, want %v", tt.in, a.IsLoopback(), tt.loopback)
		}
	}
}

func TestParseAddrErrors(t *testing.T) {
	tests := []struct {
		in      string
		errPart string
	}{
		{"", "empty"},
		{"0", "out of range"},
		{"70000", "out of range"},
		{"127.0.0.1", "expected host:port"},
		{"127.0.0.1:", "port is missing"},
		{"127.0.0.1:http", "not a number"},
		{"::1:8787", "need brackets"},
		{"example.com:8787", "IP address or localhost"},
		{"[::1]:-5", "not a number"},
		{"1.2.3.4.5:80", "IP address or localhost"},
	}
	for _, tt := range tests {
		_, err := ParseAddr(tt.in)
		if err == nil {
			t.Errorf("ParseAddr(%q) succeeded, want error", tt.in)
			continue
		}
		if !strings.Contains(err.Error(), tt.errPart) {
			t.Errorf("ParseAddr(%q) error %q, want it to mention %q", tt.in, err, tt.errPart)
		}
	}
}
