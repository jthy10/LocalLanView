package config

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	c, err := Parse(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr.String() != "127.0.0.1:8787" || c.Mode != "auto" || c.User != "admin" || c.ScanInterval != 5*time.Minute {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestParseDoubleDash(t *testing.T) {
	c, err := Parse([]string{"--addr", "9000", "--mode=std", "-no-open-browser"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr.String() != "127.0.0.1:9000" || c.Mode != "std" || !c.NoOpenBrowser {
		t.Fatalf("got %+v", c)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"-password", "hunter2"}, "process lists"},
		{[]string{"--password=hunter2"}, "process lists"},
		{[]string{"-mode", "root"}, "auto, std or elv"},
		{[]string{"-addr", "nope"}, "-addr"},
		{[]string{"-subnet", "10.0.0.0"}, "CIDR"},
		{[]string{"-tls-cert", "a.pem"}, "together"},
		{[]string{"-scan-interval", "1s"}, "at least"},
		{[]string{"stray"}, "unexpected argument"},
		{[]string{"-user", " "}, "empty"},
	}
	for _, tt := range tests {
		_, err := Parse(tt.args, io.Discard)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Parse(%v) = %v, want error containing %q", tt.args, err, tt.want)
		}
	}
}

func TestParseSubnetMasked(t *testing.T) {
	c, err := Parse([]string{"-subnet", "192.168.1.77/24"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subnet.String() != "192.168.1.0/24" {
		t.Fatalf("got %s", c.Subnet)
	}
}
