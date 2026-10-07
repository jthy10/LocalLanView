package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Addr is a validated listen address for the web console.
type Addr struct {
	IP   netip.Addr
	Port int
}

func (a Addr) String() string {
	return netip.AddrPortFrom(a.IP, uint16(a.Port)).String()
}

// IsLoopback reports whether the console is only reachable from this machine.
// Unspecified addresses (0.0.0.0, ::) listen on every interface, so they are
// not loopback.
func (a Addr) IsLoopback() bool {
	return a.IP.IsLoopback()
}

// ParseAddr accepts "host:port", ":port", a bare "port", or a bracketed IPv6
// literal such as "[::1]:8787". The bare-port and ":port" forms bind to
// 127.0.0.1. Hosts must be IP literals or "localhost"; hostnames are rejected
// so it's always obvious which interface the console is exposed on.
func ParseAddr(s string) (Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Addr{}, fmt.Errorf("address is empty; expected host:port, :port or port (e.g. 127.0.0.1:8787)")
	}

	if isDigits(s) {
		p, err := parsePort(s)
		if err != nil {
			return Addr{}, err
		}
		return Addr{IP: netip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: p}, nil
	}

	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		if strings.Count(s, ":") > 1 && !strings.HasPrefix(s, "[") {
			return Addr{}, fmt.Errorf("invalid address %q: IPv6 addresses need brackets, e.g. [::1]:8787", s)
		}
		return Addr{}, fmt.Errorf("invalid address %q: expected host:port, :port or port (e.g. 127.0.0.1:8787)", s)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return Addr{}, fmt.Errorf("invalid address %q: %v", s, err)
	}

	var ip netip.Addr
	switch strings.ToLower(host) {
	case "":
		ip = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	case "localhost":
		ip = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	default:
		ip, err = netip.ParseAddr(host)
		if err != nil {
			return Addr{}, fmt.Errorf("invalid address %q: host must be an IP address or localhost, got %q", s, host)
		}
	}
	return Addr{IP: ip.Unmap(), Port: port}, nil
}

func parsePort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("port is missing")
	}
	if !isDigits(s) {
		return 0, fmt.Errorf("port %q is not a number", s)
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %s is out of range (1-65535)", s)
	}
	return p, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
