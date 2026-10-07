// Package arptable reads the operating system's neighbor (ARP) cache. It
// works without any special privileges on every OS.
package arptable

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/jthy10/LocalLanView/internal/scan"
)

// Entry is one resolved neighbor.
type Entry struct {
	IP      netip.Addr
	MAC     net.HardwareAddr
	IfIndex int    // 0 if unknown
	IfName  string // "" if unknown
}

// Collector reads the ARP cache. With Prime set it first sends a single tiny
// UDP datagram to every address in the subnet so the OS resolves (ARPs) each
// one; that's how live hosts get into the table without raw sockets.
type Collector struct {
	Prime bool
	// read is swapped out in tests.
	read func() ([]Entry, error)
}

func (c *Collector) Name() string      { return "ARP table" }
func (c *Collector) Phase() scan.Phase { return scan.PhaseSweep }

func (c *Collector) Available(bool) (bool, string) {
	if !supported {
		return false, "reading the ARP table isn't supported on this OS"
	}
	return true, ""
}

func (c *Collector) Run(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	if c.Prime {
		prime(ctx, env)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second): // give ARP replies time to land
		}
	}
	read := c.read
	if read == nil {
		read = Read
	}
	entries, err := read()
	if err != nil {
		return err
	}
	now := time.Now()
	for _, e := range Filter(entries, env) {
		emit(scan.Observation{Source: "arp", Time: now, IP: e.IP, MAC: e.MAC})
	}
	return nil
}

// Filter keeps usable entries on the scanned interface and subnet.
func Filter(entries []Entry, env *scan.Env) []Entry {
	var out []Entry
	for _, e := range entries {
		if len(e.MAC) != 6 || isZero(e.MAC) || isBroadcast(e.MAC) || e.MAC[0]&1 == 1 {
			continue
		}
		if env.Net != nil {
			if !env.Net.InScope(e.IP) {
				continue
			}
			if e.IfIndex != 0 && e.IfIndex != env.Net.Iface.Index {
				continue
			}
			if e.IfName != "" && e.IfName != env.Net.Iface.Name {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func prime(ctx context.Context, env *scan.Env) {
	if env.Net == nil {
		return
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: env.Net.IP.AsSlice()})
	if err != nil {
		return
	}
	defer conn.Close()
	payload := []byte{0}
	for _, ip := range env.Net.Hosts() {
		if env.Limiter.Wait(ctx) != nil {
			return
		}
		// Port 9 is "discard"; nobody is expected to answer. The point is
		// the ARP request the OS sends first.
		conn.WriteToUDPAddrPort(payload, netip.AddrPortFrom(ip, 9))
	}
}

func isZero(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

func isBroadcast(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0xff {
			return false
		}
	}
	return true
}
