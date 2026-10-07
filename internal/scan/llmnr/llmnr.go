// Package llmnr resolves host names with Link-Local Multicast Name
// Resolution reverse queries, which Windows answers when NetBIOS is off.
package llmnr

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/jthy10/LocalLanView/internal/scan"
)

type Collector struct {
	Port int // default 5355
	Wait time.Duration
}

func (c *Collector) Name() string                  { return "LLMNR" }
func (c *Collector) Phase() scan.Phase             { return scan.PhaseDiscover }
func (c *Collector) Available(bool) (bool, string) { return true, "" }

func (c *Collector) Run(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	port := c.Port
	if port == 0 {
		port = 5355
	}
	wait := c.Wait
	if wait == 0 {
		wait = 2 * time.Second
	}
	var mu sync.Mutex
	seen := map[netip.Addr]bool{}
	return scan.UDPProbe(ctx, env, env.Targets(), port, wait, Query,
		func(src netip.Addr, pkt []byte) {
			name := ParseReply(pkt)
			if name == "" {
				return
			}
			mu.Lock()
			dup := seen[src]
			seen[src] = true
			mu.Unlock()
			if !dup {
				emit(scan.Observation{Source: "llmnr", Time: time.Now(), IP: src, Hostname: name})
			}
		})
}

// Query builds a reverse (PTR) query for ip.
func Query(ip netip.Addr) []byte {
	a := ip.As4()
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: uint16(a[3])<<8 | uint16(a[2])},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", a[3], a[2], a[1], a[0])),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		}},
	}
	b, _ := m.Pack()
	return b
}

// ParseReply returns the host name from a PTR answer, or "".
func ParseReply(b []byte) string {
	var m dnsmessage.Message
	if m.Unpack(b) != nil || !m.Header.Response {
		return ""
	}
	for _, a := range m.Answers {
		if p, ok := a.Body.(*dnsmessage.PTRResource); ok {
			return strings.TrimSuffix(p.PTR.String(), ".")
		}
	}
	return ""
}
