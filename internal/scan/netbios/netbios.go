// Package netbios asks hosts for their NetBIOS name table (NBSTAT), which
// Windows machines, Samba servers and many NAS boxes answer.
package netbios

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jthy10/LocalLanView/internal/scan"
)

type Collector struct {
	Port int // default 137
	Wait time.Duration
}

func (c *Collector) Name() string                  { return "NetBIOS" }
func (c *Collector) Phase() scan.Phase             { return scan.PhaseDiscover }
func (c *Collector) Available(bool) (bool, string) { return true, "" }

func (c *Collector) Run(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	port := c.Port
	if port == 0 {
		port = 137
	}
	wait := c.Wait
	if wait == 0 {
		wait = 2 * time.Second
	}
	var mu sync.Mutex
	seen := map[netip.Addr]bool{}
	req := Request(0x4c4c)
	return scan.UDPProbe(ctx, env, env.Targets(), port, wait,
		func(netip.Addr) []byte { return req },
		func(src netip.Addr, pkt []byte) {
			r, err := Parse(pkt)
			if err != nil || r.Name == "" {
				return
			}
			mu.Lock()
			dup := seen[src]
			seen[src] = true
			mu.Unlock()
			if dup {
				return
			}
			o := scan.Observation{Source: "netbios", Time: time.Now(), IP: src, Hostname: r.Name, Attrs: map[string]string{}}
			if r.Workgroup != "" {
				o.Attrs["netbios.workgroup"] = r.Workgroup
			}
			if r.Server {
				o.Attrs["netbios.fileserver"] = "true"
			}
			if r.MAC != nil {
				o.MAC = r.MAC
			}
			emit(o)
		})
}

// Request builds an NBSTAT query for the wildcard name "*".
func Request(id uint16) []byte {
	b := make([]byte, 0, 50)
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) // flags, QD=1, AN/NS/AR=0
	b = append(b, 0x20)
	name := [16]byte{'*'}
	for _, c := range name {
		b = append(b, 'A'+c>>4, 'A'+c&0x0f)
	}
	b = append(b, 0)
	b = append(b, 0, 0x21, 0, 1) // NBSTAT, IN
	return b
}

// Result is the useful part of a node status response.
type Result struct {
	Name      string
	Workgroup string
	Server    bool // has the 0x20 file server service
	MAC       net.HardwareAddr
}

var errShort = errors.New("netbios: short packet")

// Parse decodes a node status response.
func Parse(b []byte) (Result, error) {
	var r Result
	if len(b) < 12 || b[2]&0x80 == 0 { // must be a response
		return r, errShort
	}
	if binary.BigEndian.Uint16(b[6:]) == 0 { // ANCOUNT
		return r, errShort
	}
	off := 12
	// answer name
	for off < len(b) {
		l := int(b[off])
		if l&0xc0 == 0xc0 {
			off += 2
			break
		}
		off++
		if l == 0 {
			break
		}
		off += l
	}
	if off+10 > len(b) {
		return r, errShort
	}
	if binary.BigEndian.Uint16(b[off:]) != 0x21 {
		return r, errors.New("netbios: not an NBSTAT answer")
	}
	off += 10 // type, class, ttl, rdlength
	if off >= len(b) {
		return r, errShort
	}
	n := int(b[off])
	off++
	for i := 0; i < n; i++ {
		if off+18 > len(b) {
			return r, errShort
		}
		raw := b[off : off+15]
		suffix := b[off+15]
		flags := binary.BigEndian.Uint16(b[off+16:])
		off += 18
		name := strings.TrimRight(string(raw), " \x00")
		group := flags&0x8000 != 0
		switch {
		case suffix == 0x00 && !group && r.Name == "":
			r.Name = name
		case suffix == 0x00 && group && r.Workgroup == "":
			r.Workgroup = name
		case suffix == 0x20 && !group:
			r.Server = true
			if r.Name == "" {
				r.Name = name
			}
		}
	}
	if off+6 <= len(b) {
		mac := net.HardwareAddr(append([]byte(nil), b[off:off+6]...))
		zero := true
		for _, x := range mac {
			if x != 0 {
				zero = false
			}
		}
		if !zero {
			r.MAC = mac
		}
	}
	return r, nil
}
