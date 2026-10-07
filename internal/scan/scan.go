// Package scan defines the collector interface every discovery method
// implements, and the engine that runs them on a schedule.
package scan

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/jthy10/LocalLanView/internal/netinfo"
)

// Observation is the single unit of data collectors produce. Anything that
// learns about a device (scanners today; traffic or topology sources later)
// emits these and the inventory merges them.
type Observation struct {
	Source   string            `json:"source"`
	Time     time.Time         `json:"time"`
	IP       netip.Addr        `json:"ip"`
	MAC      net.HardwareAddr  `json:"mac,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
	Services []Service         `json:"services,omitempty"`
	Ports    []Port            `json:"ports,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	// PortScan is true when Ports is the complete result of a port scan of
	// this host, so ports missing from it can be marked closed.
	PortScan bool `json:"-"`
}

// Service is something a device advertises (mDNS, SSDP).
type Service struct {
	Source string            `json:"source"`         // mdns, ssdp
	Type   string            `json:"type"`           // _ipp._tcp, urn:schemas-upnp-org:device:MediaRenderer:1
	Name   string            `json:"name,omitempty"` // instance / friendly name
	Port   int               `json:"port,omitempty"`
	Info   map[string]string `json:"info,omitempty"` // TXT records, model, manufacturer...
}

// Port is an open TCP port found by probing.
type Port struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// Phase orders collectors within a scan cycle.
type Phase int

const (
	// PhaseSweep pokes every address so neighbors show up (ARP, ICMP).
	PhaseSweep Phase = iota
	// PhaseDiscover asks devices to describe themselves (mDNS, SSDP...).
	PhaseDiscover
	// PhaseProbe looks closer at hosts already known to be alive.
	PhaseProbe
)

// Env is what a collector gets to work with.
type Env struct {
	Net      *netinfo.Network
	Limiter  *Limiter
	Elevated bool
	// LiveHosts returns addresses believed to be up, for targeted probes.
	LiveHosts func() []netip.Addr
}

// Collector is one discovery method.
type Collector interface {
	Name() string
	Phase() Phase
	// Available says whether the collector can run here and, if not, why.
	Available(elevated bool) (ok bool, reason string)
	// Run does one active pass and returns when finished or ctx is done.
	Run(ctx context.Context, env *Env, emit func(Observation)) error
}

// Feature is a row in the "what's active" panel.
type Feature struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"`
}
