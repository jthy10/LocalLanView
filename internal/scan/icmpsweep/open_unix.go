//go:build !windows

package icmpsweep

import (
	"fmt"
	"net/netip"
)

// Open sets up the collector: a raw socket when elevated, otherwise an
// unprivileged ICMP socket if the OS allows one.
func Open(local netip.Addr, elevated bool) *Collector {
	if elevated {
		if c, err := openSocket(local, false); err == nil {
			return &Collector{C: c, Mode: "raw"}
		}
	}
	c, err := openSocket(local, true)
	if err != nil {
		return &Collector{OpenErr: fmt.Errorf("needs admin/root, or unprivileged ICMP (Linux: sysctl net.ipv4.ping_group_range): %v", err)}
	}
	return &Collector{C: c, Mode: "unprivileged"}
}
