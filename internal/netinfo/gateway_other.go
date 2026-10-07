//go:build !linux && !darwin

package netinfo

import "net/netip"

// Gateway isn't implemented here yet; routers are still recognized from
// UPnP, vendor and open-port signals.
func Gateway(string) (netip.Addr, bool) { return netip.Addr{}, false }
