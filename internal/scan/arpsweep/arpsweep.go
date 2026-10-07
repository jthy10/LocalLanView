// Package arpsweep sends ARP requests to every address in the subnet. This
// finds devices that ignore everything else, but needs raw socket access
// (root/CAP_NET_RAW on Linux, root on macOS). On Windows it uses SendARP,
// which works without admin rights.
package arpsweep

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jthy10/LocalLanView/internal/scan"
)

// Transport sends and receives raw Ethernet frames.
type Transport interface {
	Send(frame []byte) error
	// Recv returns the next frame or an error after timeout.
	Recv(timeout time.Duration) ([]byte, error)
	Close() error
}

// Collector runs the sweep. Open the transport before dropping privileges.
type Collector struct {
	T       Transport
	OpenErr error
	Wait    time.Duration
}

func (c *Collector) Name() string      { return "ARP sweep" }
func (c *Collector) Phase() scan.Phase { return scan.PhaseSweep }

func (c *Collector) Available(elevated bool) (bool, string) {
	if resolverOnly {
		return true, ""
	}
	if !elevated {
		return false, "needs admin/root (raw sockets); rerun with -mode elv or sudo"
	}
	if c.T == nil {
		if c.OpenErr != nil {
			return false, "could not open raw socket: " + c.OpenErr.Error()
		}
		return false, "raw socket not opened"
	}
	return true, ""
}

func (c *Collector) Run(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	if resolverOnly {
		return resolveAll(ctx, env, emit)
	}
	wait := c.Wait
	if wait == 0 {
		wait = 2 * time.Second
	}
	mac := env.Net.Iface.HardwareAddr
	if len(mac) != 6 {
		return nil
	}

	var mu sync.Mutex
	seen := map[netip.Addr]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, ip := range env.Net.Hosts() {
			if env.Limiter.Wait(ctx) != nil {
				return
			}
			c.T.Send(BuildRequest(mac, env.Net.IP, ip))
		}
	}()

	var deadline time.Time
	for {
		if deadline.IsZero() {
			select {
			case <-done:
				deadline = time.Now().Add(wait)
			default:
			}
		} else if time.Now().After(deadline) {
			return nil
		}
		if ctx.Err() != nil {
			<-done
			return ctx.Err()
		}
		frame, err := c.T.Recv(200 * time.Millisecond)
		if err != nil {
			continue
		}
		ip, hw, ok := ParseReply(frame)
		if !ok || !env.Net.InScope(ip) || ip == env.Net.IP || isOwn(hw, mac) {
			continue
		}
		mu.Lock()
		dup := seen[ip]
		seen[ip] = true
		mu.Unlock()
		if !dup {
			emit(scan.Observation{Source: "arp-sweep", Time: time.Now(), IP: ip, MAC: hw})
		}
	}
}

func isOwn(a, b net.HardwareAddr) bool { return a.String() == b.String() }
