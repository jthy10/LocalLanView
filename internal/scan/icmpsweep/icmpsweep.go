// Package icmpsweep pings every address in the subnet.
package icmpsweep

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/jthy10/LocalLanView/internal/scan"
)

// Conn is an ICMP socket: send an echo request, receive echo replies.
type Conn interface {
	Send(ip netip.Addr, seq int) error
	Recv(timeout time.Duration) (netip.Addr, error)
	Close() error
}

// Collector pings the subnet with either an async socket (C) or a blocking
// per-host ping function (Ping, used by Windows' IcmpSendEcho).
type Collector struct {
	C       Conn
	Ping    func(ip netip.Addr, timeout time.Duration) bool
	Mode    string // "raw" or "unprivileged", shown in the UI
	OpenErr error
	Wait    time.Duration
}

func (c *Collector) Name() string      { return "ICMP ping sweep" }
func (c *Collector) Phase() scan.Phase { return scan.PhaseSweep }

func (c *Collector) Available(bool) (bool, string) {
	if c.C == nil && c.Ping == nil {
		if c.OpenErr != nil {
			return false, c.OpenErr.Error()
		}
		return false, "needs admin/root or unprivileged ICMP sockets"
	}
	if c.Mode == "unprivileged" {
		return true, "using unprivileged ICMP sockets"
	}
	return true, ""
}

func (c *Collector) Run(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	wait := c.Wait
	if wait == 0 {
		wait = 1500 * time.Millisecond
	}
	var mu sync.Mutex
	seen := map[netip.Addr]bool{}
	report := func(ip netip.Addr) {
		if !env.Net.InScope(ip) || ip == env.Net.IP {
			return
		}
		mu.Lock()
		dup := seen[ip]
		seen[ip] = true
		mu.Unlock()
		if !dup {
			emit(scan.Observation{Source: "icmp", Time: time.Now(), IP: ip})
		}
	}

	if c.Ping != nil {
		sem := make(chan struct{}, 32)
		var wg sync.WaitGroup
		for _, ip := range env.Net.Hosts() {
			if env.Limiter.Wait(ctx) != nil {
				break
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(ip netip.Addr) {
				defer wg.Done()
				defer func() { <-sem }()
				if c.Ping(ip, time.Second) {
					report(ip)
				}
			}(ip)
		}
		wg.Wait()
		return ctx.Err()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i, ip := range env.Net.Hosts() {
			if env.Limiter.Wait(ctx) != nil {
				return
			}
			c.C.Send(ip, i)
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
		ip, err := c.C.Recv(200 * time.Millisecond)
		if err == nil {
			report(ip)
		}
	}
}
