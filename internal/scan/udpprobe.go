package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// UDPProbe sends one datagram to port on each target (rate limited) and
// passes every in-scope reply to handle until wait has passed after the
// last send.
func UDPProbe(ctx context.Context, env *Env, targets []netip.Addr, port int, wait time.Duration,
	packet func(ip netip.Addr) []byte, handle func(src netip.Addr, pkt []byte)) error {

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: env.Net.IP.AsSlice()})
	if err != nil {
		return err
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, ip := range targets {
			if !env.Net.InScope(ip) {
				continue
			}
			if env.Limiter.Wait(ctx) != nil {
				return
			}
			conn.WriteToUDPAddrPort(packet(ip), netip.AddrPortFrom(ip, uint16(port)))
		}
	}()

	buf := make([]byte, 2048)
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
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// ICMP port unreachable surfaces as a read error on some OSes.
			continue
		}
		src := from.Addr().Unmap()
		if env.Net.InScope(src) {
			handle(src, buf[:n])
		}
	}
}

// Targets returns live hosts if any are known, otherwise the whole subnet.
func (env *Env) Targets() []netip.Addr {
	if env.LiveHosts != nil {
		if h := env.LiveHosts(); len(h) > 0 {
			return h
		}
	}
	return env.Net.Hosts()
}
