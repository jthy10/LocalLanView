package icmpsweep

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type socket struct {
	pc  *icmp.PacketConn
	udp bool // unprivileged datagram socket
	id  int
	buf []byte
}

// openSocket opens a raw ICMP socket ("ip4:icmp") or, with udp set, an
// unprivileged ICMP datagram socket (macOS, and Linux when
// net.ipv4.ping_group_range allows it).
func openSocket(local netip.Addr, udp bool) (Conn, error) {
	network := "ip4:icmp"
	if udp {
		network = "udp4"
	}
	pc, err := icmp.ListenPacket(network, local.String())
	if err != nil {
		return nil, err
	}
	return &socket{pc: pc, udp: udp, id: os.Getpid() & 0xffff, buf: make([]byte, 1500)}, nil
}

func (s *socket) Send(ip netip.Addr, seq int) error {
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: s.id, Seq: seq & 0xffff, Data: []byte("LocalLanView")},
	}
	b, err := m.Marshal(nil)
	if err != nil {
		return err
	}
	var dst net.Addr = &net.IPAddr{IP: ip.AsSlice()}
	if s.udp {
		dst = &net.UDPAddr{IP: ip.AsSlice()}
	}
	_, err = s.pc.WriteTo(b, dst)
	return err
}

func (s *socket) Recv(timeout time.Duration) (netip.Addr, error) {
	s.pc.SetReadDeadline(time.Now().Add(timeout))
	n, from, err := s.pc.ReadFrom(s.buf)
	if err != nil {
		return netip.Addr{}, err
	}
	m, err := icmp.ParseMessage(1, s.buf[:n])
	if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
		return netip.Addr{}, errors.New("not an echo reply")
	}
	if e, ok := m.Body.(*icmp.Echo); ok && !s.udp && e.ID != s.id {
		return netip.Addr{}, errors.New("not our echo")
	}
	var ip net.IP
	switch a := from.(type) {
	case *net.IPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, errors.New("bad source")
	}
	return addr.Unmap(), nil
}

func (s *socket) Close() error { return s.pc.Close() }
