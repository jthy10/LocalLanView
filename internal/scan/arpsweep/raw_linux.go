package arpsweep

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jthy10/LocalLanView/internal/scan"
)

const resolverOnly = false

func resolveAll(context.Context, *scan.Env, func(scan.Observation)) error { return nil }

type packetConn struct {
	fd int
	to unix.SockaddrLinklayer
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Open creates an AF_PACKET socket bound to iface.
func Open(iface net.Interface) (Transport, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherTypeARP)))
	if err != nil {
		return nil, err
	}
	sll := unix.SockaddrLinklayer{Protocol: htons(etherTypeARP), Ifindex: iface.Index}
	if err := unix.Bind(fd, &sll); err != nil {
		unix.Close(fd)
		return nil, err
	}
	to := unix.SockaddrLinklayer{Protocol: htons(etherTypeARP), Ifindex: iface.Index, Halen: 6}
	copy(to.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	return &packetConn{fd: fd, to: to}, nil
}

func (p *packetConn) Send(frame []byte) error {
	return unix.Sendto(p.fd, frame, 0, &p.to)
}

func (p *packetConn) Recv(timeout time.Duration) ([]byte, error) {
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(p.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	buf := make([]byte, 1514)
	n, _, err := unix.Recvfrom(p.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, errors.New("empty read")
	}
	return buf[:n], nil
}

func (p *packetConn) Close() error { return unix.Close(p.fd) }
