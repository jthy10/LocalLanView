package arpsweep

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jthy10/LocalLanView/internal/scan"
)

const resolverOnly = false

func resolveAll(context.Context, *scan.Env, func(scan.Observation)) error { return nil }

type bpf struct {
	fd      int
	buf     []byte
	pending []byte
}

// Open grabs a free /dev/bpf device and attaches it to iface.
func Open(iface net.Interface) (Transport, error) {
	var fd int
	var err error
	for i := 0; i < 256; i++ {
		fd, err = unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EBUSY) {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	fail := func(e error) (Transport, error) { unix.Close(fd); return nil, e }

	bufLen := 32768
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, bufLen); err != nil {
		return fail(err)
	}
	var ifr struct {
		name [unix.IFNAMSIZ]byte
		_    [16]byte
	}
	copy(ifr.name[:], iface.Name)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&ifr))); e != 0 {
		return fail(e)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return fail(err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSHDRCMPLT, 1); err != nil {
		return fail(err)
	}
	return &bpf{fd: fd, buf: make([]byte, bufLen)}, nil
}

func (b *bpf) Send(frame []byte) error {
	_, err := unix.Write(b.fd, frame)
	return err
}

func (b *bpf) Recv(timeout time.Duration) ([]byte, error) {
	if len(b.pending) == 0 {
		tv := unix.NsecToTimeval(timeout.Nanoseconds())
		if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(b.fd), uintptr(unix.BIOCSRTIMEOUT), uintptr(unsafe.Pointer(&tv))); e != 0 {
			return nil, e
		}
		n, err := unix.Read(b.fd, b.buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, errors.New("timeout")
		}
		b.pending = b.buf[:n]
	}
	// struct bpf_hdr { timeval32 tstamp; u32 caplen; u32 datalen; u16 hdrlen; }
	p := b.pending
	if len(p) < 18 {
		b.pending = nil
		return nil, errors.New("short bpf record")
	}
	caplen := int(*(*uint32)(unsafe.Pointer(&p[8])))
	hdrlen := int(*(*uint16)(unsafe.Pointer(&p[16])))
	if hdrlen+caplen > len(p) {
		b.pending = nil
		return nil, errors.New("truncated bpf record")
	}
	frame := append([]byte(nil), p[hdrlen:hdrlen+caplen]...)
	next := (hdrlen + caplen + 3) &^ 3
	if next >= len(p) {
		b.pending = nil
	} else {
		b.pending = p[next:]
	}
	return frame, nil
}

func (b *bpf) Close() error { return unix.Close(b.fd) }
