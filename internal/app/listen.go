package app

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/jthy10/LocalLanView/internal/config"
)

// listen binds the console. A busy port is an error that names the
// conflict, unless fallback is set, in which case a free port is used.
func listen(a config.Addr, fallback bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", a.String())
	if err == nil {
		return ln, nil
	}
	if isAddrInUse(err) {
		if fallback {
			alt := a
			alt.Port = 0
			ln, err2 := net.Listen("tcp", alt.String())
			if err2 == nil {
				return ln, nil
			}
		}
		return nil, fmt.Errorf("port %d on %s is already in use by another program (maybe another LocalLanView?).\n"+
			"Pick a different one with -addr, e.g. -addr %s, or add -addr-fallback to use any free port", a.Port, a.IP, suggest(a))
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return nil, fmt.Errorf("not allowed to listen on %s (ports below 1024 usually need admin rights): %v", a, err)
	}
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		return nil, fmt.Errorf("%s isn't an address of this machine: %v", a.IP, err)
	}
	return nil, fmt.Errorf("listening on %s: %w", a, err)
}

func suggest(a config.Addr) string {
	alt := a
	if alt.Port < 65535 {
		alt.Port++
	} else {
		alt.Port--
	}
	return alt.String()
}

func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == 10048 // WSAEADDRINUSE
}
