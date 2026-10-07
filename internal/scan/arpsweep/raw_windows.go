package arpsweep

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/jthy10/LocalLanView/internal/scan"
)

// On Windows SendARP does the work and needs no admin rights, so there is
// no raw transport.
const resolverOnly = true

var procSendARP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SendARP")

func Open(net.Interface) (Transport, error) { return nil, errors.New("not used on Windows") }

func sendARP(dst netip.Addr) (net.HardwareAddr, bool) {
	a := dst.As4()
	ip := *(*uint32)(unsafe.Pointer(&a[0]))
	var mac [8]byte
	n := uint32(len(mac))
	r, _, _ := procSendARP.Call(uintptr(ip), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&n)))
	if r != 0 || n != 6 {
		return nil, false
	}
	return net.HardwareAddr(append([]byte(nil), mac[:6]...)), true
}

func resolveAll(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	sem := make(chan struct{}, 32) // SendARP blocks for up to ~3s on silent hosts
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
			if mac, ok := sendARP(ip); ok {
				emit(scan.Observation{Source: "arp-sweep", Time: time.Now(), IP: ip, MAC: mac})
			}
		}(ip)
	}
	wg.Wait()
	return ctx.Err()
}
