package icmpsweep

import (
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho   = iphlpapi.NewProc("IcmpSendEcho")
)

// Open uses a raw socket when elevated, otherwise IcmpSendEcho, which
// Windows allows for normal users.
func Open(local netip.Addr, elevated bool) *Collector {
	if elevated {
		if c, err := openSocket(local, false); err == nil {
			return &Collector{C: c, Mode: "raw"}
		}
	}
	h, _, err := procIcmpCreateFile.Call()
	if h == 0 || h == uintptr(windows.InvalidHandle) {
		return &Collector{OpenErr: err}
	}
	return &Collector{Mode: "unprivileged", Ping: func(ip netip.Addr, timeout time.Duration) bool {
		a := ip.As4()
		dst := *(*uint32)(unsafe.Pointer(&a[0]))
		data := []byte("LocalLanView")
		reply := make([]byte, 256)
		n, _, _ := procIcmpSendEcho.Call(h, uintptr(dst),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
		// ICMP_ECHO_REPLY: Address uint32, Status uint32 (0 = success)
		return n > 0 && binary.LittleEndian.Uint32(reply[4:]) == 0
	}}
}
