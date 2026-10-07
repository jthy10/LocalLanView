package arptable

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const supported = true

var procGetIpNetTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpNetTable")

// Read returns the current ARP cache via GetIpNetTable.
func Read() ([]Entry, error) {
	var size uint32
	r, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && r != 0 {
		return nil, fmt.Errorf("GetIpNetTable: error %d", r)
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	r, _, _ = procGetIpNetTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		return nil, fmt.Errorf("GetIpNetTable: error %d", r)
	}
	return parseIPNetTable(buf[:size]), nil
}
