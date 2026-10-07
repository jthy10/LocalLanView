package arptable

import "os"

const supported = true

// Read returns the current ARP cache.
func Read() ([]Entry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcNetARP(f), nil
}
