// Package oui maps MAC addresses to vendors using the IEEE MA-L, MA-M and
// MA-S registries embedded in the binary.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/oui.tsv.gz
var data []byte

// PrivateLabel is shown instead of "unknown" for locally administered MACs.
const PrivateLabel = "Private/randomized address"

// Result describes what we know about a MAC address.
type Result struct {
	Vendor   string `json:"vendor,omitempty"`
	Registry string `json:"registry,omitempty"` // MA-L, MA-M or MA-S
	Private  bool   `json:"private"`            // locally administered bit set
}

// Label is a display string: vendor, the private label, or "Unknown vendor".
func (r Result) Label() string {
	switch {
	case r.Vendor != "":
		return r.Vendor
	case r.Private:
		return PrivateLabel
	default:
		return "Unknown vendor"
	}
}

// DB is a longest-prefix vendor table.
type DB struct {
	tables [3]map[uint64]string // 36, 28, 24 bit prefixes
}

var blocks = [3]struct {
	bits int
	reg  string
}{{36, "MA-S"}, {28, "MA-M"}, {24, "MA-L"}}

var (
	defaultOnce sync.Once
	defaultDB   *DB
)

// Default returns the embedded registry, parsed on first use.
func Default() *DB {
	defaultOnce.Do(func() {
		db, err := Load(data)
		if err != nil {
			panic("oui: embedded data is corrupt: " + err.Error())
		}
		defaultDB = db
	})
	return defaultDB
}

// Lookup is shorthand for Default().Lookup.
func Lookup(mac net.HardwareAddr) Result { return Default().Lookup(mac) }

// Load parses gzipped TSV lines of "bits<TAB>hexprefix<TAB>vendor".
func Load(gz []byte) (*DB, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	db := &DB{}
	for i := range db.tables {
		db.tables[i] = make(map[uint64]string)
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		bitsStr, rest, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		hex, name, ok := strings.Cut(rest, "\t")
		if !ok {
			continue
		}
		bits, err := strconv.Atoi(bitsStr)
		if err != nil {
			continue
		}
		p, err := strconv.ParseUint(hex, 16, 64)
		if err != nil || len(hex)*4 != bits {
			continue
		}
		db.Add(bits, p, name)
	}
	return db, sc.Err()
}

// Add registers a prefix of the given bit length (24, 28 or 36).
func (db *DB) Add(bits int, prefix uint64, vendor string) {
	for i, b := range blocks {
		if b.bits == bits {
			db.tables[i][prefix] = vendor
		}
	}
}

// Len returns the number of prefixes loaded.
func (db *DB) Len() int {
	n := 0
	for _, t := range db.tables {
		n += len(t)
	}
	return n
}

// Lookup finds the most specific registry entry for mac.
func (db *DB) Lookup(mac net.HardwareAddr) Result {
	if len(mac) != 6 {
		return Result{}
	}
	r := Result{Private: IsLocallyAdministered(mac)}
	v := uint64(mac[0])<<40 | uint64(mac[1])<<32 | uint64(mac[2])<<24 |
		uint64(mac[3])<<16 | uint64(mac[4])<<8 | uint64(mac[5])
	for i, b := range blocks {
		if name, ok := db.tables[i][v>>(48-b.bits)]; ok {
			r.Vendor, r.Registry = name, b.reg
			break
		}
	}
	// A locally administered address isn't registered to anyone, even if its
	// bytes happen to collide with a registry entry.
	if r.Private {
		r.Vendor, r.Registry = "", ""
	}
	return r
}

// IsLocallyAdministered reports whether the U/L bit is set, which is how
// phones and laptops mark randomized ("private") Wi-Fi addresses.
func IsLocallyAdministered(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&0x02 != 0
}

// IsMulticast reports whether the I/G bit is set.
func IsMulticast(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&0x01 != 0
}
