// Command ouigen builds internal/oui/data/oui.tsv.gz from the IEEE registry.
//
// Download the IEEE CSVs once (this is the only step that touches the network,
// and it only happens when a developer refreshes the data):
//
//	https://standards-oui.ieee.org/oui/oui.csv        (MA-L)
//	https://standards-oui.ieee.org/oui28/mam.csv      (MA-M)
//	https://standards-oui.ieee.org/oui36/oui36.csv    (MA-S)
//	https://standards-oui.ieee.org/iab/iab.csv        (IAB, legacy 36-bit)
//
// then run:
//
//	go run ./tools/ouigen -o internal/oui/data/oui.tsv.gz oui.csv mam.csv oui36.csv iab.csv
//
// Wireshark's generated epan/manuf-data.c (built from the same IEEE files) is
// accepted as an input too, which is handy when the IEEE site is unreachable.
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
)

type entry struct {
	bits   int
	prefix string // uppercase hex, bits/4 digits
	name   string
}

func main() {
	out := flag.String("o", "internal/oui/data/oui.tsv.gz", "output file")
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("usage: ouigen -o out.tsv.gz <ieee csv files or manuf-data.c>")
	}

	seen := map[string]entry{}
	for _, path := range flag.Args() {
		var es []entry
		var err error
		if strings.HasSuffix(path, ".c") {
			es, err = readWireshark(path)
		} else {
			es, err = readIEEE(path)
		}
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		for _, e := range es {
			seen[fmt.Sprintf("%d/%s", e.bits, e.prefix)] = e
		}
		log.Printf("%s: %d entries", path, len(es))
	}

	all := make([]entry, 0, len(seen))
	for _, e := range seen {
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].bits != all[j].bits {
			return all[i].bits < all[j].bits
		}
		return all[i].prefix < all[j].prefix
	})

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	// Zero header fields keep the output byte-for-byte reproducible.
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	w := bufio.NewWriter(zw)
	for _, e := range all {
		fmt.Fprintf(w, "%d\t%s\t%s\n", e.bits, e.prefix, e.name)
	}
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d entries to %s", len(all), *out)
}

func readIEEE(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	var out []entry
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 3 || rec[0] == "Registry" {
			continue
		}
		reg, hex, name := rec[0], strings.ToUpper(strings.TrimSpace(rec[1])), clean(rec[2])
		var bits int
		switch reg {
		case "MA-L":
			bits = 24
		case "MA-M":
			bits = 28
		case "MA-S", "IAB":
			bits = 36
		default:
			continue // CID and friends aren't MAC address blocks
		}
		if len(hex) != bits/4 || name == "" {
			continue
		}
		out = append(out, entry{bits, hex, name})
	}
	return out, nil
}

var wsLine = regexp.MustCompile(`^\s*\{ \{ ([0-9A-Fa-fx, ]+) \}, "(?:[^"\\]|\\.)*",\s*"((?:[^"\\]|\\.)*)" \},`)

func readWireshark(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := wsLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var hex strings.Builder
		parts := strings.Split(m[1], ",")
		for _, p := range parts {
			hex.WriteString(strings.ToUpper(strings.TrimPrefix(strings.TrimSpace(p), "0x")))
		}
		h := hex.String()
		var bits int
		switch len(parts) {
		case 3:
			bits = 24
		case 4:
			bits = 28
		case 5:
			bits = 36
		default:
			continue
		}
		name := clean(strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(m[2]))
		if strings.HasPrefix(name, "Officially Xerox") {
			name = "Xerox Corporation"
		}
		if name == "" {
			continue
		}
		out = append(out, entry{bits, h[:bits/4], name})
	}
	return out, sc.Err()
}

func clean(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}
