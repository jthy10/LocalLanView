// Package ports does light TCP connect probes against hosts that are already
// known to be up, and grabs whatever banner the service volunteers.
package ports

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jthy10/LocalLanView/internal/scan"
)

// Default is the list of ports probed on every live host.
var Default = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
	515: "lpd", 548: "afp", 554: "rtsp", 631: "ipp", 1400: "sonos",
	1883: "mqtt", 2049: "nfs", 3000: "http-dev", 3306: "mysql", 3389: "rdp",
	5000: "upnp/http", 5001: "https-alt", 5357: "wsd", 5432: "postgres",
	5900: "vnc", 6668: "tuya", 7000: "airplay", 8000: "http-alt",
	8008: "chromecast", 8009: "cast", 8080: "http-proxy", 8081: "http-alt",
	8123: "home-assistant", 8443: "https-alt", 8883: "mqtts", 9000: "http-alt",
	9100: "jetdirect", 10001: "ubiquiti", 32400: "plex", 49152: "upnp",
	62078: "iphone-sync",
}

var httpPorts = map[int]bool{80: true, 1400: true, 3000: true, 5000: true, 7000: true, 8000: true,
	8008: true, 8080: true, 8081: true, 8123: true, 9000: true, 32400: true, 49152: true}
var tlsPorts = map[int]bool{443: true, 5001: true, 8443: true}

type Collector struct {
	Ports       map[int]string // nil means Default
	DialTimeout time.Duration
	PerHost     int // max concurrent probes per host
	Disabled    bool
}

func (c *Collector) Name() string      { return "TCP port scan" }
func (c *Collector) Phase() scan.Phase { return scan.PhaseProbe }
func (c *Collector) Available(bool) (bool, string) {
	if c.Disabled {
		return false, "disabled with -no-port-scan"
	}
	return true, ""
}

func (c *Collector) Run(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	if env.LiveHosts == nil {
		return nil
	}
	pm := c.Ports
	if pm == nil {
		pm = Default
	}
	ports := make([]int, 0, len(pm))
	for p := range pm {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	perHost := c.PerHost
	if perHost <= 0 {
		perHost = 2
	}

	hostSem := make(chan struct{}, 16) // hosts scanned at once
	var wg sync.WaitGroup
	for _, ip := range env.LiveHosts() {
		if !env.Net.InScope(ip) {
			continue
		}
		select {
		case hostSem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-hostSem }()
			open := c.scanHost(ctx, env, ip, ports, pm, perHost)
			if ctx.Err() != nil {
				return
			}
			emit(scan.Observation{Source: "ports", Time: time.Now(), IP: ip, Ports: open, PortScan: true})
		}(ip)
	}
	wg.Wait()
	return ctx.Err()
}

func (c *Collector) scanHost(ctx context.Context, env *scan.Env, ip netip.Addr, ports []int, names map[int]string, perHost int) []scan.Port {
	timeout := c.DialTimeout
	if timeout == 0 {
		timeout = time.Second
	}
	var mu sync.Mutex
	var open []scan.Port
	sem := make(chan struct{}, perHost)
	var wg sync.WaitGroup
	for _, p := range ports {
		if env.Limiter.Wait(ctx) != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := netip.AddrPortFrom(ip, uint16(p)).String()
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp4", addr)
			if err != nil {
				return
			}
			banner := grab(conn, ip, p)
			conn.Close()
			mu.Lock()
			open = append(open, scan.Port{Port: p, Service: names[p], Banner: banner})
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

func grab(conn net.Conn, ip netip.Addr, port int) string {
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	switch {
	case tlsPorts[port]:
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: ip.String()}) // only reading the cert, not trusting it
		if err := tc.Handshake(); err != nil {
			return ""
		}
		certs := tc.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			return ""
		}
		cert := certs[0]
		s := "TLS cert CN=" + cert.Subject.CommonName
		if cert.Issuer.CommonName != "" && cert.Issuer.CommonName != cert.Subject.CommonName {
			s += ", issuer=" + cert.Issuer.CommonName
		} else if cert.Issuer.String() == cert.Subject.String() {
			s += " (self-signed)"
		}
		return Clean(s)
	case httpPorts[port]:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: LocalLanView\r\n\r\n", ip)
		r := bufio.NewReader(conn)
		status, err := r.ReadString('\n')
		if err != nil {
			return ""
		}
		out := strings.TrimSpace(status)
		for i := 0; i < 30; i++ {
			line, err := r.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "server") {
				out += " | Server: " + strings.TrimSpace(v)
			}
		}
		return Clean(out)
	default:
		buf := make([]byte, 256)
		conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, _ := conn.Read(buf)
		return Clean(string(buf[:n]))
	}
}

// Clean keeps a banner printable and short.
func Clean(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		b.WriteRune(r)
		if b.Len() >= 200 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}
