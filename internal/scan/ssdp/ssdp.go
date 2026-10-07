// Package ssdp discovers UPnP devices (routers, TVs, media servers, smart
// speakers) with SSDP M-SEARCH and reads their device descriptions.
package ssdp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/jthy10/LocalLanView/internal/scan"
)

type Collector struct {
	Group string // default 239.255.255.250:1900
	Wait  time.Duration
}

func (c *Collector) Name() string                  { return "SSDP / UPnP" }
func (c *Collector) Phase() scan.Phase              { return scan.PhaseDiscover }
func (c *Collector) Available(bool) (bool, string) { return true, "" }

type reply struct {
	server    string
	sts       map[string]bool
	locations []string
}

func (c *Collector) Run(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	group := c.Group
	if group == "" {
		group = "239.255.255.250:1900"
	}
	wait := c.Wait
	if wait == 0 {
		wait = 3 * time.Second
	}
	gaddr, err := net.ResolveUDPAddr("udp4", group)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: env.Net.IP.AsSlice()})
	if err != nil {
		return err
	}
	defer conn.Close()
	pc := ipv4.NewPacketConn(conn)
	_ = pc.SetMulticastInterface(&env.Net.Iface)
	_ = pc.SetMulticastTTL(2)

	for _, st := range []string{"ssdp:all", "upnp:rootdevice"} {
		msg := "M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\n" +
			"ST: " + st + "\r\n" +
			"USER-AGENT: LocalLanView/1 UPnP/1.1\r\n\r\n"
		if env.Limiter.Wait(ctx) != nil {
			return ctx.Err()
		}
		conn.WriteToUDP([]byte(msg), gaddr)
	}

	replies := map[netip.Addr]*reply{}
	deadline := time.Now().Add(wait)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		src := from.Addr().Unmap()
		if !env.Net.InScope(src) {
			continue
		}
		h, ok := parseResponse(buf[:n])
		if !ok {
			continue
		}
		r := replies[src]
		if r == nil {
			r = &reply{sts: map[string]bool{}}
			replies[src] = r
		}
		if s := h.Get("Server"); s != "" {
			r.server = s
		}
		if st := h.Get("St"); st != "" {
			r.sts[st] = true
		}
		if loc := h.Get("Location"); loc != "" && len(r.locations) < 3 && !contains(r.locations, loc) {
			r.locations = append(r.locations, loc)
		}
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		// Never follow redirects or use a proxy: descriptions are fetched
		// straight from the device on the local subnet only.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
	}
	now := time.Now()
	for ip, r := range replies {
		o := scan.Observation{Source: "ssdp", Time: now, IP: ip, Attrs: map[string]string{}}
		if r.server != "" {
			o.Attrs["ssdp.server"] = r.server
		}
		for _, loc := range r.locations {
			if ctx.Err() != nil {
				break
			}
			d, port, err := fetchDescription(ctx, client, env, loc)
			if err != nil {
				continue
			}
			for _, dev := range d.all() {
				info := map[string]string{}
				set := func(k, v string) {
					if v = strings.TrimSpace(v); v != "" {
						info[k] = truncate(v, 128)
					}
				}
				set("manufacturer", dev.Manufacturer)
				set("model", dev.ModelName)
				set("modelNumber", dev.ModelNumber)
				set("description", dev.ModelDescription)
				o.Services = append(o.Services, scan.Service{
					Source: "ssdp",
					Type:   strings.TrimSpace(dev.DeviceType),
					Name:   truncate(strings.TrimSpace(dev.FriendlyName), 128),
					Port:   port,
					Info:   info,
				})
			}
		}
		if len(o.Services) == 0 {
			for st := range r.sts {
				if strings.HasPrefix(st, "urn:") {
					o.Services = append(o.Services, scan.Service{Source: "ssdp", Type: st})
				}
			}
		}
		emit(o)
	}
	return nil
}

func parseResponse(b []byte) (http.Header, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil {
		// NOTIFY messages are requests, not responses.
		req, err2 := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
		if err2 != nil {
			return nil, false
		}
		return req.Header, true
	}
	resp.Body.Close()
	return resp.Header, true
}

type device struct {
	DeviceType       string   `xml:"deviceType"`
	FriendlyName     string   `xml:"friendlyName"`
	Manufacturer     string   `xml:"manufacturer"`
	ModelName        string   `xml:"modelName"`
	ModelNumber      string   `xml:"modelNumber"`
	ModelDescription string   `xml:"modelDescription"`
	Children         []device `xml:"deviceList>device"`
}

type description struct {
	Device device `xml:"device"`
}

func (d description) all() []device {
	out := []device{d.Device}
	// Embedded devices (e.g. a router's WANDevice) add little beyond the
	// root, so only keep ones with their own friendly name.
	for _, c := range d.Device.Children {
		if c.FriendlyName != "" && c.FriendlyName != d.Device.FriendlyName {
			out = append(out, c)
		}
	}
	return out
}

func fetchDescription(ctx context.Context, client *http.Client, env *scan.Env, loc string) (*description, int, error) {
	u, err := url.Parse(loc)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, 0, errors.New("bad location")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !env.Net.InScope(ip) {
		return nil, 0, errors.New("location is not on the local subnet")
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 80
	}
	if err := env.Limiter.Wait(ctx); err != nil {
		return nil, 0, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, errors.New(resp.Status)
	}
	var d description
	dec := xml.NewDecoder(io.LimitReader(resp.Body, 256<<10))
	dec.Strict = false
	if err := dec.Decode(&d); err != nil {
		return nil, 0, err
	}
	return &d, port, nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
