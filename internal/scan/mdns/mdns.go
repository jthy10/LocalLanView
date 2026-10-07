// Package mdns discovers devices through multicast DNS / DNS-SD (Bonjour,
// Avahi, Chromecast, HomeKit, printers...).
package mdns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"

	"github.com/jthy10/LocalLanView/internal/scan"
)

const enumType = "_services._dns-sd._udp.local."

// CommonTypes are always asked for, because not every responder answers
// the service enumeration query.
var CommonTypes = []string{
	"_http._tcp", "_https._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp",
	"_scanner._tcp", "_uscan._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp",
	"_spotify-connect._tcp", "_hap._tcp", "_homekit._tcp", "_smb._tcp", "_afpovertcp._tcp",
	"_ssh._tcp", "_sftp-ssh._tcp", "_device-info._tcp", "_companion-link._tcp", "_sonos._tcp",
	"_amzn-wplay._tcp", "_workstation._tcp", "_hue._tcp", "_matter._tcp", "_matterc._udp",
	"_esphomelib._tcp", "_home-assistant._tcp", "_octoprint._tcp", "_mqtt._tcp", "_rfb._tcp",
	"_androidtvremote2._tcp", "_nvstream._tcp", "_plexmediasvr._tcp", "_daap._tcp",
	"_apple-mobdev2._tcp", "_adisk._tcp", "_sleep-proxy._udp", "_miio._udp", "_shelly._tcp",
	"_elg._tcp", "_meshcop._udp", "_trel._udp", "_rdlink._tcp", "_touch-able._tcp",
}

// Collector sends mDNS queries and listens for answers.
type Collector struct {
	// Group and UnicastPort default to 224.0.0.251:5353 and 5353; tests
	// point them at a fake responder.
	Group       string
	UnicastPort int
	Wait        time.Duration
}

func (c *Collector) Name() string                  { return "mDNS / Bonjour" }
func (c *Collector) Phase() scan.Phase              { return scan.PhaseDiscover }
func (c *Collector) Available(bool) (bool, string) { return true, "" }

type instance struct {
	typ, name, host string
	port            int
	txt             map[string]string
	from            netip.Addr
}

type state struct {
	types     map[string]bool
	instances map[string]*instance // full instance name -> data
	hostIPs   map[string]netip.Addr
	ipNames   map[netip.Addr]string
	seen      map[netip.Addr]bool
}

func (c *Collector) Run(ctx context.Context, env *scan.Env, emit func(scan.Observation)) error {
	group := c.Group
	if group == "" {
		group = "224.0.0.251:5353"
	}
	uport := c.UnicastPort
	if uport == 0 {
		uport = 5353
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
	_ = pc.SetMulticastTTL(255)

	st := &state{
		types:     map[string]bool{},
		instances: map[string]*instance{},
		hostIPs:   map[string]netip.Addr{},
		ipNames:   map[netip.Addr]string{},
		seen:      map[netip.Addr]bool{},
	}
	send := func(to *net.UDPAddr, qs []dnsmessage.Question) {
		for len(qs) > 0 {
			n := min(len(qs), 20)
			if b, err := query(qs[:n]); err == nil && env.Limiter.Wait(ctx) == nil {
				conn.WriteToUDP(b, to)
			}
			qs = qs[n:]
		}
	}

	qs := []dnsmessage.Question{ptrQ(enumType)}
	for _, t := range CommonTypes {
		st.types[t+".local."] = true
		qs = append(qs, ptrQ(t+".local."))
	}
	send(gaddr, qs)

	// Reverse lookups go straight to each live host; Apple devices, Linux
	// boxes running Avahi and many IoT devices answer with their name.
	if env.LiveHosts != nil {
		go func() {
			for _, ip := range env.LiveHosts() {
				if ctx.Err() != nil {
					return
				}
				send(&net.UDPAddr{IP: ip.AsSlice(), Port: uport}, []dnsmessage.Question{ptrQ(reverseName(ip))})
			}
		}()
	}

	deadline := time.Now().Add(wait)
	buf := make([]byte, 9000)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		src := from.Addr().Unmap()
		if !env.Net.InScope(src) {
			continue
		}
		newTypes := st.handle(buf[:n], src)
		if len(newTypes) > 0 {
			var qs []dnsmessage.Question
			for _, t := range newTypes {
				qs = append(qs, ptrQ(t))
			}
			send(gaddr, qs)
		}
	}

	for _, o := range st.observations(env) {
		emit(o)
	}
	return nil
}

func (st *state) handle(pkt []byte, src netip.Addr) (newTypes []string) {
	var m dnsmessage.Message
	if err := m.Unpack(pkt); err != nil || !m.Header.Response {
		return nil
	}
	st.seen[src] = true
	rrs := append(append(m.Answers, m.Additionals...), m.Authorities...)
	for _, rr := range rrs {
		name := strings.ToLower(rr.Header.Name.String())
		rawName := rr.Header.Name.String()
		switch b := rr.Body.(type) {
		case *dnsmessage.PTRResource:
			target := b.PTR.String()
			switch {
			case name == enumType:
				t := strings.ToLower(target)
				if !st.types[t] {
					st.types[t] = true
					newTypes = append(newTypes, t)
				}
			case strings.HasSuffix(name, ".in-addr.arpa."):
				if ip, ok := parseReverse(name); ok {
					st.ipNames[ip] = trimLocal(target)
				}
			default:
				st.inst(target, src).typ = rawName
			}
		case *dnsmessage.SRVResource:
			in := st.inst(rawName, src)
			in.host = strings.ToLower(b.Target.String())
			in.port = int(b.Port)
		case *dnsmessage.TXTResource:
			in := st.inst(rawName, src)
			for _, kv := range b.TXT {
				if len(in.txt) >= 24 {
					break
				}
				k, v, _ := strings.Cut(kv, "=")
				if k == "" {
					continue
				}
				if len(v) > 128 {
					v = v[:128]
				}
				in.txt[strings.ToLower(k)] = v
			}
		case *dnsmessage.AResource:
			ip := netip.AddrFrom4(b.A)
			st.hostIPs[name] = ip
			if _, ok := st.ipNames[ip]; !ok {
				st.ipNames[ip] = trimLocal(name)
			}
		}
	}
	return newTypes
}

func (st *state) inst(full string, src netip.Addr) *instance {
	key := strings.ToLower(full)
	in, ok := st.instances[key]
	if !ok {
		in = &instance{name: full, txt: map[string]string{}, from: src}
		st.instances[key] = in
	}
	return in
}

func (st *state) observations(env *scan.Env) []scan.Observation {
	now := time.Now()
	byIP := map[netip.Addr]*scan.Observation{}
	get := func(ip netip.Addr) *scan.Observation {
		o, ok := byIP[ip]
		if !ok {
			o = &scan.Observation{Source: "mdns", Time: now, IP: ip}
			byIP[ip] = o
		}
		return o
	}
	for _, in := range st.instances {
		if in.typ == "" {
			in.typ = guessType(in.name)
		}
		if in.typ == "" {
			continue
		}
		ip := in.from
		if a, ok := st.hostIPs[in.host]; ok && env.Net.InScope(a) {
			ip = a
		}
		o := get(ip)
		svc := scan.Service{
			Source: "mdns",
			Type:   strings.TrimSuffix(strings.TrimSuffix(in.typ, "."), ".local"),
			Name:   instanceLabel(in.name, in.typ),
			Port:   in.port,
		}
		if len(in.txt) > 0 {
			svc.Info = in.txt
		}
		o.Services = append(o.Services, svc)
		if o.Hostname == "" && in.host != "" {
			o.Hostname = trimLocal(in.host)
		}
	}
	for ip, name := range st.ipNames {
		if !env.Net.InScope(ip) {
			continue
		}
		o := get(ip)
		if o.Hostname == "" {
			o.Hostname = name
		}
	}
	for ip := range st.seen {
		get(ip)
	}
	out := make([]scan.Observation, 0, len(byIP))
	for _, o := range byIP {
		out = append(out, *o)
	}
	return out
}

// guessType recovers the service type from an instance name like
// "Office Printer._ipp._tcp.local." when no PTR record named it.
func guessType(full string) string {
	l := strings.ToLower(full)
	for _, proto := range []string{"._tcp.local.", "._udp.local."} {
		i := strings.Index(l, proto)
		if i < 0 {
			continue
		}
		j := strings.LastIndex(l[:i], "._")
		if j < 0 {
			return ""
		}
		return full[j+1 : i+len(proto)]
	}
	return ""
}

func instanceLabel(full, typ string) string {
	if strings.HasSuffix(strings.ToLower(full), "."+strings.ToLower(typ)) {
		full = full[:len(full)-len(typ)-1]
	}
	return strings.ReplaceAll(full, `\ `, " ")
}

func trimLocal(s string) string {
	s = strings.TrimSuffix(s, ".")
	return strings.TrimSuffix(s, ".local")
}

func ptrQ(name string) dnsmessage.Question {
	return dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}
}

func query(qs []dnsmessage.Question) ([]byte, error) {
	m := dnsmessage.Message{Questions: qs}
	return m.Pack()
}

func reverseName(ip netip.Addr) string {
	a := ip.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", a[3], a[2], a[1], a[0])
}

func parseReverse(name string) (netip.Addr, bool) {
	parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa."), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0])
	return ip, err == nil
}
