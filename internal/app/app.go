// Package app wires every part of LocalLanView together and runs it.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jthy10/LocalLanView/internal/alert"
	"github.com/jthy10/LocalLanView/internal/auth"
	"github.com/jthy10/LocalLanView/internal/config"
	"github.com/jthy10/LocalLanView/internal/fingerprint"
	"github.com/jthy10/LocalLanView/internal/inventory"
	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/oui"
	"github.com/jthy10/LocalLanView/internal/privilege"
	"github.com/jthy10/LocalLanView/internal/scan"
	"github.com/jthy10/LocalLanView/internal/scan/arpsweep"
	"github.com/jthy10/LocalLanView/internal/scan/arptable"
	"github.com/jthy10/LocalLanView/internal/scan/icmpsweep"
	"github.com/jthy10/LocalLanView/internal/scan/llmnr"
	"github.com/jthy10/LocalLanView/internal/scan/mdns"
	"github.com/jthy10/LocalLanView/internal/scan/netbios"
	"github.com/jthy10/LocalLanView/internal/scan/ports"
	"github.com/jthy10/LocalLanView/internal/scan/ssdp"
	"github.com/jthy10/LocalLanView/internal/store"
	"github.com/jthy10/LocalLanView/internal/web"
	"github.com/jthy10/LocalLanView/ui"
)

// Options lets tests replace the outside world.
type Options struct {
	Version  string
	Stdout   io.Writer
	Stderr   io.Writer
	Stdin    *os.File
	Checker  privilege.Checker
	Network  *netinfo.Network // skip auto-detection
	Ready    func(url string) // called once the console is serving
	NoSignal bool
}

type scanState struct {
	mu        sync.Mutex
	Running   bool
	LastStart time.Time
	LastEnd   time.Time
	Interval  float64
}

func (s *scanState) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]any{"running": s.Running, "lastStart": s.LastStart, "interval": s.Interval}
	if !s.LastEnd.IsZero() {
		m["lastEnd"] = s.LastEnd
	}
	return m
}

// Run starts LocalLanView and blocks until ctx is cancelled or a signal
// arrives.
func Run(ctx context.Context, cfg *config.Config, opt Options) error {
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if opt.Stdin == nil {
		opt.Stdin = os.Stdin
	}
	if opt.Checker == nil {
		opt.Checker = privilege.OS
	}
	out := opt.Stdout
	log := slog.New(slog.NewTextHandler(opt.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	restrictUmask()

	// 1. Privileges.
	priv, err := privilege.Resolve(privilege.Mode(cfg.Mode), opt.Checker)
	if err != nil {
		return err
	}
	target, dropping, err := privilege.DropTarget(cfg.RunAs)
	if err != nil {
		return err
	}

	// 2. Network segment.
	nw := opt.Network
	if nw == nil {
		if nw, err = netinfo.Detect(cfg.Interface, cfg.Subnet); err != nil {
			return err
		}
	}

	// 3. Raw sockets, opened while we still have the rights to.
	sweep := &arpsweep.Collector{}
	if priv.Elevated {
		sweep.T, sweep.OpenErr = arpsweep.Open(nw.Iface)
	}
	icmp := icmpsweep.Open(nw.IP, priv.Elevated)

	// 4. Data directory and database.
	dataDir, defaultDir := cfg.DataDir, cfg.DataDir == ""
	if defaultDir {
		if dataDir, err = defaultDataDir(target, dropping); err != nil {
			return fmt.Errorf("finding a data directory: %w (use -data-dir)", err)
		}
	}
	createdDirs, err := makeDataDir(dataDir)
	if err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	if defaultDir || len(createdDirs) > 0 {
		// Leave the permissions of a directory the user picked alone.
		os.Chmod(dataDir, 0o700)
	}
	st, err := store.Open(filepath.Join(dataDir, "locallanview.db"))
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer st.Close()

	// 5. Console password.
	pw, src, err := passwordInput(cfg.PasswordFile, cfg.SetPassword, opt.Stdin, out)
	if err != nil {
		return err
	}
	cr, err := ensureCredentials(ctx, st, cfg.User, pw, src)
	if err != nil {
		return err
	}

	// 6. Exposure rules.
	var warnings []string
	if cfg.LANSet && cfg.LAN && cr.Creds.Generated {
		return fmt.Errorf("refusing to open the console to the network with the auto-generated password.\n"+
			"Set your own strong password first with -set-password, -password-file or %s", EnvPassword)
	}
	lan, err := lanWanted(ctx, st, cfg)
	if err != nil {
		return err
	}
	const heldBackWarning = "LAN access is on, but the console still uses the generated password, so it's only reachable from this machine. Set your own password, then turn LAN access on again under Settings."
	lanHeldBack := lan && cr.Creds.Generated
	if lanHeldBack {
		lan = false
		fmt.Fprintln(opt.Stderr, "WARNING: "+heldBackWarning)
	}
	if !cfg.Addr.IsLoopback() && cr.Creds.Generated {
		return fmt.Errorf("refusing to listen on %s: the console would be reachable from the network with the auto-generated password.\n"+
			"Set your own strong password first with -set-password, -password-file or %s", cfg.Addr, EnvPassword)
	}

	// 7. Bind the console, with TLS when asked for or when it's on the LAN.
	cons := &console{cfg: cfg, nw: nw, dataDir: dataDir, out: out, stderr: opt.Stderr, log: log, errs: make(chan error, 2)}
	if err := cons.bind(lan, 0, cfg.AddrFallback); err != nil {
		return err
	}
	defer cons.stop(context.Background())

	// 8. Drop root now that the sockets are open; they stay usable.
	if dropping {
		handBack(dataDir, createdDirs, defaultDir, target.UID, target.GID)
		if err := privilege.DropTo(target); err != nil {
			// Carrying on would run every network parser as root.
			return fmt.Errorf("could not drop root privileges: %w", err)
		}
		log.Info("dropped root privileges", "user", target.Name, "uid", target.UID, "via", target.Via)
	} else if privilege.IsRoot() {
		msg := "Running as root with no account to drop to, so every network parser runs as root. Start it with sudo, add -run-as USER, or use setcap on Linux."
		warnings = append(warnings, msg)
		fmt.Fprintln(opt.Stderr, "WARNING: "+msg)
	}

	// 9. Inventory, alerts, scanning.
	hub := alert.NewHub()
	var webhook *alert.Webhook
	if cfg.Webhook != "" {
		if webhook, err = alert.NewWebhook(cfg.Webhook); err != nil {
			return err
		}
	}
	inv := &inventory.Inventory{Store: st, OUI: oui.Default(), FP: fingerprint.Default(), Log: log, Self: nw.IP}
	inv.OnChange = func(id int64) { hub.Publish(alert.Message{Type: "device", Data: map[string]int64{"id": id}}) }
	inv.OnEvent = func(e store.Event, d *store.Device) {
		hub.Publish(alert.Message{Type: "event", Data: e})
		log.Info("alert", "kind", e.Kind, "msg", e.Message)
		if webhook != nil {
			go func() {
				c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := webhook.Send(c, map[string]any{"event": e, "device": d}); err != nil {
					log.Warn("webhook failed", "err", err)
				}
			}()
		}
		if cfg.Notify {
			go alert.Notify("LocalLanView", e.Message)
		}
	}
	gateway := ""
	if gw, ok := netinfo.Gateway(nw.Iface.Name); ok && nw.InScope(gw) {
		inv.Gateway = gw
		gateway = gw.String()
	}
	if _, err := st.Setting(ctx, "baseline_done"); errors.Is(err, store.ErrNotFound) {
		inv.SetBaseline(true)
	}

	liveWindow := 2*cfg.ScanInterval + time.Minute
	inv.LiveWindow = liveWindow
	env := &scan.Env{
		Net:       nw,
		Limiter:   scan.NewLimiter(cfg.ProbeRate),
		Elevated:  priv.Elevated,
		LiveHosts: func() []netip.Addr { return excludeSelf(inv.LiveHosts(liveWindow), nw) },
	}
	sweepOK, _ := sweep.Available(priv.Elevated)
	collectors := []scan.Collector{
		sweep,
		icmp,
		&arptable.Collector{Prime: !sweepOK},
		&mdns.Collector{},
		&ssdp.Collector{},
		&netbios.Collector{},
		&llmnr.Collector{},
		&ports.Collector{Disabled: cfg.NoPortScan},
	}
	ss := &scanState{Interval: cfg.ScanInterval.Seconds()}
	var lastPrune time.Time // OnCycle calls don't overlap
	engine := &scan.Engine{
		Collectors: collectors,
		Env:        env,
		Interval:   cfg.ScanInterval,
		Emit:       inv.Observe,
		Log:        log,
	}
	engine.OnCycle = func(running bool, started time.Time) {
		ss.mu.Lock()
		ss.Running = running
		if running {
			ss.LastStart = started
		} else {
			ss.LastEnd = time.Now()
		}
		ss.mu.Unlock()
		if !running {
			inv.FlushPending()
			if time.Since(lastPrune) > 24*time.Hour {
				lastPrune = time.Now()
				inv.Prune(lastPrune)
			}
			inv.SetBaseline(false)
			st.SetSetting(context.Background(), "baseline_done", "1")
		}
		hub.Publish(alert.Message{Type: "scan", Data: ss.snapshot()})
	}

	// 10. Web console.
	srv := &web.Server{
		Store:   st,
		Limiter: auth.NewLoginLimiter(),
		Hub:     hub,
		Static:  ui.FS(),
		Log:     log,
		ScanNow: engine.ScanNow,
	}
	generated := cr.Creds.Generated
	var genMu sync.Mutex
	srv.OnPasswordChange = func(g bool) { genMu.Lock(); generated = g; genMu.Unlock() }
	srv.SetLAN = func(ctx context.Context, on bool) (any, error) {
		genMu.Lock()
		g := generated
		genMu.Unlock()
		if on && g {
			return nil, ErrLANNeedsPassword
		}
		return cons.setLAN(ctx, st, on)
	}
	srv.Status = func(ctx context.Context) any {
		ds, _ := st.Devices(ctx)
		unread, _ := st.UnacknowledgedCount(ctx)
		online := 0
		for _, d := range ds {
			if time.Since(d.LastSeen) < liveWindow {
				online++
			}
		}
		genMu.Lock()
		g := generated
		genMu.Unlock()
		ci := cons.info()
		ws := append([]string(nil), warnings...)
		if !ci.Loopback && !ci.TLS {
			ws = append(ws, plainHTTPWarning)
		}
		if lanHeldBack && g {
			ws = append(ws, heldBackWarning)
		}
		return map[string]any{
			"version":           opt.Version,
			"network":           map[string]string{"interface": nw.Iface.Name, "ip": nw.IP.String(), "subnet": nw.Prefix.String(), "mac": nw.Iface.HardwareAddr.String(), "gateway": gateway},
			"privilege":         priv,
			"features":          engine.Features(),
			"scan":              ss.snapshot(),
			"console":           ci,
			"dbPath":            st.Path(),
			"devices":           len(ds),
			"online":            online,
			"unread":            unread,
			"generatedPassword": g,
			"warnings":          ws,
			"liveWindowSeconds": liveWindow.Seconds(),
		}
	}
	// Each listener gets its own copy of the server, with fresh sessions:
	// moving to or from the LAN changes the address and the scheme anyway.
	cons.handler = func(loopback bool, tlsCfg *tls.Config) http.Handler {
		s := *srv
		s.Sessions = auth.NewSessions(tlsCfg != nil)
		s.LoopbackOnly = loopback
		s.AllowedHosts = consoleHosts(cfg.AllowHosts, tlsCfg)
		return s.Handler()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !opt.NoSignal {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sig)
		go func() {
			select {
			case <-sig:
				fmt.Fprintln(out, "\nShutting down...")
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	cons.serve()
	ci := cons.info()
	printBanner(out, ci, cr, priv, nw, engine.Features(), dataDir)
	if opt.Ready != nil {
		opt.Ready(ci.URL)
	}
	if !cfg.NoOpenBrowser {
		openBrowser(ci.URL)
	}

	go engine.Run(ctx)

	select {
	case <-ctx.Done():
	case err := <-cons.errs:
		return fmt.Errorf("web console stopped: %w", err)
	}
	shutCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	cons.stop(shutCtx)
	return nil
}

// consoleHosts lists the names the console answers to besides IP literals
// and localhost: this machine's name (bare and .local), the TLS
// certificate's names and anything passed with -allow-host.
func consoleHosts(extra []string, tlsCfg *tls.Config) []string {
	hosts := append([]string(nil), extra...)
	if h, err := os.Hostname(); err == nil && h != "" {
		short, _, _ := strings.Cut(h, ".")
		hosts = append(hosts, h, short, short+".local")
	}
	if tlsCfg != nil {
		for _, c := range tlsCfg.Certificates {
			if c.Leaf == nil && len(c.Certificate) > 0 {
				c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
			}
			if c.Leaf != nil {
				hosts = append(hosts, c.Leaf.DNSNames...)
			}
		}
	}
	return hosts
}

func consoleURL(a *net.TCPAddr, tls bool) string {
	host := a.IP
	if host.IsUnspecified() {
		if host.To4() != nil {
			host = net.IPv4(127, 0, 0, 1)
		} else {
			host = net.IPv6loopback
		}
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host.String(), fmt.Sprint(a.Port)) + "/"
}

func printBanner(w io.Writer, ci consoleInfo, cr *credResult, priv privilege.Status, nw *netinfo.Network, feats []scan.Feature, dataDir string) {
	fmt.Fprintf(w, "\nLocalLanView is running\n\n")
	fmt.Fprintf(w, "  Dashboard:  %s\n", ci.URL)
	if ci.LANURL != "" {
		fmt.Fprintf(w, "  On your network: %s  (open it on any device on this network)\n", ci.LANURL)
	}
	fmt.Fprintf(w, "  Scanning:   %s on %s (this machine is %s)\n", nw.Prefix, nw.Iface.Name, nw.IP)
	mode := "standard"
	if priv.Elevated {
		mode = "elevated"
	}
	fmt.Fprintf(w, "  Mode:       %s (%s)\n", mode, priv.Reason)
	fmt.Fprintf(w, "  Data:       %s\n", dataDir)
	var off []string
	for _, f := range feats {
		if !f.Active {
			off = append(off, f.Name)
		}
	}
	if len(off) > 0 {
		fmt.Fprintf(w, "  Inactive:   %v (see the Capabilities page for why)\n", off)
	}
	switch {
	case cr.Generated != "":
		fmt.Fprintf(w, "\n  First run: log in as %q with this password. It is shown only once:\n\n", cr.Creds.User)
		fmt.Fprintf(w, "      %s\n\n", cr.Generated)
		fmt.Fprintf(w, "  Change it on the Settings page or with -set-password.\n")
	case cr.Changed:
		fmt.Fprintf(w, "\n  Console password updated from %s.\n", cr.Source)
	}
	fmt.Fprintln(w)
}

func excludeSelf(ips []netip.Addr, nw *netinfo.Network) []netip.Addr {
	out := ips[:0]
	for _, ip := range ips {
		if ip != nw.IP {
			out = append(out, ip)
		}
	}
	return out
}
