// Package app wires every part of LocalLanView together and runs it.
package app

import (
	"context"
	"crypto/tls"
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
	dataDir := cfg.DataDir
	if dataDir == "" {
		if dataDir, err = defaultDataDir(); err != nil {
			return fmt.Errorf("finding a data directory: %w (use -data-dir)", err)
		}
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	os.Chmod(dataDir, 0o700)
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
	if !cfg.Addr.IsLoopback() {
		if cr.Creds.Generated {
			return fmt.Errorf("refusing to listen on %s: the console would be reachable from the network with the auto-generated password.\n"+
				"Set your own strong password first with -set-password, -password-file or %s", cfg.Addr, EnvPassword)
		}
		if !cfg.TLS() {
			msg := "The console is reachable from the network over plain HTTP; logins and the device list can be sniffed. Use -tls-self-signed or -tls-cert/-tls-key."
			warnings = append(warnings, msg)
			fmt.Fprintln(opt.Stderr, "WARNING: "+msg)
		}
	}

	// 7. TLS.
	var tlsCfg *tls.Config
	switch {
	case cfg.TLSCert != "":
		c, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("loading TLS certificate: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
	case cfg.TLSSelfSigned:
		ips := []net.IP{nw.IP.AsSlice()}
		if !cfg.Addr.IP.IsUnspecified() {
			ips = append(ips, cfg.Addr.IP.AsSlice())
		}
		c, path, err := selfSignedCert(dataDir, ips)
		if err != nil {
			return fmt.Errorf("creating self-signed certificate: %w", err)
		}
		fmt.Fprintf(out, "Using self-signed certificate %s (your browser will warn about it once).\n", path)
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
	}

	// 8. Bind the console.
	ln, err := listen(cfg.Addr, cfg.AddrFallback)
	if err != nil {
		return err
	}
	defer ln.Close()

	// 9. Drop root if we came in through sudo; sockets stay usable.
	if uid, gid, ok := privilege.SudoUser(); ok {
		chownTree(dataDir, uid, gid)
		if dropped, err := privilege.DropSudo(); err != nil {
			log.Warn("could not drop root privileges", "err", err)
		} else if dropped {
			log.Info("dropped root privileges", "uid", uid)
		}
	}

	// 10. Inventory, alerts, scanning.
	hub := alert.NewHub()
	var webhook *alert.Webhook
	if cfg.Webhook != "" {
		if webhook, err = alert.NewWebhook(cfg.Webhook); err != nil {
			return err
		}
	}
	inv := &inventory.Inventory{Store: st, OUI: oui.Default(), FP: fingerprint.Default(), Log: log}
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
	if gw, ok := netinfo.Gateway(nw.Iface.Name); ok && nw.InScope(gw) {
		inv.Gateway = gw
	}
	if _, err := st.Setting(ctx, "baseline_done"); errors.Is(err, store.ErrNotFound) {
		inv.SetBaseline(true)
	}

	liveWindow := 2*cfg.ScanInterval + time.Minute
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
			inv.SetBaseline(false)
			st.SetSetting(context.Background(), "baseline_done", "1")
		}
		hub.Publish(alert.Message{Type: "scan", Data: ss.snapshot()})
	}

	// 11. Web console.
	consoleAddr := ln.Addr().String()
	srv := &web.Server{
		Store:        st,
		Sessions:     auth.NewSessions(tlsCfg != nil),
		Limiter:      auth.NewLoginLimiter(),
		Hub:          hub,
		Static:       ui.FS(),
		Log:          log,
		ScanNow:      engine.ScanNow,
		LoopbackOnly: cfg.Addr.IsLoopback(),
	}
	generated := cr.Creds.Generated
	var genMu sync.Mutex
	srv.OnPasswordChange = func(g bool) { genMu.Lock(); generated = g; genMu.Unlock() }
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
		return map[string]any{
			"version":           opt.Version,
			"network":           map[string]string{"interface": nw.Iface.Name, "ip": nw.IP.String(), "subnet": nw.Prefix.String(), "mac": nw.Iface.HardwareAddr.String()},
			"privilege":         priv,
			"features":          engine.Features(),
			"scan":              ss.snapshot(),
			"console":           map[string]any{"addr": consoleAddr, "tls": tlsCfg != nil, "loopback": cfg.Addr.IsLoopback()},
			"dbPath":            st.Path(),
			"devices":           len(ds),
			"online":            online,
			"unread":            unread,
			"generatedPassword": g,
			"warnings":          warnings,
			"liveWindowSeconds": liveWindow.Seconds(),
		}
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         tlsCfg,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
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

	serveErr := make(chan error, 1)
	go func() {
		var err error
		if tlsCfg != nil {
			err = httpSrv.ServeTLS(ln, "", "")
		} else {
			err = httpSrv.Serve(ln)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	url := consoleURL(ln.Addr().(*net.TCPAddr), tlsCfg != nil)
	printBanner(out, url, cfg, cr, priv, nw, engine.Features(), dataDir)
	if opt.Ready != nil {
		opt.Ready(url)
	}
	if !cfg.NoOpenBrowser {
		openBrowser(url)
	}

	go engine.Run(ctx)

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("web console stopped: %w", err)
		}
	}
	shutCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	httpSrv.Shutdown(shutCtx)
	return nil
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

func printBanner(w io.Writer, url string, cfg *config.Config, cr *credResult, priv privilege.Status, nw *netinfo.Network, feats []scan.Feature, dataDir string) {
	fmt.Fprintf(w, "\nLocalLanView is running\n\n")
	fmt.Fprintf(w, "  Dashboard:  %s\n", url)
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
		fmt.Fprintf(w, "  Inactive:   %v (see the Status page for why)\n", off)
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
