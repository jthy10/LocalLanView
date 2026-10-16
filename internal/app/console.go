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
	"sync"
	"time"

	"github.com/jthy10/LocalLanView/internal/config"
	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/store"
)

// settingLAN remembers whether the console is open to the LAN.
const settingLAN = "lan_access"

// ErrLANNeedsPassword is returned when LAN access is asked for while the
// console still uses the generated first-run password.
var ErrLANNeedsPassword = errors.New("set your own console password before opening the console to the network")

// console owns the web console's listener, so it can move between this
// machine and the LAN without restarting scanning.
type console struct {
	cfg     *config.Config
	nw      *netinfo.Network
	dataDir string
	out     io.Writer
	stderr  io.Writer
	log     *slog.Logger
	// handler builds the HTTP handler for a listener; it's called again on
	// every move, so sessions start fresh along with the new address.
	handler func(loopback bool, tlsCfg *tls.Config) http.Handler
	// errs receives an error if serving stops unexpectedly.
	errs chan error

	mu     sync.Mutex
	lan    bool
	ln     net.Listener
	srv    *http.Server
	plain  *http.Server // redirects http:// to https:// on a TLS port
	tlsCfg *tls.Config
	moving bool
	closed bool
}

// lanAddr is where the console listens with LAN access on: every
// interface, on the port it would use otherwise.
func lanAddr(a config.Addr) config.Addr {
	return config.Addr{IP: netip.IPv4Unspecified(), Port: a.Port}
}

// bind opens the console's listener. Serving starts with serve, so the
// port can be taken before privileges are dropped.
func (c *console) bind(lan bool, port int, fallback bool) error {
	addr := c.cfg.Addr
	if lan {
		addr = lanAddr(addr)
	}
	if port != 0 {
		addr.Port = port
	}
	tlsCfg, err := c.tlsConfig(lan, addr)
	if err != nil {
		return err
	}
	ln, err := listen(addr, fallback)
	if err != nil {
		return err
	}
	if !addr.IsLoopback() && tlsCfg == nil {
		fmt.Fprintln(c.stderr, "WARNING: "+plainHTTPWarning)
	}
	c.lan, c.ln, c.tlsCfg = lan, ln, tlsCfg
	return nil
}

// serve serves the console on the bound listener in the background.
func (c *console) serve() {
	ln, tlsCfg := c.ln, c.tlsCfg
	if tlsCfg != nil {
		var plainLn net.Listener
		ln, plainLn = splitTLS(ln)
		c.plain = &http.Server{
			Handler:           redirectHTTPS,
			ReadHeaderTimeout: 10 * time.Second,
			ErrorLog:          slog.NewLogLogger(c.log.Handler(), slog.LevelWarn),
		}
		go c.plain.Serve(plainLn) // ends when the console's listener closes
	}
	srv := &http.Server{
		Handler:           c.handler(ln.Addr().(*net.TCPAddr).IP.IsLoopback(), tlsCfg),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         tlsCfg,
		ErrorLog:          slog.NewLogLogger(c.log.Handler(), slog.LevelWarn),
	}
	c.srv = srv
	go func() {
		var err error
		if tlsCfg != nil {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			c.errs <- err
		}
	}()
}

const plainHTTPWarning = "The console is reachable from the network over plain HTTP; logins and the device list can be sniffed. Use -tls-self-signed or -tls-cert/-tls-key."

// tlsConfig serves HTTPS when asked to on the command line, and always
// when the console is open to the LAN, so the password never crosses the
// network in the clear.
func (c *console) tlsConfig(lan bool, addr config.Addr) (*tls.Config, error) {
	switch {
	case c.cfg.TLSCert != "":
		cert, err := tls.LoadX509KeyPair(c.cfg.TLSCert, c.cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("loading TLS certificate: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	case c.cfg.TLSSelfSigned || lan:
		ips := []net.IP{c.nw.IP.AsSlice()}
		if !addr.IP.IsUnspecified() {
			ips = append(ips, addr.IP.AsSlice())
		}
		cert, path, err := selfSignedCert(c.dataDir, ips)
		if err != nil {
			return nil, fmt.Errorf("creating self-signed certificate: %w", err)
		}
		fmt.Fprintf(c.out, "Using self-signed certificate %s (browsers will warn about it once).\n", path)
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
	return nil, nil
}

// setLAN moves the console to or from the LAN. The move happens shortly
// after it returns, so the request that asked for it can still be
// answered; the reply carries the addresses the console will have.
func (c *console) setLAN(ctx context.Context, st *store.Store, on bool) (consoleInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.AddrSet {
		return consoleInfo{}, errors.New("the console address was set with -addr on the command line, so it can't be changed here")
	}
	if c.moving {
		return consoleInfo{}, errors.New("the console is already moving; try again in a moment")
	}
	if c.lan == on {
		return c.infoLocked(), nil
	}
	if err := st.SetSetting(ctx, settingLAN, boolSetting(on)); err != nil {
		return consoleInfo{}, err
	}
	c.moving = true
	port := c.ln.Addr().(*net.TCPAddr).Port
	secure := on || c.cfg.TLS()
	next := consoleInfo{TLS: secure, Loopback: !on, LAN: on, URL: consoleURL(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, secure)}
	if on {
		next.LANURL = lanURL(c.nw, port, secure)
	}
	go func() {
		time.Sleep(500 * time.Millisecond) // let the reply reach the browser
		c.move(st, on)
	}()
	return next, nil
}

// move restarts the console on the new address, going back to the old
// one if that fails.
func (c *console) move(st *store.Store, on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { c.moving = false }()
	if c.closed {
		return
	}
	port := c.ln.Addr().(*net.TCPAddr).Port
	c.srv.Close()
	c.closePlain()
	if err := c.bind(on, port, false); err != nil {
		c.log.Error("couldn't move the console", "lan", on, "err", err)
		fmt.Fprintf(c.stderr, "Couldn't move the console: %v\n", err)
		st.SetSetting(context.Background(), settingLAN, boolSetting(!on))
		if err := c.bind(!on, port, false); err != nil {
			c.errs <- fmt.Errorf("restarting the console: %w", err)
			return
		}
	}
	c.serve()
	c.printAddresses(c.infoLocked())
}

func (c *console) stop(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.srv != nil {
		c.srv.Shutdown(ctx)
	} else {
		c.ln.Close()
	}
	c.closePlain()
}

func (c *console) closePlain() {
	if c.plain != nil {
		c.plain.Close()
		c.plain = nil
	}
}

// consoleInfo is what the dashboard and the terminal are told about the
// console.
type consoleInfo struct {
	Addr     string `json:"addr"`
	TLS      bool   `json:"tls"`
	Loopback bool   `json:"loopback"`
	LAN      bool   `json:"lan"`
	URL      string `json:"url"`              // from this machine
	LANURL   string `json:"lanUrl,omitempty"` // from other devices
	Locked   string `json:"locked,omitempty"` // why LAN access can't be toggled here
}

func (c *console) info() consoleInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.infoLocked()
}

func (c *console) infoLocked() consoleInfo {
	a := c.ln.Addr().(*net.TCPAddr)
	secure := c.tlsCfg != nil
	i := consoleInfo{
		Addr:     a.String(),
		TLS:      secure,
		Loopback: a.IP.IsLoopback(),
		LAN:      !a.IP.IsLoopback(),
		URL:      consoleURL(a, secure),
	}
	switch {
	case a.IP.IsUnspecified():
		i.LANURL = lanURL(c.nw, a.Port, secure)
	case !i.Loopback:
		i.LANURL = i.URL // -addr named one of this machine's addresses
	}
	if c.cfg.AddrSet {
		i.Locked = "Set with -addr on the command line."
	}
	return i
}

func lanURL(nw *netinfo.Network, port int, secure bool) string {
	return consoleURL(&net.TCPAddr{IP: nw.IP.AsSlice(), Port: port}, secure)
}

// printAddresses tells the terminal where the console can be reached.
func (c *console) printAddresses(i consoleInfo) {
	if i.LANURL == "" {
		fmt.Fprintf(c.out, "\nThe console is now only reachable from this machine: %s\n\n", i.URL)
		return
	}
	fmt.Fprintf(c.out, "\nThe console is open to your network.\n  On this machine:  %s\n  On other devices: %s\n\n", i.URL, i.LANURL)
}

// lanWanted works out whether to start with LAN access: -lan sets and
// remembers the choice, otherwise the stored one applies. -addr overrides
// both.
func lanWanted(ctx context.Context, st *store.Store, cfg *config.Config) (bool, error) {
	if cfg.AddrSet {
		return false, nil
	}
	if cfg.LANSet {
		return cfg.LAN, st.SetSetting(ctx, settingLAN, boolSetting(cfg.LAN))
	}
	v, err := st.Setting(ctx, settingLAN)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return v == "1", err
}

func boolSetting(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
