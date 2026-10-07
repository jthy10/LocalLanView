package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

// Config holds everything parsed from the command line.
type Config struct {
	Addr          Addr
	AddrFallback  bool
	User          string
	PasswordFile  string
	SetPassword   bool
	Mode          string
	DataDir       string
	ScanInterval  time.Duration
	Interface     string
	Subnet        netip.Prefix
	NoOpenBrowser bool
	Version       bool

	TLSCert       string
	TLSKey        string
	TLSSelfSigned bool

	NoPortScan bool
	ProbeRate  int
	Webhook    string
	Notify     bool
}

// ErrHelp is returned when -h/-help was requested and usage has been printed.
var ErrHelp = flag.ErrHelp

// Parse parses args (without the program name). Go's flag package already
// accepts both -flag and --flag.
func Parse(args []string, output io.Writer) (*Config, error) {
	for _, a := range args {
		name := strings.TrimLeft(a, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if strings.HasPrefix(a, "-") && name == "password" {
			return nil, errors.New("-password is not supported because command-line arguments leak through process lists and shell history; use -password-file or the LOCALLANVIEW_PASSWORD environment variable")
		}
		if a == "--" {
			break
		}
	}

	c := &Config{}
	fs := flag.NewFlagSet("LocalLanView", flag.ContinueOnError)
	fs.SetOutput(output)

	addr := fs.String("addr", "127.0.0.1:8787", "address the web console binds to: host:port, :port or port")
	fs.BoolVar(&c.AddrFallback, "addr-fallback", false, "if the port is in use, pick a free port instead of exiting")
	fs.StringVar(&c.User, "user", "admin", "console username")
	fs.StringVar(&c.PasswordFile, "password-file", "", "read the console password from this file")
	fs.BoolVar(&c.SetPassword, "set-password", false, "set the console password (from -password-file, LOCALLANVIEW_PASSWORD, or a prompt) and continue")
	fs.StringVar(&c.Mode, "mode", "auto", "privilege mode: auto, std or elv")
	fs.StringVar(&c.DataDir, "data-dir", "", "where the database and config live (default: per-user config dir)")
	fs.DurationVar(&c.ScanInterval, "scan-interval", 5*time.Minute, "time between active scans")
	fs.StringVar(&c.Interface, "interface", "", "network interface to scan from (default: auto-detect)")
	subnet := fs.String("subnet", "", "subnet to scan in CIDR form, overrides auto-detect (e.g. 192.168.1.0/24)")
	fs.BoolVar(&c.NoOpenBrowser, "no-open-browser", false, "don't open the dashboard in a browser on start")
	fs.BoolVar(&c.Version, "version", false, "print version and exit")
	fs.StringVar(&c.TLSCert, "tls-cert", "", "TLS certificate file (PEM)")
	fs.StringVar(&c.TLSKey, "tls-key", "", "TLS private key file (PEM)")
	fs.BoolVar(&c.TLSSelfSigned, "tls-self-signed", false, "serve HTTPS with a self-signed certificate stored in the data dir")
	fs.BoolVar(&c.NoPortScan, "no-port-scan", false, "disable TCP port probes and banner grabbing")
	fs.IntVar(&c.ProbeRate, "probe-rate", 100, "maximum probe packets per second")
	fs.StringVar(&c.Webhook, "webhook", "", "POST new-device alerts to this URL (must be a local/private address)")
	fs.BoolVar(&c.Notify, "notify", false, "show a desktop notification for new devices")

	fs.Usage = func() {
		fmt.Fprintf(output, "Usage: LocalLanView [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q (all options are flags, see -h)", fs.Arg(0))
	}

	var err error
	if c.Addr, err = ParseAddr(*addr); err != nil {
		return nil, fmt.Errorf("-addr: %w", err)
	}
	switch c.Mode {
	case "auto", "std", "elv":
	default:
		return nil, fmt.Errorf("-mode: %q is not valid; use auto, std or elv", c.Mode)
	}
	if c.User = strings.TrimSpace(c.User); c.User == "" {
		return nil, errors.New("-user: username can't be empty")
	}
	if *subnet != "" {
		p, err := netip.ParsePrefix(*subnet)
		if err != nil {
			return nil, fmt.Errorf("-subnet: %q is not a valid CIDR prefix (e.g. 192.168.1.0/24)", *subnet)
		}
		c.Subnet = p.Masked()
	}
	if c.ScanInterval < 30*time.Second {
		return nil, errors.New("-scan-interval: must be at least 30s")
	}
	if c.ProbeRate < 1 || c.ProbeRate > 10000 {
		return nil, errors.New("-probe-rate: must be between 1 and 10000")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("-tls-cert and -tls-key must be used together")
	}
	if c.TLSCert != "" && c.TLSSelfSigned {
		return nil, errors.New("use either -tls-cert/-tls-key or -tls-self-signed, not both")
	}
	return c, nil
}

// TLS reports whether the console will be served over HTTPS.
func (c *Config) TLS() bool { return c.TLSCert != "" || c.TLSSelfSigned }
