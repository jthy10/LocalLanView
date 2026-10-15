package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jthy10/LocalLanView/internal/config"
	"github.com/jthy10/LocalLanView/internal/netinfo"
	"github.com/jthy10/LocalLanView/internal/privilege"
)

type fakeChecker bool

func (f fakeChecker) Check() (bool, string) {
	if f {
		return true, "root"
	}
	return false, ""
}

// syncBuf is a goroutine-safe output buffer.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func testConfig(t *testing.T, args ...string) *config.Config {
	t.Helper()
	cfg, err := config.Parse(append([]string{"-no-open-browser", "-data-dir", t.TempDir()}, args...), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func loopbackNet() *netinfo.Network {
	lo, _ := net.InterfaceByIndex(1)
	n := &netinfo.Network{IP: netip.MustParseAddr("127.0.0.1"), Prefix: netip.MustParsePrefix("127.0.0.0/30")}
	if lo != nil {
		n.Iface = *lo
	}
	return n
}

// start runs the app until the test ends and returns the console URL.
func start(t *testing.T, cfg *config.Config, out io.Writer) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, Options{
			Version: "test", Stdout: out, Stderr: out, Checker: fakeChecker(false),
			Network: loopbackNet(), NoSignal: true, Ready: func(u string) { ready <- u },
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case u := <-ready:
		return u
	case err := <-done:
		t.Fatalf("Run exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("app did not become ready")
	}
	return ""
}

func run(cfg *config.Config, c privilege.Checker) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Run(ctx, cfg, Options{Stdout: io.Discard, Stderr: io.Discard, Checker: c, Network: loopbackNet(), NoSignal: true,
		Ready: func(string) { cancel() }})
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestFirstRunServesDashboard(t *testing.T) {
	out := &syncBuf{}
	cfg := testConfig(t, "-addr", itoa(freePort(t)))
	url := start(t, cfg, out)
	if !strings.Contains(out.String(), "shown only once") {
		t.Fatalf("first run should print the generated password:\n%s", out)
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("dashboard: %d %v", resp.StatusCode, resp.Header)
	}
	info, err := os.Stat(filepath.Join(cfg.DataDir, "locallanview.db"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("database is readable by others: %v", info.Mode())
	}
}

func TestElvModeWithoutRights(t *testing.T) {
	err := run(testConfig(t, "-mode", "elv", "-addr", itoa(freePort(t))), fakeChecker(false))
	if !errors.Is(err, privilege.ErrNotElevated) {
		t.Fatalf("want ErrNotElevated, got %v", err)
	}
}

func TestPortInUse(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := itoa(l.Addr().(*net.TCPAddr).Port)

	err = run(testConfig(t, "-addr", port), fakeChecker(false))
	if err == nil || !strings.Contains(err.Error(), "already in use") || !strings.Contains(err.Error(), port) {
		t.Fatalf("want a clear port conflict error, got %v", err)
	}
	if err := run(testConfig(t, "-addr", port, "-addr-fallback"), fakeChecker(false)); err != nil {
		t.Fatalf("-addr-fallback should pick another port: %v", err)
	}
}

func TestNonLoopbackNeedsUserPassword(t *testing.T) {
	err := run(testConfig(t, "-addr", "0.0.0.0:"+itoa(freePort(t))), fakeChecker(false))
	if err == nil || !strings.Contains(err.Error(), "refusing to listen") {
		t.Fatalf("want refusal with generated password, got %v", err)
	}

	pwFile := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pwFile, []byte("weak\n"), 0o600)
	err = run(testConfig(t, "-addr", "0.0.0.0:"+itoa(freePort(t)), "-password-file", pwFile), fakeChecker(false))
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("weak password should be rejected, got %v", err)
	}

	os.WriteFile(pwFile, []byte("A-much-Better-passw0rd\n"), 0o600)
	out := &syncBuf{}
	cfg := testConfig(t, "-addr", "0.0.0.0:"+itoa(freePort(t)), "-password-file", pwFile)
	start(t, cfg, out)
	if !strings.Contains(out.String(), "plain HTTP") {
		t.Fatalf("expected plaintext warning:\n%s", out)
	}
}

func TestEnvPassword(t *testing.T) {
	t.Setenv(EnvPassword, "Env-Supplied-Passw0rd")
	out := &syncBuf{}
	start(t, testConfig(t, "-addr", itoa(freePort(t))), out)
	if strings.Contains(out.String(), "shown only once") || !strings.Contains(out.String(), "updated from "+EnvPassword) {
		t.Fatalf("env password not applied:\n%s", out)
	}
}

func TestSelfSignedTLS(t *testing.T) {
	out := &syncBuf{}
	url := start(t, testConfig(t, "-addr", itoa(freePort(t)), "-tls-self-signed"), out)
	if !strings.HasPrefix(url, "https://") {
		t.Fatalf("url %s", url)
	}
}

// lanConfig is testConfig on a free port, which -lan keeps; -addr can't be
// combined with -lan.
func lanConfig(t *testing.T, args ...string) *config.Config {
	cfg := testConfig(t, args...)
	cfg.Addr.Port = freePort(t)
	return cfg
}

func TestLANFlag(t *testing.T) {
	err := run(lanConfig(t, "-lan"), fakeChecker(false))
	if err == nil || !strings.Contains(err.Error(), "auto-generated password") {
		t.Fatalf("want refusal with generated password, got %v", err)
	}

	t.Setenv(EnvPassword, "Env-Supplied-Passw0rd")
	dir := t.TempDir()
	out := &syncBuf{}
	cfg := lanConfig(t, "-lan", "-data-dir", dir)
	url := start(t, cfg, out)
	if !strings.HasPrefix(url, "https://127.0.0.1:") || !strings.Contains(out.String(), "On your network: https://") {
		t.Fatalf("url %s, output:\n%s", url, out)
	}

	// The choice is remembered without the flag, and -lan=false forgets it.
	for _, tc := range []struct {
		args  []string
		https bool
	}{{nil, true}, {[]string{"-lan=false"}, false}, {nil, false}} {
		url := ""
		cfg := lanConfig(t, append([]string{"-data-dir", dir}, tc.args...)...)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		Run(ctx, cfg, Options{Stdout: io.Discard, Stderr: io.Discard, Checker: fakeChecker(false), Network: loopbackNet(), NoSignal: true,
			Ready: func(u string) { url = u; cancel() }})
		cancel()
		if strings.HasPrefix(url, "https://") != tc.https {
			t.Fatalf("%v: url %q", tc.args, url)
		}
	}
}

func TestLANToggle(t *testing.T) {
	t.Setenv(EnvPassword, "Env-Supplied-Passw0rd")
	out := &syncBuf{}
	url := start(t, lanConfig(t), out)
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("LAN access should be off by default: %s", url)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	csrf := login(t, c, url)

	resp := post(t, c, url+"api/console", csrf, `{"lan":true}`)
	var info struct {
		URL    string `json:"url"`
		LANURL string `json:"lanUrl"`
		LAN    bool   `json:"lan"`
	}
	json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()
	if resp.StatusCode != 200 || !info.LAN || !strings.HasPrefix(info.URL, "https://127.0.0.1:") || info.LANURL == "" {
		t.Fatalf("turning LAN on: %d %+v", resp.StatusCode, info)
	}

	// The console comes back over HTTPS on the same port, with new sessions.
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := c.Get(info.URL + "api/session")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("console didn't come back on %s: %v", info.URL, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "On other devices: https://") {
		t.Fatalf("terminal wasn't told the new address:\n%s", out)
	}

	csrf = login(t, c, info.URL)
	resp = post(t, c, info.URL+"api/console", csrf, `{"lan":false}`)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("turning LAN off: %d", resp.StatusCode)
	}
}

func TestLANToggleNeedsOwnPassword(t *testing.T) {
	out := &syncBuf{}
	url := start(t, lanConfig(t), out)
	pw := ""
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "      ") && strings.TrimSpace(l) != "" {
			pw = strings.TrimSpace(l)
		}
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	csrf := loginAs(t, c, url, pw)
	resp := post(t, c, url+"api/console", csrf, `{"lan":true}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409 with the generated password, got %d", resp.StatusCode)
	}
}

func login(t *testing.T, c *http.Client, url string) string {
	return loginAs(t, c, url, "Env-Supplied-Passw0rd")
}

func loginAs(t *testing.T, c *http.Client, url, pw string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"user": "admin", "password": pw})
	resp, err := c.Post(url+"api/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	var out struct{ CSRF string }
	json.NewDecoder(resp.Body).Decode(&out)
	return out.CSRF
}

func post(t *testing.T, c *http.Client, url, csrf, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
