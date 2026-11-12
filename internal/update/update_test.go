package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeGitHub struct {
	tag    string
	binary []byte
	sum    string // overrides the real checksum when set
	noOS   bool   // leave this platform's binary out
}

func (f *fakeGitHub) start(t *testing.T) *httptest.Server {
	var srv *httptest.Server
	name := "LocalLanView-" + f.tag + "-linux-amd64"
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + Repo + "/releases/latest":
			assets := []map[string]string{{"name": "SHA256SUMS", "browser_download_url": srv.URL + "/sums"}}
			if !f.noOS {
				assets = append(assets, map[string]string{"name": name, "browser_download_url": srv.URL + "/bin"})
			}
			json.NewEncoder(w).Encode(map[string]any{"tag_name": f.tag, "html_url": "https://example/rel", "assets": assets})
		case "/sums":
			sum := sha256.Sum256(f.binary)
			s := hex.EncodeToString(sum[:])
			if f.sum != "" {
				s = f.sum
			}
			fmt.Fprintf(w, "%s  LocalLanView-%s-windows-amd64.exe\n%s  %s\n", strings.Repeat("0", 64), f.tag, s, name)
		case "/bin":
			w.Write(f.binary)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newUpdater(t *testing.T, srv *httptest.Server, current string) (*Updater, string) {
	exe := filepath.Join(t.TempDir(), "LocalLanView")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Updater{
		Current: current, API: srv.URL, Client: srv.Client(), Exe: exe, GOOS: "linux", GOARCH: "amd64",
		verify: func(context.Context, string, string) error { return nil },
	}, exe
}

func TestCheck(t *testing.T) {
	srv := (&fakeGitHub{tag: "v1.10.0", binary: []byte("new")}).start(t)
	for _, tc := range []struct {
		current, blocked string
		newer, can       bool
	}{
		{"v1.9.9", "", true, true},
		{"v1.10.0", "", false, false},
		{"v2.0.0", "", false, false},
		{"dev", "", false, false},
		{"v1.0.0", "can't restart", true, false},
	} {
		u, _ := newUpdater(t, srv, tc.current)
		u.Blocked = tc.blocked
		c, err := u.Check(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if c.Newer != tc.newer || c.CanInstall != tc.can || c.Latest.Version != "v1.10.0" {
			t.Errorf("%s: got newer=%v can=%v (%s)", tc.current, c.Newer, c.CanInstall, c.Reason)
		}
	}
}

func TestInstall(t *testing.T) {
	srv := (&fakeGitHub{tag: "v1.5.0", binary: []byte("new binary")}).start(t)
	u, exe := newUpdater(t, srv, "v1.4.2")
	if err := u.Install(context.Background(), "v1.4.9"); err == nil {
		t.Fatal("installed a version that isn't the latest")
	}
	if err := u.Install(context.Background(), "v1.5.0"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new binary" {
		t.Fatalf("binary is %q", b)
	}
}

func TestInstallWindowsKeepsOld(t *testing.T) {
	f := &fakeGitHub{tag: "v1.5.0", binary: []byte("new binary")}
	srv := f.start(t)
	u, exe := newUpdater(t, srv, "v1.4.2")
	// The fake only serves a linux asset name; swap the Windows way anyway.
	if err := u.Install(context.Background(), "v1.5.0"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(newPath(exe), []byte("newer"), 0o755)
	if err := swap(exe, newPath(exe), true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "new binary" {
		t.Fatalf(".old is %q", b)
	}
	if b, _ := os.ReadFile(exe); string(b) != "newer" {
		t.Fatalf("binary is %q", b)
	}
}

func TestInstallRejectsBadChecksum(t *testing.T) {
	srv := (&fakeGitHub{tag: "v1.5.0", binary: []byte("evil"), sum: strings.Repeat("ab", 32)}).start(t)
	u, exe := newUpdater(t, srv, "v1.4.2")
	err := u.Install(context.Background(), "v1.5.0")
	if err == nil || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary changed to %q", b)
	}
	if _, err := os.Stat(newPath(exe)); !os.IsNotExist(err) {
		t.Fatal("left the download behind")
	}
}

func TestInstallFailedVerifyKeepsOld(t *testing.T) {
	srv := (&fakeGitHub{tag: "v1.5.0", binary: []byte("new")}).start(t)
	u, exe := newUpdater(t, srv, "v1.4.2")
	u.verify = func(context.Context, string, string) error { return fmt.Errorf("won't start") }
	if err := u.Install(context.Background(), "v1.5.0"); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary changed to %q", b)
	}
}

func TestNoBuildForPlatform(t *testing.T) {
	srv := (&fakeGitHub{tag: "v1.5.0", noOS: true}).start(t)
	u, _ := newUpdater(t, srv, "v1.4.2")
	c, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.CanInstall || c.Reason == "" {
		t.Fatalf("got %+v", c)
	}
}

func TestNewPath(t *testing.T) {
	if got := newPath("dir/LocalLanView.exe"); got != "dir/LocalLanView.new.exe" {
		t.Errorf("got %s", got)
	}
	if got := newPath("/usr/bin/LocalLanView"); got != "/usr/bin/LocalLanView.new" {
		t.Errorf("got %s", got)
	}
}

func TestRestartArgs(t *testing.T) {
	got := restartArgs([]string{"-set-password", "-lan", "--set-password=true", "-data-dir", "x"})
	want := []string{"-lan", "-data-dir", "x", "-no-open-browser"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	got = restartArgs([]string{"--no-open-browser"})
	if !reflect.DeepEqual(got, []string{"--no-open-browser"}) {
		t.Fatalf("got %v", got)
	}
}
