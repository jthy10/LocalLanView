// Package update replaces the running binary with the latest GitHub
// release. It only talks to GitHub when someone presses the button in the
// console; nothing here runs on its own.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Repo is where releases are published.
const Repo = "jthy10/LocalLanView"

const (
	maxBinary = 256 << 20 // well above any release binary
	maxSmall  = 1 << 20   // release JSON and SHA256SUMS
)

var tagRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// ErrBusy is returned when an update is already being installed.
var ErrBusy = errors.New("an update is already being installed")

// Release is the latest published release, as far as this platform cares.
type Release struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	asset   string // download URL of this platform's binary
	sums    string // download URL of SHA256SUMS
	name    string // file name of this platform's binary
}

// Check is what the console shows before installing.
type Check struct {
	Current    string   `json:"current"`
	Latest     *Release `json:"latest"`
	Newer      bool     `json:"newer"`
	CanInstall bool     `json:"canInstall"`
	Reason     string   `json:"reason,omitempty"` // why CanInstall is false
}

// Updater checks for and installs releases.
type Updater struct {
	Current string // running version, e.g. v1.4.1
	// Blocked, if set, says why this process can't restart itself after
	// an update (e.g. it dropped root), so installing is refused.
	Blocked string

	// For tests; zero values mean the real thing.
	API    string // GitHub API base URL
	Client *http.Client
	Exe    string // path of the binary to replace
	GOOS   string
	GOARCH string
	verify func(ctx context.Context, path, version string) error

	mu sync.Mutex
}

func (u *Updater) goos() string {
	if u.GOOS != "" {
		return u.GOOS
	}
	return runtime.GOOS
}

func (u *Updater) goarch() string {
	if u.GOARCH != "" {
		return u.GOARCH
	}
	return runtime.GOARCH
}

func (u *Updater) client() *http.Client {
	if u.Client != nil {
		return u.Client
	}
	return &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.URL.Scheme != "https" {
				return errors.New("refusing a non-HTTPS redirect")
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func (u *Updater) get(ctx context.Context, url, accept string, limit int64) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "LocalLanView-updater")
	res, err := u.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching GitHub: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("GitHub answered %s", res.Status)
	}
	if res.ContentLength > limit {
		res.Body.Close()
		return nil, errors.New("download is unexpectedly large")
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(res.Body, limit+1), res.Body}, nil
}

// Latest fetches the newest release and finds this platform's binary.
func (u *Updater) Latest(ctx context.Context) (*Release, error) {
	base := u.API
	if base == "" {
		base = "https://api.github.com"
	}
	body, err := u.get(ctx, base+"/repos/"+Repo+"/releases/latest", "application/vnd.github+json", maxSmall)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var gr struct {
		Tag    string `json:"tag_name"`
		URL    string `json:"html_url"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(body).Decode(&gr); err != nil {
		return nil, fmt.Errorf("reading the release: %w", err)
	}
	if !tagRE.MatchString(gr.Tag) {
		return nil, fmt.Errorf("latest release has an unexpected tag %q", gr.Tag)
	}
	r := &Release{Version: gr.Tag, URL: gr.URL}
	r.name = fmt.Sprintf("LocalLanView-%s-%s-%s", gr.Tag, u.goos(), u.goarch())
	if u.goos() == "windows" {
		r.name += ".exe"
	}
	for _, a := range gr.Assets {
		if !strings.HasPrefix(a.URL, "https://") {
			continue
		}
		switch a.Name {
		case r.name:
			r.asset = a.URL
		case "SHA256SUMS":
			r.sums = a.URL
		}
	}
	return r, nil
}

// Check compares the latest release with the running version.
func (u *Updater) Check(ctx context.Context) (*Check, error) {
	rel, err := u.Latest(ctx)
	if err != nil {
		return nil, err
	}
	c := &Check{Current: u.Current, Latest: rel}
	cur, ok := parse(u.Current)
	switch {
	case !ok:
		c.Reason = "This is a development build (" + u.Current + "), so it isn't updated from releases."
	case u.Blocked != "":
		c.Reason = u.Blocked
	case rel.asset == "" || rel.sums == "":
		c.Reason = "The latest release has no build for " + u.goos() + "/" + u.goarch() + "."
	}
	if ok {
		latest, _ := parse(rel.Version)
		c.Newer = newer(latest, cur)
	}
	c.CanInstall = c.Reason == "" && c.Newer
	return c, nil
}

// Install downloads version (which must still be the latest release),
// verifies it against SHA256SUMS and swaps it in for the running binary.
// The caller restarts the process afterwards.
func (u *Updater) Install(ctx context.Context, version string) error {
	if !u.mu.TryLock() {
		return ErrBusy
	}
	defer u.mu.Unlock()

	c, err := u.Check(ctx)
	if err != nil {
		return err
	}
	if c.Latest.Version != version {
		return fmt.Errorf("the latest release is now %s; check again", c.Latest.Version)
	}
	if !c.CanInstall {
		if c.Reason != "" {
			return errors.New(c.Reason)
		}
		return fmt.Errorf("%s is already up to date", u.Current)
	}

	want, err := u.checksum(ctx, c.Latest)
	if err != nil {
		return err
	}
	exe, err := u.exe()
	if err != nil {
		return err
	}
	tmp := newPath(exe)
	if err := u.download(ctx, c.Latest.asset, tmp, want); err != nil {
		os.Remove(tmp)
		return err
	}
	verify := u.verify
	if verify == nil {
		verify = verifyRuns
	}
	if err := verify(ctx, tmp, version); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := swap(exe, tmp, u.goos() == "windows"); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (u *Updater) exe() (string, error) {
	exe := u.Exe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return "", fmt.Errorf("finding this program: %w", err)
		}
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return exe, nil
}

// checksum reads this platform's line from SHA256SUMS.
func (u *Updater) checksum(ctx context.Context, rel *Release) ([]byte, error) {
	body, err := u.get(ctx, rel.sums, "application/octet-stream", maxSmall)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	sc := bufio.NewScanner(body)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == rel.name {
			sum, err := hex.DecodeString(f[0])
			if err != nil || len(sum) != sha256.Size {
				return nil, errors.New("SHA256SUMS has a malformed entry")
			}
			return sum, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading SHA256SUMS: %w", err)
	}
	return nil, fmt.Errorf("SHA256SUMS doesn't list %s", rel.name)
}

func (u *Updater) download(ctx context.Context, url, dst string, want []byte) error {
	body, err := u.get(ctx, url, "application/octet-stream", maxBinary)
	if err != nil {
		return err
	}
	defer body.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return writeErr(dst, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), body)
	if err == nil && n > maxBinary {
		err = errors.New("download is unexpectedly large")
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("downloading the update: %w", err)
	}
	if !bytes.Equal(h.Sum(nil), want) {
		return errors.New("the download doesn't match SHA256SUMS; nothing was changed")
	}
	return nil
}

// verifyRuns makes sure the new binary starts on this machine and is the
// version we asked for, before it replaces the working one.
func verifyRuns(ctx context.Context, path, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-version").Output()
	if err != nil {
		return fmt.Errorf("the new version won't start on this machine: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != "LocalLanView "+version {
		return fmt.Errorf("the new binary reports %q, expected %s", got, version)
	}
	return nil
}

// swap puts tmp where exe is. Windows won't let a running exe be replaced,
// but it can be renamed out of the way; Cleanup removes it next start.
func swap(exe, tmp string, windows bool) error {
	if !windows {
		if err := os.Rename(tmp, exe); err != nil {
			return writeErr(exe, err)
		}
		return nil
	}
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return writeErr(exe, err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe)
		return writeErr(exe, err)
	}
	return nil
}

func writeErr(path string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("no permission to replace %s; update it by hand or move LocalLanView somewhere you can write to", filepath.Dir(path))
	}
	return fmt.Errorf("replacing %s: %w", path, err)
}

// newPath is where the download goes before it's swapped in. On Windows it
// has to end in .exe so it can be run to check it.
func newPath(exe string) string {
	if strings.EqualFold(filepath.Ext(exe), ".exe") {
		return strings.TrimSuffix(exe, filepath.Ext(exe)) + ".new.exe"
	}
	return exe + ".new"
}

// Cleanup removes what a previous update left behind on Windows.
func Cleanup() {
	if exe, err := os.Executable(); err == nil {
		if p, err := filepath.EvalSymlinks(exe); err == nil {
			exe = p
		}
		os.Remove(exe + ".old")
		os.Remove(newPath(exe))
	}
}

type semver [3]int

func parse(v string) (semver, bool) {
	m := tagRE.FindStringSubmatch(v)
	if m == nil {
		return semver{}, false
	}
	var s semver
	for i := range s {
		s[i], _ = strconv.Atoi(m[i+1])
	}
	return s, true
}

func newer(a, b semver) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
