package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jthy10/LocalLanView/internal/alert"
	"github.com/jthy10/LocalLanView/internal/auth"
	"github.com/jthy10/LocalLanView/internal/store"
)

type env struct {
	srv   *httptest.Server
	st    *store.Store
	c     *http.Client
	csrf  string
	scans int
}

func setup(t *testing.T, loopbackOnly bool) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, _ := auth.HashPassword("Sup3r-Secret-Pass")
	st.SetCredentials(context.Background(), store.Credentials{User: "admin", Hash: hash, Generated: true})
	e := &env{st: st}
	lim := auth.NewLoginLimiter()
	lim.DelayStep = 0
	s := &Server{
		Store:        st,
		Sessions:     auth.NewSessions(false),
		Limiter:      lim,
		Hub:          alert.NewHub(),
		Static:       fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>LocalLanView</title>")}},
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Status:       func(context.Context) any { return map[string]string{"ok": "yes"} },
		ScanNow:      func() { e.scans++ },
		LoopbackOnly: loopbackOnly,
	}
	e.srv = httptest.NewServer(s.Handler())
	t.Cleanup(e.srv.Close)
	jar, _ := cookiejar.New(nil)
	e.c = &http.Client{Jar: jar}
	return e
}

func (e *env) do(t *testing.T, method, path string, body any, csrf bool) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (e *env) login(t *testing.T) {
	t.Helper()
	resp := e.do(t, "POST", "/api/login", map[string]string{"user": "admin", "password": "Sup3r-Secret-Pass"}, false)
	if resp.StatusCode != 200 {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var out struct{ CSRF string }
	json.NewDecoder(resp.Body).Decode(&out)
	e.csrf = out.CSRF
}

func TestSecurityHeaders(t *testing.T) {
	e := setup(t, false)
	resp := e.do(t, "GET", "/", nil, false)
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP %q", csp)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing headers")
	}
}

func TestAuthRequired(t *testing.T) {
	e := setup(t, false)
	for _, p := range []string{"/api/devices", "/api/status", "/api/events", "/api/export"} {
		if resp := e.do(t, "GET", p, nil, false); resp.StatusCode != 401 {
			t.Errorf("%s without login: %d", p, resp.StatusCode)
		}
	}
}

func TestLoginAndCSRF(t *testing.T) {
	e := setup(t, false)
	if resp := e.do(t, "POST", "/api/login", map[string]string{"user": "admin", "password": "nope"}, false); resp.StatusCode != 401 {
		t.Fatalf("bad password: %d", resp.StatusCode)
	}
	e.login(t)
	if resp := e.do(t, "GET", "/api/devices", nil, false); resp.StatusCode != 200 {
		t.Fatalf("devices: %d", resp.StatusCode)
	}
	if resp := e.do(t, "POST", "/api/scan", nil, false); resp.StatusCode != 403 {
		t.Fatalf("POST without CSRF: %d", resp.StatusCode)
	}
	if resp := e.do(t, "POST", "/api/scan", nil, true); resp.StatusCode != 202 || e.scans != 1 {
		t.Fatalf("POST with CSRF: %d scans=%d", resp.StatusCode, e.scans)
	}
}

func TestCrossSiteLoginRefused(t *testing.T) {
	e := setup(t, false)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/login", strings.NewReader(`{"user":"admin","password":"Sup3r-Secret-Pass"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, _ := e.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-site login: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", e.srv.URL+"/api/login", strings.NewReader(`user=admin`))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _ = e.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("form login: %d", resp.StatusCode)
	}
}

func TestLockout(t *testing.T) {
	e := setup(t, false)
	for i := 0; i < 10; i++ {
		e.do(t, "POST", "/api/login", map[string]string{"user": "admin", "password": "wrong"}, false)
	}
	resp := e.do(t, "POST", "/api/login", map[string]string{"user": "admin", "password": "Sup3r-Secret-Pass"}, false)
	if resp.StatusCode != 429 {
		t.Fatalf("expected lockout, got %d", resp.StatusCode)
	}
}

func TestDNSRebindingBlocked(t *testing.T) {
	e := setup(t, true)
	req, _ := http.NewRequest("GET", e.srv.URL+"/", nil)
	req.Host = "attacker.example:8787"
	resp, _ := e.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host: %d", resp.StatusCode)
	}
	if resp := e.do(t, "GET", "/", nil, false); resp.StatusCode != 200 {
		t.Fatalf("loopback Host: %d", resp.StatusCode)
	}
}

func TestDeviceEditAndExport(t *testing.T) {
	e := setup(t, false)
	e.login(t)
	now := time.Now()
	id, _ := e.st.InsertDevice(context.Background(), &store.Device{Key: "mac:00:11:22:33:44:55", MAC: "00:11:22:33:44:55", IP: "10.0.0.7", FirstSeen: now, LastSeen: now})

	resp := e.do(t, "PATCH", "/api/devices/"+itoa(int(id)), map[string]any{"customName": "=HYPERLINK(\"x\")", "trusted": true, "tags": []string{"lab"}}, true)
	if resp.StatusCode != 200 {
		t.Fatalf("patch: %d", resp.StatusCode)
	}
	if resp := e.do(t, "PATCH", "/api/devices/"+itoa(int(id)), map[string]any{"bogus": 1}, true); resp.StatusCode != 400 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
	resp = e.do(t, "GET", "/api/devices/"+itoa(int(id)), nil, false)
	var detail struct {
		Device store.Device `json:"device"`
	}
	json.NewDecoder(resp.Body).Decode(&detail)
	if !detail.Device.Trusted || detail.Device.Tags[0] != "lab" {
		t.Fatalf("detail %+v", detail.Device)
	}
	resp = e.do(t, "GET", "/api/export?format=csv", nil, false)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `'=HYPERLINK`) {
		t.Fatalf("CSV formula not neutralized:\n%s", body)
	}
	if resp := e.do(t, "DELETE", "/api/devices/"+itoa(int(id)), nil, true); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp := e.do(t, "GET", "/api/devices/"+itoa(int(id)), nil, false); resp.StatusCode != 404 {
		t.Fatalf("deleted device: %d", resp.StatusCode)
	}
}

func TestPasswordChange(t *testing.T) {
	e := setup(t, false)
	e.login(t)
	if resp := e.do(t, "POST", "/api/password", map[string]string{"current": "Sup3r-Secret-Pass", "new": "short"}, true); resp.StatusCode != 400 {
		t.Fatalf("weak password: %d", resp.StatusCode)
	}
	resp := e.do(t, "POST", "/api/password", map[string]string{"current": "Sup3r-Secret-Pass", "new": "N3w-Strong-Passw0rd!"}, true)
	if resp.StatusCode != 200 {
		t.Fatalf("change: %d", resp.StatusCode)
	}
	c, _ := e.st.Credentials(context.Background())
	if c.Generated {
		t.Fatal("password should be marked user-set")
	}
	if ok, _ := auth.VerifyPassword("N3w-Strong-Passw0rd!", c.Hash); !ok {
		t.Fatal("new password not stored")
	}
}

func TestStream(t *testing.T) {
	e := setup(t, false)
	e.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+"/api/stream", nil)
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
}
