// Package web serves the dashboard and its JSON API.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jthy10/LocalLanView/internal/alert"
	"github.com/jthy10/LocalLanView/internal/auth"
	"github.com/jthy10/LocalLanView/internal/store"
)

// Server holds everything the handlers need.
type Server struct {
	Store    *store.Store
	Sessions *auth.Sessions
	Limiter  *auth.LoginLimiter
	Hub      *alert.Hub
	Static   fs.FS
	Log      *slog.Logger

	// Status reports runtime state for the dashboard header and the
	// capabilities panel.
	Status func(ctx context.Context) any
	// ScanNow triggers an immediate scan cycle.
	ScanNow func()
	// LoopbackOnly enables Host header checks against DNS rebinding.
	LoopbackOnly bool
	// OnPasswordChange is called after a successful password change.
	OnPasswordChange func(generated bool)
}

// dummyHash keeps login timing the same for unknown users.
var dummyHash, _ = auth.HashPassword("not-a-real-password")

// Handler builds the HTTP handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/session", s.handleSession)

	mux.Handle("GET /api/status", s.authed(s.handleStatus))
	mux.Handle("GET /api/devices", s.authed(s.handleDevices))
	mux.Handle("GET /api/devices/{id}", s.authed(s.handleDevice))
	mux.Handle("PATCH /api/devices/{id}", s.authed(s.handleUpdateDevice))
	mux.Handle("DELETE /api/devices/{id}", s.authed(s.handleDeleteDevice))
	mux.Handle("GET /api/events", s.authed(s.handleEvents))
	mux.Handle("POST /api/events/ack", s.authed(s.handleAck))
	mux.Handle("POST /api/scan", s.authed(s.handleScan))
	mux.Handle("POST /api/password", s.authed(s.handlePassword))
	mux.Handle("GET /api/export", s.authed(s.handleExport))
	mux.Handle("GET /api/stream", s.authed(s.handleStream))
	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	}))

	static := http.FileServer(http.FS(s.Static))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Single page app: unknown paths get index.html.
		if r.URL.Path != "/" && !strings.Contains(r.URL.Path, ".") {
			r.URL.Path = "/"
		}
		static.ServeHTTP(w, r)
	}))

	return s.securityHeaders(s.hostCheck(http.MaxBytesHandler(mux, 64<<10)))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// hostCheck blocks DNS rebinding: a loopback-only console must be reached
// through a loopback name, not some attacker-controlled domain that
// resolves to 127.0.0.1.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.LoopbackOnly && !isLoopbackHost(r.Host) {
			http.Error(w, "unexpected Host header", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameOrigin rejects cross-site requests that carry an Origin header for
// another site.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		// Browsers always send Origin on cross-origin POSTs; a missing one
		// means same-origin or a non-browser client.
		return true
	}
	o = strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://")
	return strings.EqualFold(o, r.Host)
}

type ctxKey struct{}

// authed requires a session, and a CSRF token on anything but GET.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, *auth.Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := s.Sessions.Get(r)
		if sess == nil {
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) || !auth.ValidCSRF(sess, r) {
				writeError(w, http.StatusForbidden, "invalid CSRF token")
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)), sess)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusForbidden, "cross-site login refused")
		return
	}
	ip := clientIP(r)
	if ok, wait := s.Limiter.Allow(ip); !ok {
		w.Header().Set("Retry-After", itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many failed logins; try again in "+wait.Round(time.Minute).String())
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if d := s.Limiter.Delay(ip); d > 0 {
		time.Sleep(d)
	}
	creds, err := s.Store.Credentials(r.Context())
	hash, user := dummyHash, ""
	if err == nil {
		hash, user = creds.Hash, creds.User
	}
	ok, _ := auth.VerifyPassword(req.Password, hash)
	if !ok || err != nil || req.User != user {
		s.Limiter.Fail(ip)
		s.Log.Warn("failed login", "remote", ip, "user", req.User)
		writeError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	s.Limiter.Success(ip)
	sess := s.Sessions.Create(w, user)
	writeJSON(w, http.StatusOK, map[string]any{"user": sess.User, "csrf": sess.CSRF, "generatedPassword": creds.Generated})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess := s.Sessions.Get(r); sess != nil && (!auth.ValidCSRF(sess, r) || !sameOrigin(r)) {
		writeError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	s.Sessions.Destroy(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess := s.Sessions.Get(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "login required")
		return
	}
	generated := false
	if c, err := s.Store.Credentials(r.Context()); err == nil {
		generated = c.Generated
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": sess.User, "csrf": sess.CSRF, "generatedPassword": generated})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	writeJSON(w, http.StatusOK, s.Status(r.Context()))
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.ScanNow()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "scan requested"})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	creds, err := s.Store.Credentials(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no credentials")
		return
	}
	ip := clientIP(r)
	if ok, _ := s.Limiter.Allow(ip); !ok {
		writeError(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}
	if ok, _ := auth.VerifyPassword(req.Current, creds.Hash); !ok {
		s.Limiter.Fail(ip)
		writeError(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if err := auth.CheckStrength(req.New, creds.User); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hashing failed")
		return
	}
	if err := s.Store.SetCredentials(r.Context(), store.Credentials{User: creds.User, Hash: hash, Generated: false}); err != nil {
		writeError(w, http.StatusInternalServerError, "saving failed")
		return
	}
	s.Sessions.DestroyAll()
	ns := s.Sessions.Create(w, creds.User)
	if s.OnPasswordChange != nil {
		s.OnPasswordChange(false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": ns.User, "csrf": ns.CSRF, "generatedPassword": false})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func storeError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "database error")
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
