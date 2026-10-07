package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const CookieName = "llv_session"

// Session is one logged-in browser.
type Session struct {
	ID       string
	User     string
	CSRF     string
	Created  time.Time
	LastSeen time.Time
}

// Sessions is an in-memory session table. Restarting the program logs
// everyone out, which is fine for a single-user console.
type Sessions struct {
	Idle     time.Duration
	Absolute time.Duration
	Secure   bool // set the Secure cookie flag (HTTPS)

	mu sync.Mutex
	m  map[string]*Session
}

func NewSessions(secure bool) *Sessions {
	return &Sessions{Idle: 12 * time.Hour, Absolute: 7 * 24 * time.Hour, Secure: secure, m: map[string]*Session{}}
}

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Create starts a session and sets the cookie.
func (s *Sessions) Create(w http.ResponseWriter, user string) *Session {
	now := time.Now()
	sess := &Session{ID: token(), User: user, CSRF: token(), Created: now, LastSeen: now}
	s.mu.Lock()
	s.gc(now)
	s.m[sess.ID] = sess
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.Absolute.Seconds()),
	})
	return sess
}

// Get returns the session for a request, or nil.
func (s *Sessions) Get(r *http.Request) *Session {
	c, err := r.Cookie(CookieName)
	if err != nil || len(c.Value) != 64 {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.m[c.Value]
	if sess == nil {
		return nil
	}
	if now.Sub(sess.LastSeen) > s.Idle || now.Sub(sess.Created) > s.Absolute {
		delete(s.m, sess.ID)
		return nil
	}
	sess.LastSeen = now
	return sess
}

// Destroy logs a session out and clears the cookie.
func (s *Sessions) Destroy(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		s.mu.Lock()
		delete(s.m, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.Secure, SameSite: http.SameSiteStrictMode})
}

// DestroyAll logs everyone out (after a password change).
func (s *Sessions) DestroyAll() {
	s.mu.Lock()
	s.m = map[string]*Session{}
	s.mu.Unlock()
}

func (s *Sessions) gc(now time.Time) {
	for id, sess := range s.m {
		if now.Sub(sess.LastSeen) > s.Idle || now.Sub(sess.Created) > s.Absolute {
			delete(s.m, id)
		}
	}
}

// ValidCSRF compares the request's X-CSRF-Token header to the session's.
func ValidCSRF(sess *Session, r *http.Request) bool {
	got := r.Header.Get("X-CSRF-Token")
	return sess != nil && got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) == 1
}
