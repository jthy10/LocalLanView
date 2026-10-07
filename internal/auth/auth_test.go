package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format %s", h)
	}
	if ok, _ := VerifyPassword("correct horse battery staple", h); !ok {
		t.Fatal("right password rejected")
	}
	if ok, _ := VerifyPassword("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("hashes must be salted")
	}
	if _, err := VerifyPassword("x", "$2a$10$bcrypt"); err == nil {
		t.Fatal("foreign hash format should error")
	}
}

func TestGeneratePassword(t *testing.T) {
	a, _ := GeneratePassword()
	b, _ := GeneratePassword()
	if a == b || len(a) != 23 || strings.Count(a, "-") != 3 {
		t.Fatalf("bad generated passwords %q %q", a, b)
	}
}

func TestStrength(t *testing.T) {
	weak := []string{"short", "password1234", "admin-admin-admin", "aaaaaaaaaaaaaaaa", "abcdefghijkl"}
	for _, pw := range weak {
		if CheckStrength(pw, "admin") == nil {
			t.Errorf("%q accepted", pw)
		}
	}
	strong := []string{"Tr0ub4dor&3xyz", "correct horse battery staple", "k9#Lm2!pQ7zR"}
	for _, pw := range strong {
		if err := CheckStrength(pw, "admin"); err != nil {
			t.Errorf("%q rejected: %v", pw, err)
		}
	}
}

func TestSessions(t *testing.T) {
	s := NewSessions(true)
	w := httptest.NewRecorder()
	sess := s.Create(w, "admin")
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags %+v", cookie)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(cookie)
	if got := s.Get(r); got == nil || got.ID != sess.ID {
		t.Fatal("session lookup failed")
	}
	r.Header.Set("X-CSRF-Token", sess.CSRF)
	if !ValidCSRF(sess, r) {
		t.Fatal("csrf should match")
	}
	r.Header.Set("X-CSRF-Token", "nope")
	if ValidCSRF(sess, r) {
		t.Fatal("csrf mismatch accepted")
	}
	sess.LastSeen = time.Now().Add(-13 * time.Hour)
	if s.Get(r) != nil {
		t.Fatal("idle session should expire")
	}
}

func TestLoginLimiter(t *testing.T) {
	l := NewLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	for i := 0; i < 9; i++ {
		l.Fail("1.2.3.4")
	}
	if ok, _ := l.Allow("1.2.3.4"); !ok {
		t.Fatal("locked too early")
	}
	l.Fail("1.2.3.4")
	if ok, wait := l.Allow("1.2.3.4"); ok || wait != 15*time.Minute {
		t.Fatalf("should be locked out, ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Allow("5.6.7.8"); !ok {
		t.Fatal("other addresses should not be locked")
	}
	now = now.Add(16 * time.Minute)
	if ok, _ := l.Allow("1.2.3.4"); !ok {
		t.Fatal("lockout should expire")
	}
	for i := 0; i < 50; i++ {
		l.Fail(string(rune('a' + i%26)))
	}
	if ok, _ := l.Allow("9.9.9.9"); ok {
		t.Fatal("global lockout should apply")
	}
}
