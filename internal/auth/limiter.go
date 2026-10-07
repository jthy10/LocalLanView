package auth

import (
	"sync"
	"time"
)

// LoginLimiter throttles password guessing per client address and overall.
type LoginLimiter struct {
	Window      time.Duration // failures are counted over this window
	MaxPerIP    int           // failures before an address is locked out
	MaxGlobal   int           // failures (all addresses) before everyone is locked out
	LockoutTime time.Duration
	DelayStep   time.Duration // extra pause per recent failure, after the third

	mu     sync.Mutex
	ips    map[string]*failRecord
	global failRecord
	now    func() time.Time
}

type failRecord struct {
	times       []time.Time
	lockedUntil time.Time
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		Window: 15 * time.Minute, MaxPerIP: 10, MaxGlobal: 50, LockoutTime: 15 * time.Minute, DelayStep: 250 * time.Millisecond,
		ips: map[string]*failRecord{}, now: time.Now,
	}
}

// Allow reports whether a login attempt from ip may proceed, and if not,
// how long to wait.
func (l *LoginLimiter) Allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Before(l.global.lockedUntil) {
		return false, l.global.lockedUntil.Sub(now)
	}
	if r := l.ips[ip]; r != nil && now.Before(r.lockedUntil) {
		return false, r.lockedUntil.Sub(now)
	}
	return true, 0
}

// Delay is a small growing pause after repeated failures, to slow scripts
// without locking anyone out yet.
func (l *LoginLimiter) Delay(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.ips[ip]
	if r == nil || len(r.times) < 3 {
		return 0
	}
	return time.Duration(len(r.times)) * l.DelayStep
}

// Fail records a failed attempt.
func (l *LoginLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	r := l.ips[ip]
	if r == nil {
		r = &failRecord{}
		l.ips[ip] = r
	}
	r.times = prune(append(r.times, now), now.Add(-l.Window))
	if len(r.times) >= l.MaxPerIP {
		r.lockedUntil = now.Add(l.LockoutTime)
		r.times = nil
	}
	l.global.times = prune(append(l.global.times, now), now.Add(-l.Window))
	if len(l.global.times) >= l.MaxGlobal {
		l.global.lockedUntil = now.Add(l.LockoutTime)
		l.global.times = nil
	}
}

// Success clears an address's failure count.
func (l *LoginLimiter) Success(ip string) {
	l.mu.Lock()
	delete(l.ips, ip)
	l.mu.Unlock()
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}
