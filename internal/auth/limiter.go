package auth

import (
	"net"
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
	return l.allow(limitKey(ip), l.now())
}

func (l *LoginLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	// The global lockout doesn't apply on the machine itself, so a flood of
	// guesses from the network can't lock the owner out of a local console.
	if key != loopbackKey && now.Before(l.global.lockedUntil) {
		return false, l.global.lockedUntil.Sub(now)
	}
	if r := l.ips[key]; r != nil && now.Before(r.lockedUntil) {
		return false, r.lockedUntil.Sub(now)
	}
	return true, 0
}

// Begin admits a login attempt and counts it as a failure straight away,
// so a burst of concurrent guesses can't all get past the limit while the
// slow password hash runs. Call done(true) if the password was right.
// If the attempt isn't allowed, done is nil and wait says how long.
func (l *LoginLimiter) Begin(ip string) (done func(ok bool), wait time.Duration) {
	key := limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if ok, wait := l.allow(key, now); !ok {
		return nil, wait
	}
	l.fail(key, now)
	return func(ok bool) {
		if ok {
			l.succeed(key, now)
		}
	}, 0
}

// Delay is a small growing pause after repeated failures, to slow scripts
// without locking anyone out yet.
func (l *LoginLimiter) Delay(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.ips[limitKey(ip)]
	if r == nil || len(r.times) < 3 {
		return 0
	}
	return time.Duration(len(r.times)) * l.DelayStep
}

// Fail records a failed attempt.
func (l *LoginLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fail(limitKey(ip), l.now())
}

func (l *LoginLimiter) fail(key string, now time.Time) {
	r := l.ips[key]
	if r == nil {
		r = &failRecord{}
		l.ips[key] = r
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
	// Drop addresses whose failures have all aged out, so a scan across
	// many source addresses doesn't grow the map forever.
	for k, r := range l.ips {
		if len(prune(r.times, now.Add(-l.Window))) == 0 && !now.Before(r.lockedUntil) {
			delete(l.ips, k)
		}
	}
}

// Success clears an address's failure count.
func (l *LoginLimiter) Success(ip string) {
	l.mu.Lock()
	delete(l.ips, limitKey(ip))
	l.mu.Unlock()
}

// succeed undoes the failure Begin counted at time at.
func (l *LoginLimiter) succeed(key string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ips, key)
	for i := len(l.global.times) - 1; i >= 0; i-- {
		if l.global.times[i].Equal(at) {
			l.global.times = append(l.global.times[:i], l.global.times[i+1:]...)
			break
		}
	}
}

const loopbackKey = "loopback"

// limitKey groups addresses the way one client holds them: all loopback
// addresses together, and IPv6 by /64, since a single host can pick any
// address in its prefix.
func limitKey(ip string) string {
	a := net.ParseIP(ip)
	switch {
	case a == nil:
		return ip
	case a.IsLoopback():
		return loopbackKey
	case a.To4() != nil:
		return a.To4().String()
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}
