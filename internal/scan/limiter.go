package scan

import (
	"context"
	"sync"
	"time"
)

// Limiter is a simple token bucket shared by all probes so total traffic
// stays under the configured packets-per-second.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func NewLimiter(perSecond int) *Limiter {
	if perSecond < 1 {
		perSecond = 1
	}
	return &Limiter{interval: time.Second / time.Duration(perSecond)}
}

// Wait blocks until the caller may send one probe.
func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	d := time.Until(at)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
