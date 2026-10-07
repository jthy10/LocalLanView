package scan

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Engine runs collectors every Interval, phase by phase.
type Engine struct {
	Collectors []Collector
	Env        *Env
	Interval   time.Duration
	Emit       func(Observation)
	Log        *slog.Logger

	// OnCycle, if set, is called when a cycle starts and finishes.
	OnCycle func(running bool, started time.Time)

	trigger chan struct{}
	once    sync.Once
}

func (e *Engine) init() {
	e.once.Do(func() {
		e.trigger = make(chan struct{}, 1)
		if e.Log == nil {
			e.Log = slog.Default()
		}
	})
}

// Features lists every collector and whether it's active.
func (e *Engine) Features() []Feature {
	out := make([]Feature, 0, len(e.Collectors))
	for _, c := range e.Collectors {
		ok, why := c.Available(e.Env.Elevated)
		out = append(out, Feature{Name: c.Name(), Active: ok, Reason: why})
	}
	return out
}

// ScanNow asks the engine to start a cycle as soon as possible.
func (e *Engine) ScanNow() {
	e.init()
	select {
	case e.trigger <- struct{}{}:
	default:
	}
}

// Run blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	e.init()
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.trigger:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}
		e.Cycle(ctx)
		t.Reset(e.Interval)
	}
}

// Cycle runs one full scan: all collectors of a phase in parallel, phases in
// order.
func (e *Engine) Cycle(ctx context.Context) {
	e.init()
	start := time.Now()
	if e.OnCycle != nil {
		e.OnCycle(true, start)
		defer func() { e.OnCycle(false, start) }()
	}
	for _, phase := range []Phase{PhaseSweep, PhaseDiscover, PhaseProbe} {
		var wg sync.WaitGroup
		for _, c := range e.Collectors {
			if c.Phase() != phase {
				continue
			}
			if ok, _ := c.Available(e.Env.Elevated); !ok {
				continue
			}
			wg.Add(1)
			go func(c Collector) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						e.Log.Error("collector panicked", "collector", c.Name(), "panic", r)
					}
				}()
				t0 := time.Now()
				if err := c.Run(ctx, e.Env, e.Emit); err != nil && ctx.Err() == nil {
					e.Log.Warn("collector failed", "collector", c.Name(), "err", err)
					return
				}
				e.Log.Debug("collector done", "collector", c.Name(), "took", time.Since(t0).Round(time.Millisecond))
			}(c)
		}
		wg.Wait()
		if ctx.Err() != nil {
			return
		}
	}
	e.Log.Info("scan cycle finished", "took", time.Since(start).Round(time.Millisecond))
}
