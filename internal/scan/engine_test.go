package scan

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeCollector struct {
	name  string
	phase Phase
	ok    bool
	order *[]string
	mu    *sync.Mutex
}

func (f fakeCollector) Name() string                  { return f.name }
func (f fakeCollector) Phase() Phase                  { return f.phase }
func (f fakeCollector) Available(bool) (bool, string) { return f.ok, "test" }
func (f fakeCollector) Run(ctx context.Context, env *Env, emit func(Observation)) error {
	f.mu.Lock()
	*f.order = append(*f.order, f.name)
	f.mu.Unlock()
	emit(Observation{Source: f.name, IP: netip.MustParseAddr("10.0.0.1")})
	return nil
}

func TestCyclePhasesAndAvailability(t *testing.T) {
	var order []string
	var mu sync.Mutex
	var got []string
	e := &Engine{
		Env: &Env{},
		Collectors: []Collector{
			fakeCollector{"probe", PhaseProbe, true, &order, &mu},
			fakeCollector{"sweep", PhaseSweep, true, &order, &mu},
			fakeCollector{"off", PhaseDiscover, false, &order, &mu},
			fakeCollector{"mdns", PhaseDiscover, true, &order, &mu},
		},
		Emit: func(o Observation) { mu.Lock(); got = append(got, o.Source); mu.Unlock() },
	}
	e.Cycle(context.Background())
	want := []string{"sweep", "mdns", "probe"}
	if len(order) != 3 || order[0] != want[0] || order[1] != want[1] || order[2] != want[2] {
		t.Fatalf("order = %v, want %v", order, want)
	}
	if len(got) != 3 {
		t.Fatalf("emitted %v", got)
	}
	feats := e.Features()
	if len(feats) != 4 || feats[2].Active {
		t.Fatalf("features = %+v", feats)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(100)
	start := time.Now()
	for i := 0; i < 21; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 180*time.Millisecond {
		t.Fatalf("21 tokens at 100/s took %v, expected ~200ms", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slow := NewLimiter(1)
	slow.Wait(context.Background())
	if err := slow.Wait(ctx); err == nil {
		t.Fatal("expected cancelled wait to fail")
	}
}
