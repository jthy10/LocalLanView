package privilege

import (
	"errors"
	"strings"
	"testing"
)

type fake struct {
	ok  bool
	src string
}

func (f fake) Check() (bool, string) { return f.ok, f.src }

func TestResolve(t *testing.T) {
	root := fake{true, "root"}
	user := fake{false, ""}
	tests := []struct {
		mode     Mode
		c        Checker
		elevated bool
		err      bool
	}{
		{Auto, root, true, false},
		{Auto, user, false, false},
		{Standard, root, false, false},
		{Standard, user, false, false},
		{Elevated, root, true, false},
		{Elevated, user, false, true},
		{Mode("x"), root, false, true},
	}
	for _, tt := range tests {
		s, err := Resolve(tt.mode, tt.c)
		if (err != nil) != tt.err {
			t.Errorf("Resolve(%s, %v) err = %v, want err %v", tt.mode, tt.c, err, tt.err)
			continue
		}
		if err == nil && s.Elevated != tt.elevated {
			t.Errorf("Resolve(%s, %v).Elevated = %v, want %v", tt.mode, tt.c, s.Elevated, tt.elevated)
		}
	}
}

func TestResolveElvMessage(t *testing.T) {
	_, err := Resolve(Elevated, fake{})
	if !errors.Is(err, ErrNotElevated) {
		t.Fatalf("want ErrNotElevated, got %v", err)
	}
	if !strings.Contains(err.Error(), RerunHint()) {
		t.Fatalf("error should include rerun instructions: %v", err)
	}
}

func TestStdKeepsSource(t *testing.T) {
	s, _ := Resolve(Standard, fake{true, "CAP_NET_RAW"})
	if !s.HasRights || s.Elevated || !strings.Contains(s.Reason, "CAP_NET_RAW") {
		t.Fatalf("got %+v", s)
	}
}
