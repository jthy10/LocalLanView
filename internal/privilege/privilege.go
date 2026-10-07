// Package privilege decides whether LocalLanView runs with elevated
// network features. It never prompts for elevation or relaunches itself.
package privilege

import (
	"errors"
	"fmt"
	"runtime"
)

type Mode string

const (
	Auto     Mode = "auto"
	Standard Mode = "std"
	Elevated Mode = "elv"
)

// Status is what the process can do, as decided by the mode and the
// privileges it actually has.
type Status struct {
	Requested Mode   `json:"requested"`
	Elevated  bool   `json:"elevated"`  // elevated features are enabled
	HasRights bool   `json:"hasRights"` // the process has admin/root/capabilities
	Source    string `json:"source"`    // e.g. "root", "CAP_NET_RAW", "Administrator"
	Reason    string `json:"reason"`    // human-readable explanation
}

// Checker reports whether the current process holds elevated rights.
// It's an interface so tests can fake it.
type Checker interface {
	Check() (ok bool, source string)
}

// OS is the Checker for the running operating system.
var OS Checker = osChecker{}

// ErrNotElevated is returned by Resolve in elv mode without rights.
var ErrNotElevated = errors.New("elevated mode requested but the process is not elevated")

// Resolve applies the mode rules:
//
//	auto: elevated features on if the process already has rights
//	std:  elevated features off, always
//	elv:  rights are required, otherwise an error with rerun instructions
func Resolve(mode Mode, c Checker) (Status, error) {
	ok, src := c.Check()
	s := Status{Requested: mode, HasRights: ok, Source: src}
	switch mode {
	case Auto:
		s.Elevated = ok
		if ok {
			s.Reason = fmt.Sprintf("auto mode: running with %s, elevated features enabled", src)
		} else {
			s.Reason = "auto mode: no admin/root rights, running in standard mode"
		}
	case Standard:
		s.Elevated = false
		if ok {
			s.Reason = fmt.Sprintf("std mode: elevated features disabled even though the process has %s", src)
		} else {
			s.Reason = "std mode: elevated features disabled"
		}
	case Elevated:
		if !ok {
			return s, fmt.Errorf("%w.\n%s", ErrNotElevated, RerunHint())
		}
		s.Elevated = true
		s.Reason = fmt.Sprintf("elv mode: running with %s", src)
	default:
		return s, fmt.Errorf("unknown mode %q", mode)
	}
	return s, nil
}

// RerunHint explains how to start the program with the rights elv mode needs.
func RerunHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Open a terminal with \"Run as administrator\" and start LocalLanView again."
	case "linux":
		return "Rerun with sudo, or grant raw socket access once with:\n  sudo setcap cap_net_raw+ep ./LocalLanView"
	default:
		return "Rerun with sudo: sudo ./LocalLanView -mode elv"
	}
}
