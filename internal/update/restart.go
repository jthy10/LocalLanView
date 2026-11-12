package update

import (
	"os"
	"path/filepath"
	"strings"
)

// restartArgs are the arguments to start the new version with: the same
// ones, minus a password prompt nobody is there to answer, and without
// opening another browser tab.
func restartArgs(args []string) []string {
	out := []string{}
	browser := false
	for _, a := range args {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch {
		case strings.HasPrefix(a, "-") && name == "set-password":
			continue
		case strings.HasPrefix(a, "-") && name == "no-open-browser":
			browser = true
		}
		out = append(out, a)
	}
	if !browser {
		out = append(out, "-no-open-browser")
	}
	return out
}

// Restart replaces this process with the binary now at its path, using
// the same arguments. It only returns on failure.
func Restart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return restart(exe, restartArgs(os.Args[1:]))
}
