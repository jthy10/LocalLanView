//go:build !windows

package update

import (
	"os"
	"syscall"
)

func restart(exe string, args []string) error {
	return syscall.Exec(exe, append([]string{os.Args[0]}, args...), os.Environ())
}
