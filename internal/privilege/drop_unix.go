//go:build unix

package privilege

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// SudoUser returns the uid/gid of the user who invoked sudo, if any.
func SudoUser() (uid, gid int, ok bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	u, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	g, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || u == 0 {
		return 0, 0, false
	}
	return u, g, true
}

// DropSudo switches the whole process back to the user who ran sudo. Call it
// after raw sockets are open; they keep working after the drop. Returns false
// if there was nothing to drop.
func DropSudo() (bool, error) {
	uid, gid, ok := SudoUser()
	if !ok {
		return false, nil
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return false, fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return false, fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return false, fmt.Errorf("setuid: %w", err)
	}
	return true, nil
}
