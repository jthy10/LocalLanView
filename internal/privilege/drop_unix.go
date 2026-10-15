//go:build unix

package privilege

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// User is an account to drop root privileges to.
type User struct {
	UID, GID int
	Name     string
	Via      string // "sudo", "doas", "pkexec" or "-run-as"
}

// DropTarget picks the account to switch to after the raw sockets are open:
// the -run-as user if one was given, otherwise whoever ran sudo, doas or
// pkexec. ok is false when the process isn't root or there's nobody to
// drop to.
func DropTarget(runAs string) (u User, ok bool, err error) {
	return dropTarget(os.Geteuid(), runAs, os.Getenv, lookupUser)
}

type lookupFunc func(nameOrID string, byID bool) (User, error)

func dropTarget(euid int, runAs string, getenv func(string) string, lookup lookupFunc) (User, bool, error) {
	if runAs != "" {
		if euid != 0 {
			return User{}, false, errors.New("-run-as only applies when started as root")
		}
		_, err := strconv.Atoi(runAs)
		u, err := lookup(runAs, err == nil)
		if err != nil {
			return User{}, false, fmt.Errorf("-run-as: %w", err)
		}
		if u.UID == 0 {
			return User{}, false, errors.New("-run-as: must be an account other than root")
		}
		u.Via = "-run-as"
		return u, true, nil
	}
	if euid != 0 {
		return User{}, false, nil
	}
	if u, err1 := strconv.Atoi(getenv("SUDO_UID")); err1 == nil && u != 0 {
		if g, err2 := strconv.Atoi(getenv("SUDO_GID")); err2 == nil {
			return User{UID: u, GID: g, Name: getenv("SUDO_USER"), Via: "sudo"}, true, nil
		}
	}
	// doas and pkexec don't pass a numeric gid; look the account up.
	if name := getenv("DOAS_USER"); name != "" {
		if u, err := lookup(name, false); err == nil && u.UID != 0 {
			u.Via = "doas"
			return u, true, nil
		}
	}
	if id := getenv("PKEXEC_UID"); id != "" {
		if u, err := lookup(id, true); err == nil && u.UID != 0 {
			u.Via = "pkexec"
			return u, true, nil
		}
	}
	return User{}, false, nil
}

func lookupUser(nameOrID string, byID bool) (User, error) {
	var u *user.User
	var err error
	if byID {
		u, err = user.LookupId(nameOrID)
	} else {
		u, err = user.Lookup(nameOrID)
	}
	if err != nil {
		return User{}, err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return User{}, fmt.Errorf("account %q has a non-numeric id", nameOrID)
	}
	return User{UID: uid, GID: gid, Name: u.Username}, nil
}

// DropTo switches the whole process to u. Call it after raw sockets are
// open; they keep working after the drop.
func DropTo(u User) error {
	if err := syscall.Setgroups([]int{u.GID}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(u.GID); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(u.UID); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	return nil
}

// IsRoot reports whether the process runs as uid 0.
func IsRoot() bool { return os.Geteuid() == 0 }
