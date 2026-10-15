package privilege

import (
	"errors"

	"golang.org/x/sys/windows"
)

type osChecker struct{}

func (osChecker) Check() (bool, string) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return true, "Administrator"
	}
	return false, ""
}

// User is an account to drop root privileges to. Windows has no
// equivalent, so it's never used there.
type User struct {
	UID, GID int
	Name     string
	Via      string
}

// DropTarget never finds anyone on Windows.
func DropTarget(runAs string) (User, bool, error) {
	if runAs != "" {
		return User{}, false, errors.New("-run-as isn't supported on Windows")
	}
	return User{}, false, nil
}

// DropTo is never called on Windows.
func DropTo(User) error { return nil }

// IsRoot is always false on Windows; Administrator isn't a separate account.
func IsRoot() bool { return false }
