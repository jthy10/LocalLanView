package privilege

import "golang.org/x/sys/windows"

type osChecker struct{}

func (osChecker) Check() (bool, string) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return true, "Administrator"
	}
	return false, ""
}

// DropSudo is a no-op on Windows; there's no equivalent of returning to the
// invoking user.
func DropSudo() (bool, error) { return false, nil }

// SudoUser is always empty on Windows.
func SudoUser() (uid, gid int, ok bool) { return 0, 0, false }
