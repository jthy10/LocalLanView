//go:build unix && !linux

package privilege

import "os"

type osChecker struct{}

func (osChecker) Check() (bool, string) {
	if os.Geteuid() == 0 {
		return true, "root"
	}
	return false, ""
}
