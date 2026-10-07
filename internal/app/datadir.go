package app

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/jthy10/LocalLanView/internal/privilege"
)

// defaultDataDir is the per-user config directory. When run through sudo it
// points at the invoking user's directory, not root's, so the inventory
// stays with the person who owns it.
func defaultDataDir() (string, error) {
	if uid, _, ok := privilege.SudoUser(); ok {
		if u, err := user.LookupId(itoa(uid)); err == nil && u.HomeDir != "" {
			switch runtime.GOOS {
			case "darwin":
				return filepath.Join(u.HomeDir, "Library", "Application Support", "LocalLanView"), nil
			default:
				return filepath.Join(u.HomeDir, ".config", "LocalLanView"), nil
			}
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "LocalLanView"), nil
}

// chownTree hands the data dir back to the sudo user before privileges are
// dropped.
func chownTree(dir string, uid, gid int) {
	filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			os.Lchown(p, uid, gid)
		}
		return nil
	})
}

func itoa(i int) string {
	return fmtInt(int64(i))
}

func fmtInt(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
