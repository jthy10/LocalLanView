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

// makeDataDir creates dir and returns the directories it had to create,
// outermost first, so they can be handed back to the sudo user.
func makeDataDir(dir string) ([]string, error) {
	var created []string
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		if _, err := os.Lstat(p); err == nil || filepath.Dir(p) == p {
			break
		}
		created = append([]string{p}, created...)
	}
	return created, os.MkdirAll(dir, 0o700)
}

// dataFiles are the files LocalLanView itself keeps in the data directory.
var dataFiles = []string{"locallanview.db", "locallanview.db-wal", "locallanview.db-shm", "tls-cert.pem", "tls-key.pem"}

// handBack gives what this program made back to the sudo user before
// privileges are dropped: the directories it created, the data directory
// if it's the default one, and its own files. It never walks a directory
// the user pointed it at, so -data-dir /srv doesn't give away /srv.
func handBack(dataDir string, created []string, isDefault bool, uid, gid int) {
	dirs := created
	if isDefault {
		dirs = append(dirs, dataDir)
	}
	for _, d := range dirs {
		os.Lchown(d, uid, gid)
	}
	for _, f := range dataFiles {
		os.Lchown(filepath.Join(dataDir, f), uid, gid)
	}
}

// writeFileReplace writes data to a temporary file and renames it over
// path, so a symlink at path is replaced rather than followed.
func writeFileReplace(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), perm); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
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
