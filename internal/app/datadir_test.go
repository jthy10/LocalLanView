package app

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestMakeDataDirReportsCreated(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b", "LocalLanView")
	created, err := makeDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b"), dir}
	if !reflect.DeepEqual(created, want) {
		t.Fatalf("created = %v, want %v", created, want)
	}
	if created, err = makeDataDir(dir); err != nil || len(created) != 0 {
		t.Fatalf("second run: created %v, err %v", created, err)
	}
}

// Under sudo, only what LocalLanView made goes back to the user: never a
// directory they pointed -data-dir at, or other files inside it.
func TestHandBack(t *testing.T) {
	var got []string
	lchown = func(p string, _, _ int) error { got = append(got, p); return nil }
	t.Cleanup(func() { lchown = os.Lchown })

	base := t.TempDir()
	files := func(dir string) []string {
		var out []string
		for _, f := range dataFiles {
			out = append(out, filepath.Join(dir, f))
		}
		return out
	}

	// -data-dir /srv: an existing directory the user chose.
	got = nil
	handBack(base, nil, false, 1000, 1000)
	if want := files(base); !reflect.DeepEqual(got, want) {
		t.Fatalf("user-chosen dir: chowned %v, want only %v", got, want)
	}

	// The default dir, with ~/.config created on the way.
	cfg := filepath.Join(base, ".config")
	dir := filepath.Join(cfg, "LocalLanView")
	got = nil
	handBack(dir, []string{cfg, dir}, true, 1000, 1000)
	want := append([]string{cfg, dir, dir}, files(dir)...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default dir: chowned %v, want %v", got, want)
	}
}

func TestWriteFileReplaceDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "tls-key.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not available:", err)
	}
	if err := writeFileReplace(link, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", b)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("path should now be a regular file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(link); string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
}
