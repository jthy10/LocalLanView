//go:build unix

package privilege

import "testing"

func TestSudoUser(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	tests := []struct {
		name     string
		euid     int
		env      map[string]string
		uid, gid int
		ok       bool
	}{
		{"via sudo", 0, map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1001"}, 1000, 1001, true},
		{"not root", 1000, map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1000"}, 0, 0, false},
		{"root without sudo", 0, map[string]string{}, 0, 0, false},
		{"sudo from root", 0, map[string]string{"SUDO_UID": "0", "SUDO_GID": "0"}, 0, 0, false},
		{"garbage", 0, map[string]string{"SUDO_UID": "x", "SUDO_GID": "1"}, 0, 0, false},
		{"missing gid", 0, map[string]string{"SUDO_UID": "1000"}, 0, 0, false},
	}
	for _, tt := range tests {
		uid, gid, ok := sudoUser(tt.euid, env(tt.env))
		if uid != tt.uid || gid != tt.gid || ok != tt.ok {
			t.Errorf("%s: got %d %d %v, want %d %d %v", tt.name, uid, gid, ok, tt.uid, tt.gid, tt.ok)
		}
	}
}
