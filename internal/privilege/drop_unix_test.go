//go:build unix

package privilege

import (
	"errors"
	"strings"
	"testing"
)

func TestDropTarget(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	accounts := map[string]User{
		"alice": {UID: 1000, GID: 1000, Name: "alice"},
		"1000":  {UID: 1000, GID: 1000, Name: "alice"},
		"1002":  {UID: 1002, GID: 1003, Name: "bob"},
		"root":  {UID: 0, GID: 0, Name: "root"},
		"0":     {UID: 0, GID: 0, Name: "root"},
	}
	lookup := func(k string, byID bool) (User, error) {
		if u, ok := accounts[k]; ok {
			return u, nil
		}
		return User{}, errors.New("unknown user " + k)
	}
	tests := []struct {
		name     string
		euid     int
		runAs    string
		env      map[string]string
		uid, gid int
		via      string
		err      string
	}{
		{"via sudo", 0, "", map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1001"}, 1000, 1001, "sudo", ""},
		{"not root", 1000, "", map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1000"}, 0, 0, "", ""},
		{"root without sudo", 0, "", map[string]string{}, 0, 0, "", ""},
		{"sudo from root", 0, "", map[string]string{"SUDO_UID": "0", "SUDO_GID": "0"}, 0, 0, "", ""},
		{"garbage", 0, "", map[string]string{"SUDO_UID": "x", "SUDO_GID": "1"}, 0, 0, "", ""},
		{"missing gid", 0, "", map[string]string{"SUDO_UID": "1000"}, 0, 0, "", ""},
		{"via doas", 0, "", map[string]string{"DOAS_USER": "alice"}, 1000, 1000, "doas", ""},
		{"doas from root", 0, "", map[string]string{"DOAS_USER": "root"}, 0, 0, "", ""},
		{"via pkexec", 0, "", map[string]string{"PKEXEC_UID": "1002"}, 1002, 1003, "pkexec", ""},
		{"run-as name", 0, "alice", map[string]string{"SUDO_UID": "1002", "SUDO_GID": "1003"}, 1000, 1000, "-run-as", ""},
		{"run-as id", 0, "1002", nil, 1002, 1003, "-run-as", ""},
		{"run-as root", 0, "root", nil, 0, 0, "", "other than root"},
		{"run-as unknown", 0, "mallory", nil, 0, 0, "", "unknown user"},
		{"run-as not root", 1000, "alice", nil, 0, 0, "", "started as root"},
	}
	for _, tt := range tests {
		u, ok, err := dropTarget(tt.euid, tt.runAs, env(tt.env), lookup)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%s: err %v, want %q", tt.name, err, tt.err)
			}
			continue
		}
		if err != nil || ok != (tt.via != "") || u.UID != tt.uid || u.GID != tt.gid || u.Via != tt.via {
			t.Errorf("%s: got %+v %v %v, want %d %d %q", tt.name, u, ok, err, tt.uid, tt.gid, tt.via)
		}
	}
}
