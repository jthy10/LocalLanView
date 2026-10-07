//go:build unix

package app

import "syscall"

// restrictUmask makes every file the process creates owner-only.
func restrictUmask() { syscall.Umask(0o077) }
