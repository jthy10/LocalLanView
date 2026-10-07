// Package ui holds the dashboard's static files, embedded into the binary.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// FS returns the static files rooted at the web root.
func FS() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
