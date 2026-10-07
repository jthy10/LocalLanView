// LocalLanView discovers devices on the local network and shows them in a
// web dashboard served from this binary. It never talks to the Internet.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jthy10/LocalLanView/internal/app"
	"github.com/jthy10/LocalLanView/internal/config"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfg, err := config.Parse(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, config.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "LocalLanView:", err)
		os.Exit(2)
	}
	if cfg.Version {
		fmt.Println("LocalLanView", version)
		return
	}
	if err := app.Run(context.Background(), cfg, app.Options{Version: version}); err != nil {
		fmt.Fprintln(os.Stderr, "LocalLanView:", err)
		os.Exit(1)
	}
}
