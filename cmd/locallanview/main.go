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
	"github.com/jthy10/LocalLanView/internal/update"
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
	update.Cleanup()
	err = app.Run(context.Background(), cfg, app.Options{Version: version})
	if errors.Is(err, app.ErrRestart) {
		fmt.Println("Restarting with the new version...")
		err = update.Restart()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "LocalLanView:", err)
		os.Exit(1)
	}
}
