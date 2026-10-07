package app

import (
	"os"
	"os/exec"
	"runtime"
)

// openBrowser opens url in the default browser. It's skipped when running
// as root (the browser would run as root too) or with no display.
func openBrowser(url string) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		cmd = exec.Command("xdg-open", url)
	}
	if cmd.Start() == nil {
		go cmd.Wait()
	}
}
