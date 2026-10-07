package alert

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Notify shows a desktop notification using tools that ship with the OS.
// The text is passed as an argument or environment variable, never through
// a shell, so device names can't inject commands.
func Notify(title, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "osascript",
			"-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run",
			title, body)
	case "windows":
		script := `Add-Type -AssemblyName System.Windows.Forms;` +
			`$n = New-Object System.Windows.Forms.NotifyIcon;` +
			`$n.Icon = [System.Drawing.SystemIcons]::Information;` +
			`$n.Visible = $true;` +
			`$n.ShowBalloonTip(8000, $env:LLV_TITLE, $env:LLV_BODY, 'Info');` +
			`Start-Sleep -Seconds 8; $n.Dispose()`
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
		cmd.Env = append(os.Environ(), "LLV_TITLE="+title, "LLV_BODY="+body)
	default:
		cmd = exec.CommandContext(ctx, "notify-send", "--app-name=LocalLanView", title, body)
	}
	return cmd.Run()
}
