Use the dashboard from your phone, tablet or any other device on your network.

**New: open the console to your network**
- Settings has a new **Use on other devices** switch, off by default. Turn it on and the page tells you where to go, e.g. "Go to https://192.168.1.50:8787 on any device connected to your network."
- Or start with `-lan`. The choice is remembered across restarts; `-lan=false` turns it off again.
- The address is also shown as **Web app** in the sidebar's Network card, on the Capabilities page and in the terminal.
- Only the web console restarts when you switch; scanning keeps going. On the network it always uses HTTPS with a self-signed certificate, so browsers warn about it once.
- You need your own password first; the generated first-run one isn't allowed on the network. If other devices can't connect, allow port 8787 through this computer's firewall.
- `-addr` still works and overrides the setting.

**Fixes**
- With `-addr 0.0.0.0`, the dashboard link pointed at `https://[::1]:8787/` instead of `127.0.0.1`.

Grab the binary for your OS below and check it: `sha256sum -c --ignore-missing SHA256SUMS`. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
