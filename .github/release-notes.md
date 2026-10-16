A fix for opening the console from a phone.

**Fixes**
- Typing the console's address without `https://` (for example `192.168.1.50:8787`, which phones turn into `http://`) showed "Client sent an HTTP request to an HTTPS server". Plain HTTP on the console's port now redirects to the same address over HTTPS. This works with LAN access, `-tls-self-signed` and `-tls-cert`.

New in 1.4.0: the **Use on other devices** switch under Settings, and the `-lan` flag, for opening the dashboard on your phone or other devices on your network.

Grab the binary for your OS below and check it: `sha256sum -c --ignore-missing SHA256SUMS`. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
