A fix for console passwords that didn't stick after a restart.

**Fixes**
- A password changed on the Settings page could stop working after the computer restarted, leaving only the first-run password from the terminal. The change sat in SQLite's write-ahead log, which isn't forced to disk, so a hard reset or power cut could lose it. Password changes are now written into the database file and synced right away.
- Starting with `-password-file` or `LOCALLANVIEW_PASSWORD` put that password back on every start, undoing any change made on the Settings page. It's now applied only when the file or variable holds a new value (or with `-set-password`), so console changes survive restarts.
- Built with Go 1.26.11, which fixes an HTTP server crash in the standard library (GO-2026-6859).

New in 1.4.0: the **Use on other devices** switch under Settings, and the `-lan` flag, for opening the dashboard on your phone or other devices on your network.

Grab the binary for your OS below and check it: `sha256sum -c --ignore-missing SHA256SUMS`. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
