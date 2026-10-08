New dashboard.

- Sidebar layout with a network panel (interface, subnet, host, gateway)
- Overview page: map of every address in the subnet, device type breakdown, recent activity
- Sortable device table with Online / Offline / New / Untrusted filters, or tiles
- Device page with a summary row and tabs for services, ports, history and events
- Status page is now Capabilities, with a short description of each discovery method
- Reworked light and dark themes; still no external fonts, CDN or build step

Grab the binary for your OS below, check it against `SHA256SUMS`, and run it. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
