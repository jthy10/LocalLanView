Adds an About page.

- New About tab in the sidebar: what LocalLanView is, who made it, and links to the source, license and issue tracker
- Links only open when clicked; the page makes no outbound requests

Grab the binary for your OS below, check it against `SHA256SUMS`, and run it. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
