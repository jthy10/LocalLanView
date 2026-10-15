Security and reliability fixes. Everyone should update.

**Security**
- Built with Go 1.26.9 and golang.org/x/net v0.60.0. Earlier releases were built with Go 1.26.0, which has known vulnerabilities in HTTP, TLS, XML and header parsing that a device on your network could reach.
- A burst of parallel login attempts could get far more password guesses than the lockout allows, and use gigabytes of memory doing it. Attempts now count as soon as they start and only two password checks run at once. A flood of guesses from the network no longer locks you out of the console on the machine itself.
- A device could take over another device's record (the router's, for example) by reporting its MAC address over NetBIOS. That MAC is now only shown, never used to identify the device.
- Under `sudo`, LocalLanView no longer hands the whole `-data-dir` tree to your user, no longer leaves `~/.config` owned by root, and exits if it can't drop root.

**Fixes**
- One mDNS packet with a malformed name stopped mDNS discovery for every scan. It's now handled.
- When a new device got an address an old, offline device used to have, you'd get a false "ARP spoofing" alert and the old device showed as online.
- A known device getting a new address no longer raises a "New device" alert.
- In the dashboard, a slow page could draw over the page you had already moved to.
- `SHA256SUMS` listed a wrong checksum for itself, so `sha256sum -c` reported a failure. Fixed.
- `-version` works even when other flags have bad values. The `-webhook` and `-notify` help now says they send every alert.

Grab the binary for your OS below and check it: `sha256sum -c --ignore-missing SHA256SUMS`. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
