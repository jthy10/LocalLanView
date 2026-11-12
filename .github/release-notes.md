One-click updates from the dashboard.

**New**
- **Updates** under Settings. **Check for updates** asks GitHub for the latest release; if there's a newer one, **Update and restart** downloads the build for your OS, checks it against `SHA256SUMS`, makes sure it runs, swaps it in and restarts LocalLanView with the same options. Sign in again afterwards.
- GitHub is only contacted when you press the button. There are still no background update checks or telemetry.
- Updating from the button isn't available when LocalLanView was started with `sudo`/`-run-as` and dropped root, or got its rights from `setcap`, because a restart would lose them. Download the new release and start it the same way instead.

From 1.4.2: password changes made on the Settings page now survive restarts.

Grab the binary for your OS below and check it: `sha256sum -c --ignore-missing SHA256SUMS`. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
