A small fix for updating.

**Fixes**
- After an update, a tab that was already open kept running the previous version's dashboard until it was closed and reopened, so new pages and settings (like **Updates** in 1.5.0) didn't show up. Open pages now notice the new version and reload on their own.

New in 1.5.0: **Updates** under Settings. **Check for updates** asks GitHub for the latest release, and **Update and restart** downloads it, checks it against `SHA256SUMS` and restarts LocalLanView. GitHub is only contacted when you press the button. It isn't available when LocalLanView dropped root after starting (`sudo`, `-run-as`) or got its rights from `setcap`; download the release by hand in that case.

Grab the binary for your OS below and check it: `sha256sum -c --ignore-missing SHA256SUMS`. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
