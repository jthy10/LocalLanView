Security fixes, a tidier database and a more usable dashboard.

**Upgrading:** if you reach the console on the LAN by a name your router or DNS gives it (like `nas.lan`), add that name with `-allow-host nas.lan`. IP addresses, `localhost`, this machine's own name and TLS certificate names keep working without it.

**Security**
- When bound to the LAN, the console now checks the `Host` header, so a web page on a name that rebinds to this machine can't talk to it. New `-allow-host` flag for extra names.
- Started as root directly, or through `doas` or `pkexec`, LocalLanView now drops root just like under `sudo`. New `-run-as` flag names the account to switch to; without one it warns, on the console and the Capabilities page, that it is staying root.
- A device on the network could make the scanner fetch an SSDP description from another host and file it under the wrong device. The description URL must now point back at the device that sent it.
- Desktop notifications (`notify-send`) no longer read a device name starting with `-` as options.

**Fixes**
- Old data is now pruned once a day: alerts after 90 days (10,000 at most), old addresses, names, services and closed ports after 180 days, devices gone for a year, and randomized-MAC or IP-only devices gone for 30 days. Devices you've named, tagged, noted, trusted or retyped are never removed.
- With a VPN up, or with Docker installed, auto-detection could scan the tunnel or `docker0` instead of your LAN. It now skips those and prefers the interface with your default route.
- Vendor names are matched as whole words, so "...Manufacturing" and "...Engineering" devices are no longer typed as Ring cameras.
- A newly found device could inherit a deleted device's port-scan history and raise new-port alerts for everything on its first scan.

**Dashboard**
- The device list shows 100 devices per page, so big networks stay fast.
- When your session expires or the server goes away, the dashboard says so instead of freezing, and you're returned to the same page after signing in.
- Saving one field on a device page no longer throws away notes or tags you're still typing.
- Long device names wrap instead of making the page scroll sideways on phones.
- Accessibility: better contrast in both themes, keyboard-operable sorting and tabs, labelled fields and buttons, a skip link, and page titles that follow the page.

Grab the binary for your OS below and check it: `sha256sum -c --ignore-missing SHA256SUMS`. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
