First public release.

- Finds devices on your LAN with ARP, mDNS, SSDP, NetBIOS, LLMNR, ICMP and a light port scan
- Vendor lookup from the IEEE registry (MA-L/M/S), flags randomized MACs
- Guesses device type with a confidence level and shows why
- Keeps history in a local SQLite file, alerts on new devices
- Web dashboard on 127.0.0.1:8787, password protected, works fully offline

Grab the binary for your OS below, check it against `SHA256SUMS`, and run it. On Linux/macOS: `chmod +x` first. Run as root/admin (or `setcap cap_net_raw+ep` on Linux) for raw ARP and ICMP; it still works without, just sees less.

**Windows:** the exe isn't code-signed yet, so SmartScreen shows "Windows protected your PC". Click **More info** → **Run anyway**. You can confirm the file matches `SHA256SUMS` with `Get-FileHash .\LocalLanView-*.exe`.

**macOS:** Gatekeeper blocks unsigned binaries too. Run `xattr -d com.apple.quarantine ./LocalLanView-*` once, or right-click → Open.
