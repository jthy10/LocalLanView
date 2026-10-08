# Security notes and threat model

LocalLanView holds a map of your whole network: every device, what it
runs, and when it's around. Treat its database and console accordingly.

## What we protect against

| Threat | Mitigation |
|---|---|
| Someone else on the LAN opens the console | Binds to `127.0.0.1` by default. Binding anywhere else requires a password you set yourself (12+ chars, checked for strength), and prints a warning unless TLS is on. |
| Weak or default credentials | No default password. First run generates a random one, prints it once, and stores only an argon2id hash. |
| Password leaking via `ps` or shell history | No `-password` flag. Use `-password-file`, `LOCALLANVIEW_PASSWORD` or the prompt. |
| Brute-force login | Per-address lockout after 10 failures in 15 minutes, a global lockout after 50, plus growing delays. |
| Cross-site request forgery | `SameSite=Strict` cookies, a per-session CSRF token on every state-changing request, and an Origin check. Login only accepts JSON. |
| DNS rebinding against the loopback console | Requests with a non-loopback `Host` header are rejected when bound to loopback. |
| XSS through device names, banners, TXT records | The UI never uses `innerHTML` for data. Strict CSP: `script-src 'self'`, no inline script or style. |
| Formula injection in CSV export | Cells starting with `= + - @` are prefixed with `'`. |
| Other local users reading the database | Data dir is `0700`, files `0600`, process umask `077` (Unix). On Windows it lives in the user's profile. |
| Running as root longer than needed | Raw sockets are opened first, then the process drops back to the `sudo` user. On Linux, `setcap cap_net_raw+ep` avoids root entirely. |
| Data leaving the network | No telemetry, update checks or CDN assets. HTTP clients ignore proxy settings. SSDP descriptions are only fetched from addresses inside the subnet. Webhooks must point at loopback/private IPs. |
| Probing things you didn't mean to | All probes are rate limited and restricted to the attached subnet (largest /16). `-subnet` can only narrow it. |

## Not covered

- **Plain HTTP on the LAN.** If you bind to a non-loopback address without
  TLS, the password and data cross the network unencrypted. Use
  `-tls-self-signed` or your own certificate.
- **A compromised machine.** Anyone who can run code as your user can read
  the database.
- **Active attackers on the LAN.** Devices can lie in mDNS, SSDP and
  banners. Treat names and types as hints, not proof. The "MAC changed"
  alert can catch some ARP spoofing but isn't an IDS.
- **Sessions** live in memory and are lost on restart (you log in again).

## Scanning responsibly

Only scan networks you own or are authorized to administer. Port scanning
someone else's network can break their policies or the law.
