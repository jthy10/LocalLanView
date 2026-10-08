# Architecture

LocalLanView is one Go binary. No cgo, no runtime dependencies, nothing
downloaded at runtime. The UI, the IEEE vendor registry and the
fingerprint rules are embedded with `go:embed`.

## Why Go

- `CGO_ENABLED=0` gives a static binary for every OS/arch from one machine.
- The standard library covers HTTP/TLS, UDP multicast, TCP probes and crypto.
- Raw ARP and ICMP work without libpcap: `AF_PACKET` on Linux, `/dev/bpf` on
  macOS, `SendARP`/`IcmpSendEcho` on Windows.

Third-party code, all pure Go:

| Module | Why |
|---|---|
| `modernc.org/sqlite` | SQLite without cgo |
| `golang.org/x/crypto` | argon2id password hashing |
| `golang.org/x/net` | DNS messages (mDNS, LLMNR), ICMP, multicast options, macOS routing table |
| `golang.org/x/sys` | Raw sockets, BPF, Windows APIs, privilege checks |
| `golang.org/x/term` | Password prompt without echo |

## Layout

```
cmd/locallanview/      entry point
internal/config/       flags and -addr parsing
internal/privilege/    -mode handling, rights detection, dropping sudo
internal/netinfo/      interface/subnet/gateway detection, scope checks
internal/scan/         Collector interface, engine, rate limiter
  arptable/            OS neighbor cache (+ UDP priming when unprivileged)
  arpsweep/            raw ARP requests
  icmpsweep/           ping sweep
  mdns/ ssdp/ netbios/ llmnr/
  ports/               TCP connect probes + banners
internal/oui/          embedded IEEE MA-L/MA-M/MA-S, longest-prefix lookup
internal/fingerprint/  rule engine + rules.json
internal/inventory/    merges observations into devices, raises events
internal/store/        SQLite schema and queries
internal/alert/        live updates (SSE), webhook, desktop notifications
internal/auth/         passwords, sessions, CSRF, login lockout
internal/web/          HTTP server and JSON API
internal/app/          wires it all together
ui/static/             dashboard (vanilla JS, no build step)
tools/ouigen/          regenerates the vendor database
tools/demoseed/        fills a database with sample devices
```

## Data flow

```
collectors ──Observation──▶ inventory ──▶ fingerprint ──▶ store
                                 │
                                 └──▶ events ──▶ SSE / webhook / notification
```

- Every collector emits `scan.Observation` values: IP, maybe MAC, hostname,
  services, ports, attributes. Nothing else writes device data.
- The engine runs collectors in three phases each cycle: **sweep** (ARP,
  ICMP), **discover** (mDNS, SSDP, NetBIOS, LLMNR), **probe** (ports on
  hosts known to be up).
- One token bucket (`-probe-rate`) limits all probe traffic. Every target
  goes through `netinfo.InScope`, so nothing outside the attached subnet is
  ever contacted.
- Devices are keyed by MAC. A device seen only by IP gets a temporary
  `ip:` key and is merged when its MAC shows up.
- The first scan on a fresh database is a baseline: devices are recorded
  without "new device" alerts.

## Extension points

- **New data sources** (traffic stats, NetFlow/sFlow, LLDP/SNMP) are new
  `scan.Collector`s emitting observations. The inventory, storage and UI
  don't need to know where data came from.
- **Fingerprint rules** are JSON (`internal/fingerprint/rules.json`) loaded
  through `fingerprint.Load`, so user rule files can be added later.
- **Schema changes** are appended to `internal/store/migrate.go`.
