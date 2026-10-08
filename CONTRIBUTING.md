# Contributing

Thanks for helping out.

## Setup

You need Go (see `go.mod` for the version). Nothing else.

```sh
go test ./...
make build        # or .\build.ps1 on Windows
make demo         # run against made-up devices, no network needed
```

## Ground rules

- **No network calls** other than scan traffic on the local subnet. No
  telemetry, update checks or CDN assets.
- **No cgo, no libpcap.** The binary must stay static and cross-compile.
- **New dependencies need a reason** in the PR. Pure Go only.
- **Untrusted input everywhere.** Device names, banners and TXT records come
  from the network. Never put them in `innerHTML`, never pass them to a shell.
- **Tests.** New collectors get a test with a fake responder (see
  `internal/scan/*/..._test.go` and `internal/integration`).

## Common changes

- **Better device types:** edit `internal/fingerprint/rules.json` and add a
  case to `fingerprint_test.go`.
- **New discovery method:** implement `scan.Collector`, emit
  `scan.Observation`s, register it in `internal/app/app.go`.
- **Vendor database refresh:** download the IEEE CSVs and run `make oui`.
- **Schema change:** append a migration in `internal/store/migrate.go`.
  Never edit an existing one.

Run `gofmt` and `go vet ./...` before opening a PR.
