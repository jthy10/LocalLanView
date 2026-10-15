# Reproducible, static builds: no cgo, no paths or build IDs baked in.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# VERSION reaches recipes through the environment, never pasted into them,
# and check-version refuses anything but a plain version string.
export VERSION
LDFLAGS = -s -w -buildid= -X main.version=$$VERSION
GOFLAGS := -trimpath -buildvcs=false
export CGO_ENABLED := 0

TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build test vet dist clean oui demo check-version

check-version:
	@case "$$VERSION" in ''|*[!A-Za-z0-9._+-]*) \
		echo "VERSION must be letters, digits and ._+- only" >&2; exit 1;; esac

build: check-version
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o LocalLanView ./cmd/locallanview

test:
	go test ./...

vet:
	go vet ./...

dist: check-version clean
	@mkdir -p dist
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=; \
		[ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o "dist/LocalLanView-$$VERSION-$$os-$$arch$$ext" ./cmd/locallanview || exit 1; \
	done
	@# Write to a temp name so SHA256SUMS doesn't list (and mis-hash) itself.
	@cd dist && (sha256sum LocalLanView-* 2>/dev/null || shasum -a 256 LocalLanView-*) > .sums && mv .sums SHA256SUMS
	@cat dist/SHA256SUMS

# Refresh the embedded vendor database. Download the IEEE CSVs first
# (see tools/ouigen/main.go).
oui:
	go run ./tools/ouigen -o internal/oui/data/oui.tsv.gz oui.csv mam.csv oui36.csv iab.csv

demo:
	go run ./tools/demoseed -data-dir demo
	go run ./cmd/locallanview -data-dir demo -mode std

clean:
	rm -rf dist LocalLanView LocalLanView.exe
