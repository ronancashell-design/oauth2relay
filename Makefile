BINARY  := oauth2relay
VENV    ?= test_scripts/.venv
PYTHON  ?= $(if $(wildcard $(VENV)/bin/python),$(abspath $(VENV))/bin/python,python3)

# The version comes from the latest tag, e.g. v2.0.0 -> 2.0.0, or
# 2.0.0-3-gabc1234-dirty between tags. Override with make VERSION=...
VERSION ?= $(patsubst v%,%,$(shell git describe --tags --always --dirty 2>/dev/null || echo dev))
LDFLAGS := -s -w -X main.VERSION=$(VERSION)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

# Release targets, as GOOS/GOARCH.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
DIST      := dist
# Files shipped in every release archive next to the binary.
DOCS      := LICENSE NOTICE README.md SECURITY.md UPGRADING.md docs/OPERATIONS.md deploy/systemd/oauth2relay.service examples/config.example.json

IMAGE ?= oauth2relay

# go-licenses is installed in .tools for the build machine; GOOS then only
# selects which platform's dependencies it inspects. Like govulncheck, it is
# built with the module's own toolchain, in a directory per Go version: it
# finds the standard library through the Go installation it was built with,
# so it is rebuilt when the toolchain changes.
TOOLS       := $(abspath .tools)
GO_VERSION  := $(shell go env GOVERSION)
GO_LICENSES := $(TOOLS)/$(GO_VERSION)/go-licenses
# Licence types that must not be compiled into the binaries: GPL, LGPL and
# AGPL among others, and licences go-licenses cannot identify.
DISALLOWED_LICENCES := forbidden,restricted,unknown

.PHONY: build test test-race cover vet lint integration vulncheck licenses notice release docker clean

# The command is in cmd/oauth2relay; the other packages are the library the
# commercial edition builds on.
CMD := ./cmd/oauth2relay

build:
	$(GOBUILD) -o $(BINARY) $(CMD)

test:
	go test ./...

test-race:
	go test -race ./...

# Total coverage of the module, counting code exercised from other packages.
cover:
	go test -coverpkg=./... -coverprofile=coverage.out ./... >/dev/null
	go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

lint:
	golangci-lint run

# The Python suite runs against the binary in the repository root.
integration: build
	cd test_scripts && $(PYTHON) -m pytest -q

# Build govulncheck with the module's own toolchain; a govulncheck binary
# built with an older Go cannot load this module's packages.
vulncheck:
	GOTOOLCHAIN=$$(go env GOVERSION) go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

# Fails on a disallowed licence in any release platform's dependencies, or
# when NOTICE does not match "make notice".
$(GO_LICENSES):
	GOTOOLCHAIN=$(GO_VERSION) GOBIN=$(dir $(GO_LICENSES)) go install github.com/google/go-licenses@v1.6.0

licenses: $(GO_LICENSES)
	@set -e; for os in linux darwin windows; do \
		echo "checking licences for $$os"; \
		out=$$(GOOS=$$os $(GO_LICENSES) check ./... --disallowed_types=$(DISALLOWED_LICENCES) 2>&1) || \
			{ echo "$$out" | grep -v '^W'; exit 1; }; \
	done
	@GO_LICENSES="$(GO_LICENSES)" bash scripts/notice.sh | diff -u NOTICE - || \
		{ echo "NOTICE is out of date: run make notice"; exit 1; }
	@echo "licences OK"

# Regenerates NOTICE from the dependencies.
notice: $(GO_LICENSES)
	GO_LICENSES="$(GO_LICENSES)" bash scripts/notice.sh > NOTICE.tmp
	mv NOTICE.tmp NOTICE

# One archive per platform (.tar.gz, or .zip for Windows) and SHA256SUMS.
release:
	rm -rf $(DIST)
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		name=$(BINARY)_$(VERSION)_$${os}_$${arch}; dir=$(DIST)/$$name; \
		echo "building $$name"; \
		mkdir -p $$dir; \
		GOOS=$$os GOARCH=$$arch $(GOBUILD) -o $$dir/$(BINARY)$$ext $(CMD); \
		cp --parents $(DOCS) $$dir/; \
		if [ $$os = windows ]; then \
			(cd $(DIST) && zip -qr $$name.zip $$name); \
		else \
			tar -C $(DIST) --owner=0 --group=0 -czf $(DIST)/$$name.tar.gz $$name; \
		fi; \
		rm -rf $$dir; \
	done
	cd $(DIST) && sha256sum $(BINARY)_* > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

clean:
	rm -rf $(BINARY) $(DIST) $(TOOLS)
