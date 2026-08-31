# debvulns (Go) — Makefile
#
# Common targets:
#   make build     — build all three binaries into ./bin (with version baked in)
#   make exporter  — build only the Prometheus exporter
#   make cli       — build only the debvulns CLI
#   make mcp       — build only the debvulns-mcp server
#   make vet       — go vet ./...
#   make fmt       — gofmt -w all sources
#   make clean     — remove ./bin and the build cache
#   make run       — run the exporter on :9222 with a local cache

VERSION ?= 0.1.2
LDFLAGS  := -X github.com/deployatnight/debvulns/internal/exporter.Version=$(VERSION)
GOFLAGS ?=

BIN_DIR := bin
PKGS    := ./cmd/debvulns-exporter ./cmd/debvulns ./cmd/debvulns-mcp

.PHONY: all build exporter cli mcp vet fmt clean run install tidy

all: build

build: exporter cli mcp

exporter:
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/debvulns-exporter ./cmd/debvulns-exporter

cli:
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/debvulns ./cmd/debvulns

mcp:
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/debvulns-mcp ./cmd/debvulns-mcp

vet:
	go vet ./...

fmt:
	@find . -name '*.go' -not -path './.git/*' -exec gofmt -w {} \;

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)

run: exporter
	./$(BIN_DIR)/debvulns-exporter --port 9222 --cache-dir /var/cache/debvulns

install: build
	install -m 0755 $(BIN_DIR)/debvulns-exporter /usr/local/bin/debvulns-exporter
	install -m 0755 $(BIN_DIR)/debvulns        /usr/local/bin/debvulns
	install -m 0755 $(BIN_DIR)/debvulns-mcp     /usr/local/bin/debvulns-mcp
