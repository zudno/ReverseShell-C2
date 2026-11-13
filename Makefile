# ReverseShell — build / lint / test / cross-compile.
# Quality gates (AGENTS.md): gofmt, go vet, go test -race, go build.

BIN_DIR := bin

.PHONY: all ci lint test build cross-agent clean

all: lint test build

ci: lint test build

lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
	  echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi
	go vet ./...

# -race needs cgo on Windows; local fallback there is `go test ./...`.
# CI (Linux) always enforces the -race gate.
test:
	go test -race ./...

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -o $(BIN_DIR)/ ./cmd/...

# Static agent builds for lab targets (README §12).
cross-agent:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BIN_DIR)/agent.exe    ./cmd/agent
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o $(BIN_DIR)/agent-linux  ./cmd/agent
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o $(BIN_DIR)/agent-arm64  ./cmd/agent

clean:
	rm -rf $(BIN_DIR)
