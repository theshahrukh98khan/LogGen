# LogGen build targets.
#
# Windows users without make can run the equivalent go commands directly;
# they are listed in the README.

BINARY  := loggen
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST    := dist

.PHONY: all build run test race vet fmt clean release

all: vet test build

## build: compile for the host platform
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## run: build and start the console
run: build
	./$(BINARY)

## test: run the unit tests
test:
	go test ./... -count=1

## race: run the tests under the race detector (needs a C toolchain)
race:
	go test ./... -race -count=1

## vet: static analysis
vet:
	go vet ./...

## fmt: format all sources
fmt:
	go fmt ./...

## clean: remove build output
clean:
	rm -rf $(BINARY) $(BINARY).exe $(DIST)

## release: cross-compile release binaries for every supported platform
release: clean
	@mkdir -p $(DIST)
	@set -e; for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="$(DIST)/$(BINARY)-$(VERSION)-$$os-$$arch$$ext"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o "$$out" .; \
	done
	@echo ""
	@ls -lh $(DIST)
