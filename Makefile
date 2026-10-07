GO ?= go
PREFIX ?= /usr/local
EXE := $(if $(filter windows,$(shell $(GO) env GOOS)),.exe,)
BINARY := bin/nicotop$(EXE)

.PHONY: build test check bench integration install cross
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o $(BINARY) ./cmd/nicotop

test:
	$(GO) test ./...

check:
	$(GO) vet ./...
	$(GO) test -race ./...

bench:
	$(GO) test -run='^$$' -bench=. -benchmem ./internal/...

integration: build
	python3 -m unittest discover -s scripts -p 'test_*.py'
	python3 scripts/pty_check.py $(BINARY)

install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 755 $(BINARY) "$(DESTDIR)$(PREFIX)/bin/nicotop$(EXE)"

cross:
	@set -e; for target_os in linux darwin windows; do \
	  for target_arch in amd64 arm64; do \
	    extension=""; if [ "$$target_os" = windows ]; then extension=".exe"; fi; \
	    CGO_ENABLED=0 GOOS=$$target_os GOARCH=$$target_arch $(GO) build -trimpath -ldflags='-s -w' \
	      -o "bin/nicotop-$$target_os-$$target_arch$$extension" ./cmd/nicotop; \
	  done; \
	done
