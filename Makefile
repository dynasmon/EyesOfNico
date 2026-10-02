GO ?= go
PREFIX ?= /usr/local

.PHONY: build test check bench integration install
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o bin/nicotop ./cmd/nicotop

test:
	$(GO) test ./...

check:
	$(GO) vet ./...
	$(GO) test -race ./...

bench:
	$(GO) test -run='^$$' -bench=. -benchmem ./internal/...

integration: build
	python3 scripts/pty_check.py bin/nicotop

install: build
	install -Dm755 bin/nicotop $(DESTDIR)$(PREFIX)/bin/nicotop
