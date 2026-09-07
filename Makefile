.DEFAULT_GOAL := all

BINARY := bin/kissl
GO ?= go

.PHONY: all build test test-race run clean

all: build test

build:
	@mkdir -p $(dir $(BINARY))
	$(GO) build -o $(BINARY) .

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

run:
	$(GO) run .

clean:
	rm -rf bin
