SHELL := /bin/sh
GO ?= go
CLANG ?= clang
GOOS ?= linux
GOARCH ?= amd64
BIN_DIR := bin

.PHONY: all build-xdp build-linux docker-build test clean

all: build-linux

build-xdp:
	if [ -f /usr/include/linux/bpf.h ]; then \
		$(CLANG) -O2 -g -target bpf -c ebpf/xdp_syn.c -o ebpf/xdp_syn.o; \
	else \
		docker build --target builder -t p0f-ebpf-xdp-builder .; \
		cid=$$(docker create p0f-ebpf-xdp-builder); \
		mkdir -p ebpf; \
		docker cp $$cid:/src/ebpf/xdp_syn.o ebpf/xdp_syn.o; \
		docker rm -v $$cid; \
	fi
	mkdir -p cmd/p0f-ebpf-xdp/ebpf
	cp ebpf/xdp_syn.o cmd/p0f-ebpf-xdp/ebpf/xdp_syn.o

build-linux: build-xdp
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(BIN_DIR)/p0f-ebpf-xdp ./cmd/p0f-ebpf-xdp
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(BIN_DIR)/p0f-ebpf ./cmd/p0f-ebpf

build-darwin: build-xdp
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(BIN_DIR)/p0f-ebpf-xdp ./cmd/p0f-ebpf-xdp
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(BIN_DIR)/p0f-ebpf ./cmd/p0f-ebpf

docker-build:
	docker build -t p0f-ebpf-xdp .

test:
	$(GO) test ./...

clean:
	rm -rf $(BIN_DIR) ebpf/xdp_syn.o cmd/p0f-ebpf-xdp/ebpf/xdp_syn.o
