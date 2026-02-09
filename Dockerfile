FROM golang:1.24 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm linux-libc-dev libbpf-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu -c ebpf/xdp_syn.c -o ebpf/xdp_syn.o
RUN mkdir -p cmd/p0f-ebpf-xdp/ebpf && cp ebpf/xdp_syn.o cmd/p0f-ebpf-xdp/ebpf/xdp_syn.o
RUN go build -o /out/p0f-ebpf-xdp ./cmd/p0f-ebpf-xdp
RUN go build -o /out/p0f-ebpf ./cmd/p0f-ebpf

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /out/p0f-ebpf-xdp ./p0f-ebpf-xdp
COPY --from=builder /src/ebpf/xdp_syn.o ./ebpf/xdp_syn.o
COPY --from=builder /out/p0f-ebpf ./p0f-ebpf
ENV IFACE=eth0
ENTRYPOINT ["./p0f-ebpf-xdp"]
