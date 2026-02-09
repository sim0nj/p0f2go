# 拉依赖（你本机能访问 github 的情况下）
go mod tidy

# 构建 macOS 版 p0f-ebpf
go build ./cmd/p0f-ebpf

# 以 root 运行，抓取 en0 上的 TCP SYN，输出 label
sudo ./bim/p0f-ebpf -iface en0

# 输出 JSON，并暴露 /metrics
sudo ./bin/p0f-ebpf -iface en0 -json -metrics -metrics.addr :9100
