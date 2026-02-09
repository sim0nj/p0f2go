# github.com/sim0nj/p0f2go

被动式 OS 指纹识别库与抓取工具，基于 p0f.fp 生成常量数据，支持 Linux 原始套接字与 eBPF（XDP/后续可扩展 TC）。

## 使用场景
- 资产盘点与 CMDB 补全：为主机/服务增加“OS 指纹”维度
- 网络访问控制与零信任：发现“指纹不符”进行告警或阻断
- 威胁与异常检测：识别扫描器、爬虫、自动化工具来源
- 蜜罐与诱捕：按连接方指纹调整响应策略
- 流量画像与可观测性：形成系统族画像，辅助运营与合规

## 目录结构
- p0f/：常量数据与检测逻辑
  - data.go：由 p0f.fp 解析生成的常量库（Data）
  - model.go：数据结构定义（Entry、DB）
  - packet.go：TCP 选项解析与 PacketMeta
  - detect.go：简化的指纹识别（可扩展为精确签名匹配）
- cmd/
  - p0fgen/：生成器，读取 p0f.fp 输出 p0f/data.go
  - p0f-ebpf/：原始抓包版本（RAW）
  - p0f-ebpf-xdp/：eBPF XDP 版本（需 Linux 宿主与支持网卡）
- ebpf/
  - xdp_syn.c：XDP 程序，解析以太网/IP/TCP（边界检查、采样 SYN）
- Dockerfile：构建镜像，内置 RAW 与 XDP 两套运行入口
- Makefile：本机缺少 Linux 头文件时自动使用容器编译 eBPF

## 快速开始
### 构建镜像
```bash
docker build -t p0f-ebpf-xdp .
```

### 在容器中运行（RAW 抓包，通用且已验证）
```bash
docker run --rm --net=host --privileged -e IFACE=eth0 --entrypoint ./p0f-ebpf p0f-ebpf-xdp
```
- 输出示例：`Linux:3.x`（表示抓到的 TCP SYN 展现 Linux 3.x 栈特征）

### 在容器中运行（XDP，需真 Linux 宿主与支持 XDP 的网卡）
```bash
docker run --rm --net=host --privileged -e IFACE=eth0 p0f-ebpf-xdp
```
- 注：在 macOS + Docker Desktop 或不支持 XDP 的内核/驱动环境可能加载失败

## 本地构建（可选）
```bash
make build-linux     # 交叉构建 Linux 二进制，自动处理 eBPF .o 的生成
make docker-build    # 仅构建 Docker 镜像
make test            # 运行 Go 测试（基础校验）
```
- 当本机缺少 `/usr/include/linux/bpf.h` 等头文件时，Makefile 会启用容器内 clang 编译 `ebpf/xdp_syn.c` 并复制生成物

## 抓取模式
- RAW（原始套接字）
  - 优点：部署简单、容器环境可运行、权限要求低
  - 使用：`./cmd/p0f-ebpf` 或容器 entrypoint 指向 `./p0f-ebpf`
- XDP（eBPF）
  - 优点：高性能低开销，适合高 QPS
  - 前提：Linux 宿主、支持 XDP 的网卡与内核
  - 使用：`./cmd/p0f-ebpf-xdp` 或镜像默认入口
- 计划：TC（clsact ingress），在更多环境易加载（可作为 XDP 的备选）

## 输出与集成
- 标准输出：当前打印识别标签，便于管道/日志采集
- 可扩展：
  - JSON 输出、Prometheus 指标（按 OS 家族/版本）
  - Kafka/HTTP 推送到 SIEM/数据平台

## 路线图（规划）
- 检测引擎：引入精确签名匹配（融合 Data 与 sig 语法），提高命中率并处理优先级/冲突
- 抓取层：增加 TC 版本；保留 RAW 作为通用后备；优化 XDP 解析路径
- IPv6：扩展解析与签名
- 可观测性：JSON/Prometheus/Kafka/HTTP 输出与配置化
- CLI/配置：抓取模式、网卡、过滤器、速率限制、采样比例
- 测试：单元 + 集成（pcap 重放）、性能压测
- 交付：bpf2go 内嵌 .o，多架构镜像，K8s DaemonSet 与 systemd 模板

## 注意事项
- 中间设备可能影响 TCP 选项（代理/防火墙/NAT 会修改或剥离），识别结果需与场景结合判断
- 部分环境（如 Docker Desktop）对 XDP 加载有限制；建议在真 Linux 宿主验证
- 当前 Detect 为简化启发式，后续将以签名匹配为准

## 文档索引
- 查看所有文档：[doc/README.md](file:///Users/simon/go/src/github.com/sim0nj/p0f2go/doc/README.md)
