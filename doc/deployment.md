# 部署（Deployment）

## 容器运行
- 需 host 网络与 privileged
- RAW（通用）：
  - docker run --rm --net=host --privileged -e IFACE=eth0 --entrypoint ./p0f-ebpf p0f-ebpf-xdp
- XDP（高性能）：
  - docker run --rm --net=host --privileged -e IFACE=eth0 p0f-ebpf-xdp

## 环境注意
- macOS Docker Desktop 对 XDP 加载有限制
- Linux 宿主需支持 XDP 的内核与驱动

## K8s / systemd（规划）
- DaemonSet 模板与 Helm Chart
- systemd 服务与日志轮转
