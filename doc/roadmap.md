# 路线图（Roadmap）

## 里程碑
- M1（基础稳定）：RAW/XDP 稳定运行，CLI/JSON/采样/限速
- M2（精确识别）：签名匹配、优先级与冲突处理、IPv6
- M3（可观测性与集成）：Prometheus、HTTP/Kafka 推送
- M4（抓取层增强）：TC 模式、eBPF map 配置、bpf2go
- M5（运维与交付）：K8s DaemonSet、systemd、最小权限

## 关键决策
- 抓取层抽象与事件统一
- RAW 作为后备路径，XDP 优先
- 容器化构建 eBPF，环境缺失自动回退

## 风险与缓解
- XDP 兼容性：提供 TC/RAW 回退
- 峰值事件：rate/sample 双控与批量推送
