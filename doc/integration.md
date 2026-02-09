# 集成（Integration）

## 日志采集
- 采集 JSON 到日志管道（FluentBit、Vector）
- 字段映射：label、src/dst、port、ttl、win、mss、options、ecn
- 建议：按 label 聚合，保留原始事件用于审计

## Prometheus
- 暴露核心计数指标与采样信息
- 常见图表：按 label 的速率、丢弃、采样占比

## HTTP 集成
- 批量推送，带重试与退避策略
- 请求
  - 方法：POST
  - 路径：/events（示例）
  - Content-Type：application/json
  - 批量格式：数组，每条为 Agent 的 JSON 事件
  - 建议头：X-Agent-Version、X-Instance-ID、X-Stream
- 字段映射
  - label → os.label
  - src_ip/dst_ip → net.src/dst
  - src_port/dst_port → net.src_port/dst_port
  - ttl/win/mss → tcp.ttl/tcp.win/tcp.mss
  - options → tcp.options[]
  - ecn → tcp.ecn
- 重试与退避
  - 429/5xx：指数退避（如 1s, 2s, 4s, 8s），最大重试 N 次
  - 超过最大重试：写入本地队列或 DLQ
  - 批量大小：建议 100–1000，确保单次请求可控

## Kafka 集成
- Topic：p0f.events
- Key 与分区策略
  - key：net.src 或 os.label（便于按维度聚合）
  - 分区：按 key 的哈希或源网段
- 消息格式
  - JSON：与 Agent 事件一致，增加 meta 字段（version、instance_id、ts）
  - 示例：
```json
{"version":"1.0.0","instance_id":"agent-01","ts":1736240000,"label":"Linux:3.x","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":12345,"dst_port":443,"ttl":64,"win":64240,"mss":1460,"options":["mss","sok","ts","nop","ws"],"ecn":false}
```
- 可靠性
  - acks=all，启用 idempotent producer
  - 重试与退避：同 HTTP，且避免重排
  - DLQ：写入失败消息到 p0f.events.dlq
- RAW 在容器内环境通用；XDP 需 Linux 宿主与驱动支持
- 兼容性
- 建议：生产中 RAW 作为后备，XDP 优先用于高 QPS
- 建议：生产中 RAW 作为后备，XDP 优先用于高 QPS
