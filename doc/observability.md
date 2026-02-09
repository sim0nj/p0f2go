# 可观测性（Observability）

## 目标
- 输出结构化事件，便于日志与监控系统接入 [logx](https://github.com/sim0nj/logx)
- 控制事件速率与采样比例，保持系统稳定

## JSON 字段
- label：识别结果（如 Linux:3.x）
- src_ip / dst_ip：源/目的 IP
- src_port / dst_port：源/目的端口
- ttl, win, mss：IP TTL、TCP 窗口、MSS
- options：TCP 选项列表（mss、ws、sok、ts、nop）
- ecn：是否启用 ECN

## 输出示例
```json
{"label":"Linux:3.x","ttl":64,"win":64240,"mss":1460,"options":["mss","sok","ts","nop","ws"],"ecn":false,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":12345,"dst_port":443}
```

## 速率与采样
- rate：每秒最大输出事件数（0 表示不限）
- sample：采样比例 0..1（1 表示全量）

## 指标（规划）

- p0f_events_total{label}
  - 计数器，按 OS 指纹标签累计识别到的事件总数
  - 用途：看各类指纹的流量占比与趋势；做容量评估和基线对比
- p0f_events_dropped_total{reason}
  - 计数器，累计被丢弃的事件（原因含 rate_limit、sample、error）
  - 用途：区分“主动控制”（采样/限速）与“异常”（error）；评估丢弃比例是否可接受
- p0f_sampling_ratio
  - 仪表盘（Gauge），当前采样比例
  - 用途：结合事件速率估算真实流量；采样变化时作为图表注释与告警抑制依据
- p0f_rate_limit
  - 仪表盘（Gauge），当前最大输出速率（events/s）
  - 用途：判断是否“撞顶”导致剪峰；指导调参（提高限速或改批处理）
- p0f_output_errors_total{type}
  - 计数器，输出链路的错误累计（如 http_batch_fail、kafka_produce_fail、json_encode_err）
  - 用途：监控可靠性与重试效果；定位具体失败类型和下游问题
常见用法

- 按指纹类别的事件速率
  - sum by (label) (rate(p0f_events_total[5m])) → 观察主流 OS 指纹的变化与峰谷
- 丢弃比例与原因分解
  - ratio = sum(rate(p0f_events_dropped_total[5m])) / (sum(rate(p0f_events_total[5m])) + sum(rate(p0f_events_dropped_total[5m])))
  - 再按 reason 维度展开，区分 rate_limit / sample / error
- 采样下的真实量估算
  - est = sum by (label) (rate(p0f_events_total[5m])) / p0f_sampling_ratio
  - 采样变化时注意图表断点与解释
- 限速剪峰检测
  - rate(p0f_events_dropped_total{reason="rate_limit"}[5m]) > 0 且 p0f_rate_limit 稳定 → 说明撞限速，考虑提升限速或改聚合/批量
- 输出错误告警
  - rate(p0f_output_errors_total[5m]) > 0 持续 10m → 下游不可用或重试失败，需要检查 HTTP/Kafka/存储等链路

## 采集示例（Prometheus）
- 假设 Agent 暴露 /metrics（文本格式），Prometheus 配置示例：
```yaml
scrape_configs:
  - job_name: p0f2go
    static_configs:
      - targets: ['10.0.0.10:9100']  # 示例端口
    metrics_path: /metrics
    scrape_interval: 15s
```
- 若暂未内置 /metrics，可通过 sidecar 将 STDOUT 转换为指标：
  - 将 JSON 事件按 label 聚合，定期输出计数到文本文件
  - 使用 node_exporter textfile collector 读取并暴露
  - 文本示例：
```
p0f_events_total{label="Linux:3.x"} 1523
p0f_events_dropped_total{reason="rate_limit"} 37
p0f_sampling_ratio 0.5
```

## 相关代码
- XDP： [p0f-ebpf-xdp/main_linux.go](file:///Users/simon/go/src/p0f2go/cmd/p0f-ebpf-xdp/main_linux.go)
- RAW： [p0f-ebpf/main_linux.go](file:///Users/simon/go/src/p0f2go/cmd/p0f-ebpf/main_linux.go)
