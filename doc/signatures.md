# 签名（Signatures）

## p0f.fp
- OS 指纹规则文件，包含 TTL/窗口/MSS/选项等模式
- 用于生成常量库并参与匹配

## 生成与使用
- 生成器： [p0fgen](file:///Users/simon/go/src/github.com/sim0nj/p0f2go/cmd/p0fgen/main.go)
- 常量库： [p0f/data.go](file:///Users/simon/go/src/github.com/sim0nj/p0f2go/p0f/data.go)
- 模型： [p0f/model.go](file:///Users/simon/go/src/github.com/sim0nj/p0f2go/p0f/model.go)

## 引擎演进
- 当前：启发式识别（TTL、选项、MSS 等）
- 计划：基于 p0f.fp 的精确匹配，处理优先级与冲突
- IPv6：扩展解析与匹配
