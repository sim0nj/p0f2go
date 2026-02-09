# 发布（Release）

## 版本规范
- 语义化版本：MAJOR.MINOR.PATCH
- 变更记录关注：功能、兼容性、性能、安全

## 构建与产物
- 二进制：p0f-ebpf、p0f-ebpf-xdp（amd64/arm64）
- 容器镜像：p0f-ebpf-xdp
- eBPF 对象：容器内 clang 生成与内嵌（规划 bpf2go）

## 流程
- 编译与测试通过
- 镜像构建与运行验证
- 变更记录与文档更新
