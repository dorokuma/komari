# Changelog

All notable changes to this fork will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.6.2] - 2026-11-25

### Added

- 同步上游变更：
  - 终端 WebSocket 新增文本帧控制协议与挂起会话恢复/终止接口，支持固定挂起窗口、Dead-connection 心跳检测与同标签页关闭保护。
  - 新增服务端可选周期流量账本及配置、校准与重置接口，默认透传节点上报总量并支持切换时保留流量基线。
  - 管理员日志查询支持按关键字（`q`）和消息类型（`msg_type`）过滤。
  - 统一全站管理员审计日志格式，并保留本 Fork 的延迟监测参数严格校验。
  - 修复月末自动续费日期跨月漂移问题。
  - WebSocket 连接独立管理在线状态，断连后更快停止本机正向探测。
  - 修复备份白名单 `plugin-data/` 路径拼写错误。
- 重新构建默认前端主题资源，同步上游 `komari-web` 最新界面。

### Changed

- GPU 温度协议字段由整数扩展为浮点数（`float64`），向后兼容旧探针整数上报并保留小数精度（启用新版 `komari-agent` 的 `--gpu` 采集前请先升级服务端）。
- 成功的非 `/api` 静态资源请求（2xx/304）不再记录访问日志，异常 4xx/5xx 请求仍保留记录。

### Fixed

- 补齐 SQL 预览词法解析方言边界校验（拦截异常可执行注释块）。
- 为终端会话关闭增加代数校验与有限写入超时保护，并禁止流量账本在关闭后继续写入。
- 补强审计日志敏感凭据（DSN / Webhook 密钥）脱敏覆盖。

## [1.6.1-r1] - 2026-11-09

### Added

- **服务端本机正向出站延迟探测**：延迟监测任务目标支持本机选择器 `local4` / `@ipv4` 与 `local6` / `@ipv6`（支持 ICMP/TCP/HTTP），由服务端直接探测节点自报的公网 IP；对自报 IP 强制执行公网单播校验以防止 SSRF，非法地址记为 `-1` 不发包。
- **探测方式选择器**：`/admin` 延迟监测弹窗新增「探测方式」下拉选项，支持节点反向 Ping、本机直连 IPv4、本机直连 IPv6 三选一。
- **权限回退与任务生命周期修复**：ICMP 探测需 `CAP_NET_RAW` 权限，权限不足时自动回退 Linux 非特权 datagram ICMP（仍失败时给出一次性授权提示）；删除监测任务时先取消在途探测并刷盘待写队列，再清除指标历史，避免孤儿数据复活。

[Unreleased]: https://github.com/dorokuma/komari/compare/v1.6.2...HEAD
[v1.6.2]: https://github.com/dorokuma/komari/compare/1.6.1-r1...v1.6.2
[1.6.1-r1]: https://github.com/dorokuma/komari/compare/1.6.1...1.6.1-r1
