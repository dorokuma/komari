# Changelog

All notable changes to this fork will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.6.2] - 2026-11-25

### Added

- 同步 upstream/main 全部 13 条非 Merge 提交（分叉基线 `9a4d7305` 之后）：
  - 终端 WebSocket 文本帧控制协议（`assigned`/`ready`/`abort`/`terminate`/`heartbeat`）、挂起终端会话恢复与终止接口（`admin:listRecoverableTerminalSessions` / `admin:terminateTerminalSessions`）、`cleanupGen`/`cleanupDeadline` 固定挂起窗口与 WebSocket Ping/Pong 死连接检测、同标签页 `client_id` 关闭保护；
  - 服务端可选周期流量账本：新增 `client_traffic_ledgers` 表与 `admin:getClientTraffic` / `admin:updateClientTrafficConfig` / `admin:calibrateClientTraffic` / `admin:resetClientTrafficCycle` 接口，默认 `agent` 模式对未配置节点直通节点反向上报总量，支持切换时保留流量基线与 5 秒超时读取探针 `month_rotate`；
  - `admin:getLogs` 支持可选 `q` 与 `msg_type` 过滤；
  - 统一全站管理员审计日志格式（`database/auditlog/format.go`）：`admin.ping.go` 中本仓 `validatePingTaskParams` 前置强校验 100% 保留，审计日志在 `tasks.*` 操作成功后追加记录；
  - 月末自动续费日期不再跨月漂移（`utils/renewal` `addMonths`）；
  - WS 连接独立管理在线状态，避免 WS 断开后残留 POST 在线标记（本机正向探测更快停止）；
  - 修复备份白名单 `plugin-data/` 拼写。
- 前端嵌入产物同步重新构建：`web/public/defaultTheme/dist.tar.zst` 与 `komari-theme.json` 升级至 `komari-monitor/komari-web` 最新 main（已核验 `.km-pingtask-task-form` 与 `input[name="ping_target"]` DOM 锚点仍然存在，`local_ping_selector.js` 无需改动）。

### Changed

- GPU 温度协议字段由整数改为 `float64`，向后兼容旧探针整数上报并保留新探针小数精度（跨仓顺序约束：须先于启用 `--gpu` 的新版 komari-agent 升级）。
- 非 `/api` 静态资源成功请求（2xx/304，含 `/__komari_local_ping.js`）不再记录访问日志，异常 4xx/5xx 仍记录。
- `Makefile` 的 `RACE_PKGS` 追加 `./internal/trafficledger/`，新增并发内存账本纳入 `-race` 门禁。

## [1.6.1-r1] - 2026-11-09

### Added

- L2 开发基线：`AGENTS.md`、`Makefile`（唯一检查入口 `make check`）、本文件；CI Test workflow 接入 `make check`。
- 服务端本机正向出站延迟探测（`internal/localping`）：延迟监测任务目标支持本机选择器 `local4`/`@ipv4` 与 `local6`/`@ipv6`（icmp/tcp/http），服务端直接探测节点自报公网 IP；自报 IP 必经公网单播强校验（SSRF 防线：IPv6 限定 `2000::/3` 全球单播段并按前缀黑名单拦截 NAT64 `64:ff9b::/96`、`64:ff9b:1::/48`、`100::/64` 丢弃、`2001::/23` IETF 保留、`2001:db8::/32`、`2002::/16` 6to4、`3fff::/20`、`5f00::/16`，IPv4 补齐 `192.0.0.0/24` 与 `192.88.99.0/24`），非法地址记 -1 不发包；`admin:addPingTask`/`admin:editPingTask` 统一校验 type/interval/target。ICMP 探测需要 `CAP_NET_RAW`，权限不足时自动回退 `ping_group_range` 非特权 datagram ICMP，仍失败则一次性告警提示授权；删除任务先取消在途本机探测并同步刷盘待写队列，再清除指标历史，杜绝删除后孤儿点复活。
- `/admin` 延迟监测弹窗「探测方式」选择器：新增 `GET /__komari_local_ping.js` 并在 `/admin*` 页面注入（`web/public/local_ping_selector.js`），支持节点反向 Ping / 本机直连 IPv4 / 本机直连 IPv6 三选一。

### Changed

- `Makefile` 的 `fmt-check` 基线引用优先取 `upstream/main`，不存在时回退到上游分叉基线 commit，离线隔离 clone（origin 已移除）也能跑 `make check`；`RACE_PKGS` 新增 `internal/localping`、`utils` 与 `database/tasks`；`make check` 增加 `build-check`（编译二进制到临时文件后删除，保证可编译性），CI 严格以 `make check` 为唯一检查入口（移除独立 Coverage 跑测步骤）。

[Unreleased]: https://github.com/dorokuma/komari/compare/v1.6.2...HEAD
[v1.6.2]: https://github.com/dorokuma/komari/compare/1.6.1-r1...v1.6.2
[1.6.1-r1]: https://github.com/dorokuma/komari/compare/1.6.1...1.6.1-r1
