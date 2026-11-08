# Changelog

All notable changes to this fork will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- L2 开发基线：`AGENTS.md`、`Makefile`（唯一检查入口 `make check`）、本文件；CI Test workflow 接入 `make check`。
- 服务端本机正向出站延迟探测（`internal/localping`）：延迟监测任务目标支持本机选择器 `local4`/`@ipv4` 与 `local6`/`@ipv6`（icmp/tcp/http），服务端直接探测节点自报公网 IP；自报 IP 必经公网单播强校验（SSRF 防线：IPv6 限定 `2000::/3` 全球单播段并按前缀黑名单拦截 NAT64 `64:ff9b::/96`、`64:ff9b:1::/48`、`100::/64` 丢弃、`2001::/23` IETF 保留、`2001:db8::/32`、`2002::/16` 6to4、`3fff::/20`、`5f00::/16`，IPv4 补齐 `192.0.0.0/24` 与 `192.88.99.0/24`），非法地址记 -1 不发包；`admin:addPingTask`/`admin:editPingTask` 统一校验 type/interval/target。ICMP 探测需要 `CAP_NET_RAW`，权限不足时自动回退 `ping_group_range` 非特权 datagram ICMP，仍失败则一次性告警提示授权；删除任务先取消在途本机探测并同步刷盘待写队列，再清除指标历史，杜绝删除后孤儿点复活。
- `/admin` 延迟监测弹窗「探测方式」选择器：新增 `GET /__komari_local_ping.js` 并在 `/admin*` 页面注入（`web/public/local_ping_selector.js`），支持节点反向 Ping / 本机直连 IPv4 / 本机直连 IPv6 三选一。

### Changed

- `Makefile` 的 `fmt-check` 基线引用优先取 `upstream/main`，不存在时回退到上游分叉基线 commit，离线隔离 clone（origin 已移除）也能跑 `make check`；`RACE_PKGS` 新增 `internal/localping`、`utils` 与 `database/tasks`；`make check` 增加 `build-check`（编译二进制到临时文件后删除，保证可编译性），CI 严格以 `make check` 为唯一检查入口（移除独立 Coverage 跑测步骤）。
