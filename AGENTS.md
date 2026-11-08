# AGENTS.md

档位：L2

## 仓库定位

`komari-monitor/komari`（Komari 探针面板服务端，Go + Gin）的自维护公开 Fork，独立演化、不定期自 upstream 合并主干。

## 远端边界

- `origin` = `dorokuma/komari`：允许推送的远端。
- `upstream` = `komari-monitor/komari`：只读基准源，`pushurl=DISABLED`，严禁推送。
- 提交规范、门禁与收口按 SYSTEM §4。

## 检查

唯一入口 `make check`（verifier 与 CI 只调用它），当前覆盖：

- 增量 `gofmt` 零差异：仅检查相对 `upstream/main`（离线回退分叉基线 commit）新增/修改的 `.go`（上游存量为 CRLF 行尾，全仓 `gofmt -l` 会报 ~327 个历史文件，见下「分歧」）；
- `go vet ./...`；
- `go test ./... -count=1`；
- `RACE_PKGS` 关键并发包 `-race`：`pkg/metric`、`internal/metricstore`、`internal/plugin`、`web/connection`、`web/api/terminal`、`internal/localping`、`utils`、`web/rpc/jsonrpc`、`web/public`、`database/tasks`；
- `build-check`：编译二进制到临时文件后立即删除（依赖下述嵌入产物）。

`make build`：编译二进制 `komari`（依赖下述嵌入产物）。

## 前端嵌入产物

`web/public/public.go` 通过 `go:embed` 依赖 `web/public/defaultTheme/dist.tar.zst` 与 `komari-theme.json`（不入 git，见 `web/public/.gitignore` 与 `web/public/readme.md`）。本地构建/测试前须先按 `web/public/readme.md` 由 `komari-monitor/komari-web` 构建生成；CI 走 `.github/actions/build-frontend`。

## 铁律（本项目特有）

- 运行时隔离红线：严禁触碰 `/root/workspace/komari` 生产实例（密钥、token、SQLite 数据库、缓存、运行中的二进制），一律不得读写。
- 与上游有意分歧的记录位置：公开仓——结论同步写 `AGENTS.md` / README，或本地 `.agents/notes/fork-delta.md`（`.agents/notes/` 已 gitignore，不入库）。
- Git 仓库内只在本仓 worktree 改动，不碰主目录 `/root/workspace/komari-server`。

## 架构分层（指针）

- `cmd/`：子命令入口；`main.go`：程序入口。
- `database/`：持久层（GORM：SQLite/MySQL/PostgreSQL 驱动、记录与迁移）。
- `internal/`：内部业务包（插件、指标存储、备份等）。
- `web/`：HTTP 层——`router`/`api`/`rpc/jsonrpc`/`connection`/`security`/`oauth` 等，`web/public` 为前端嵌入。
- `pkg/`、`utils/`、`protocol/`：可复用组件、工具与探针协议。

## 与 upstream 的有意分歧

- `make check` 的 gofmt 门禁只约束增量文件，规避上游全仓 CRLF 行尾历史包袱（upstream test.yml 的 advisory 注释亦承认 ~327 个文件）。
- 服务端本机正向出站延迟探测：延迟监测任务目标可写本机选择器 `local4`/`@ipv4`（IPv4）或 `local6`/`@ipv6`（IPv6，v6-only/WARP 推荐），由服务端直接探测各节点自报的公网 IP（经 `internal/localping` 的 SSRF 公网单播强校验：IPv6 仅放行 `2000::/3` 且按前缀黑名单拦截 NAT64/Teredo/6to4/文档等转换与保留地址，IPv4 补齐 IANA 特殊用途网段），替代原版纯节点反向下发。ICMP 探测需要 `CAP_NET_RAW`；权限不足时自动回退 Linux `ping_group_range` 非特权 datagram ICMP，仍失败则一次性告警提示授权。新增 `GET /__komari_local_ping.js`，仅在 `/admin*` 页面注入探测方式选择器（`web/public/local_ping_selector.js`）。删除延迟监测任务时先取消在途本机探测并同步刷盘待写队列，再清除指标历史与任务行，保证删除后无孤儿点复活。残余风险：节点自报公网单播 IP 虽经 `ValidatePublicProbeIP` 拦截内网/保留段，被控节点仍可填写第三方公网 IP 让服务端代为探测，已由 3s 超时、HTTP 禁重定向与全局 32 并发上限约束。
  - 前端选择器脚本 `web/public/local_ping_selector.js` 依赖 `komari-web` Ping 任务表单 DOM 锚点（`.km-pingtask-task-form form` / `input[name="ping_target"]`）；未命中输入框时单次 `console.warn` 静默跳过，上游表单结构变更需同步脚本选择器。
  - `GET /__komari_local_ping.js` 为公开静态只读脚本（无敏感数据）；仅精确路径 `/admin` 与 `/admin/*` 在 `</body>` 前注入，`StaticRestricted` 受限恢复监听不注入。
  - `admin:addPingTask` / `admin:editPingTask` 较上游有意收紧：`type` 枚举 `icmp|tcp|http`、正整数 `interval`、非空 `name`/`target`，`BindParams` 失败即 InvalidParams 拦截，并调 `localping.ParseTarget` 校验本机选择器语法（含未闭合方括号、`@` 两侧误写选择器、scheme/path 包裹选择器防线，语法非法目标绝不透传下发 agent）。
  - 删除墓碑（`taskEpoch`/`taskDeleting`/`taskDeleted` + `pingTaskMu`）仅覆盖本机正向探测 `internal/localping` 路径；原版 agent 反向回传接口 `web/api/client/ingest.go -> tasks.SavePingRecord` 维持上游无墓碑存量行为。

## 关联

- 上游：`komari-monitor/komari`；前端：`komari-monitor/komari-web`；探针端 Fork：`dorokuma/komari-agent`（参考其 `AGENTS.md` 模式）。
- 本地笔记（不入库）：`.agents/notes/`
