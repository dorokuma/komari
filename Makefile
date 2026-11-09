# 唯一检查入口：verifier 与 CI 只调用 make check。
# 注意：上游存量 Go 源文件为 CRLF 行尾，全仓 gofmt -l 会报 ~327 个历史文件，
# 因此 gofmt 门禁只约束相对 upstream/main 新增或修改的 .go 文件（增量零差异）。
.PHONY: check fmt-check vet test race build-check build

RACE_PKGS := ./pkg/metric/ ./internal/metricstore/ ./internal/plugin/ ./web/connection/ ./web/api/terminal/ ./internal/localping/... ./utils/... ./web/rpc/jsonrpc/ ./web/public/ ./database/tasks/

# 增量 gofmt 基线：优先 upstream/main；离线隔离 clone（origin 已移除、无 upstream
# 远端）时回退到上游分叉基线 commit，保证 make check 不依赖远端引用。
UPSTREAM_BASE_SHA := 9a4d730507d7679977ff1b810f131369e278c694

check: fmt-check vet test race build-check
	@echo "check: all green"

# 相对基线新增/修改的 .go（含未跟踪新文件），gofmt 必须零差异。
fmt-check:
	@base=""; \
	if git rev-parse --verify -q upstream/main >/dev/null 2>&1; then \
		base="upstream/main"; \
	elif git cat-file -e "$(UPSTREAM_BASE_SHA)^{commit}" 2>/dev/null; then \
		base="$(UPSTREAM_BASE_SHA)"; \
	else \
		echo "fmt-check: 缺少 upstream/main 或上游基线 commit $(UPSTREAM_BASE_SHA)，无法确定增量范围" >&2; exit 1; \
	fi; \
	files=$$( { git diff --name-only --diff-filter=d "$$base" -- '*.go'; \
	             git ls-files --others --exclude-standard '*.go'; } | sort -u ) || exit $$?; \
	if [ -z "$$files" ]; then \
		echo "fmt-check: 无相对 $$base 改动的 .go 文件"; \
	else \
		bad=""; \
		for f in $$files; do \
			out="$$(gofmt -l "$$f")" || exit $$?; \
			[ -n "$$out" ] && bad="$$bad $$out"; \
		done; \
		if [ -n "$$bad" ]; then \
			echo "fmt-check: gofmt 未通过（相对 $$base 的增量 .go 须零差异）:" >&2; \
			echo "$$bad" | tr ' ' '\n' | sed 's/^/  /' >&2; \
			exit 1; \
		fi; \
		echo "fmt-check: ok（已检查相对 $$base 的增量 .go）"; \
	fi

vet:
	go vet ./...

test:
	go test ./... -count=1 -timeout 10m

race:
	go test -race $(RACE_PKGS) -count=1 -timeout 15m

# 编译校验：编译到临时文件并立即删除，不在工作树残留二进制
# （依赖 web/public/defaultTheme/{dist.tar.zst,komari-theme.json} 嵌入产物）。
build-check:
	@tmp="$$(mktemp -u /tmp/komari-build-check.XXXXXX)" || exit $$?; \
	go build -o "$$tmp" . && rm -f "$$tmp"

# 编译二进制（须先备好 web/public/defaultTheme/{dist.tar.zst,komari-theme.json}）
build:
	go build -o komari .
