package public

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/pkg/jsruntime"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNormalizeHTMLLanguage(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"hyphen language": {
			input: "zh-CN",
			want:  "zh-CN",
		},
		"underscore language": {
			input: "zh_CN",
			want:  "zh-CN",
		},
		"reject script injection": {
			input: `zh-CN" autofocus`,
		},
		"reject too short": {
			input: "z",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := normalizeHTMLLanguage(tt.input); got != tt.want {
				t.Fatalf("normalizeHTMLLanguage(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestReplaceHTMLLanguage(t *testing.T) {
	tests := map[string]struct {
		html     string
		language string
		want     string
	}{
		"replace existing lang": {
			html:     `<html lang="en"><head></head></html>`,
			language: "zh-CN",
			want:     `<html lang="zh-CN"><head></head></html>`,
		},
		"insert missing lang": {
			html:     `<html><head></head></html>`,
			language: "ja_JP",
			want:     `<html lang="ja-JP"><head></head></html>`,
		},
		"ignore invalid lang": {
			html:     `<html lang="en"><head></head></html>`,
			language: `zh-CN" autofocus`,
			want:     `<html lang="en"><head></head></html>`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := replaceHTMLLanguage(tt.html, tt.language); got != tt.want {
				t.Fatalf("replaceHTMLLanguage() = %q, want %q", got, tt.want)
			}
		})
	}
}

// sharedDistDir extracts the embedded dist archive once per test binary.
// Extraction dominates these tests' runtime, so both dist-related tests reuse
// a single copy instead of unpacking the archive twice.
var (
	sharedDistOnce sync.Once
	sharedDistPath string
	sharedDistErr  error
)

func extractSharedDist(t *testing.T) string {
	t.Helper()
	sharedDistOnce.Do(func() {
		dir, err := os.MkdirTemp("", "komari-public-dist-*")
		if err != nil {
			sharedDistErr = err
			return
		}
		if err := extractDistArchive(embeddedDistArchive, dir); err != nil {
			sharedDistErr = err
			_ = os.RemoveAll(dir)
			return
		}
		sharedDistPath = dir
	})
	if sharedDistErr != nil {
		t.Fatalf("extract embedded dist: %v", sharedDistErr)
	}
	return sharedDistPath
}

func TestEmbeddedDistDoesNotEmbedRawFiles(t *testing.T) {
	if _, err := PublicFS.ReadFile("defaultTheme/dist/index.html"); err == nil {
		t.Fatal("PublicFS still embeds the raw frontend files")
	}
	content, err := os.ReadFile(filepath.Join(extractSharedDist(t), IndexFile))
	if err != nil || len(content) == 0 {
		t.Fatalf("embedded dist does not contain a non-empty %q", IndexFile)
	}
}

func TestStaticRestrictedDoesNotServeCustomAssetOverride(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldDefaultDistCacheDir := defaultDistCacheDir
	defaultDistCacheDir = extractSharedDist(t)
	t.Cleanup(func() {
		defaultDistCacheDir = oldDefaultDistCacheDir
	})
	t.Chdir(t.TempDir())
	assetPath := filepath.Join("data", "theme", "custom", "dist", "assets")
	if err := os.MkdirAll(assetPath, 0o755); err != nil {
		t.Fatalf("create custom theme asset directory: %v", err)
	}
	const assetName = "about-D4JKo971.css"
	if err := os.WriteFile(filepath.Join(assetPath, assetName), []byte("custom override"), 0o644); err != nil {
		t.Fatalf("write custom theme asset: %v", err)
	}

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open config db: %v", err)
	}
	config.SetDb(db)
	if err := config.Set(config.ThemeKey, "custom"); err != nil {
		t.Fatalf("set custom theme: %v", err)
	}

	router := gin.New()
	StaticRestricted(router.Group("/"), func(handlers ...gin.HandlerFunc) {
		router.NoRoute(handlers...)
	})
	for _, requestPath := range []string{"/assets/" + assetName} {
		request := httptest.NewRequest("GET", requestPath, nil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != 200 {
			t.Fatalf("restricted asset %s status = %d, want 200", requestPath, recorder.Code)
		}
		body, err := io.ReadAll(recorder.Result().Body)
		if err != nil {
			t.Fatalf("read restricted asset %s: %v", requestPath, err)
		}
		if string(body) == "custom override" {
			t.Fatalf("restricted listener served a custom theme asset override for %s", requestPath)
		}
	}

	indexRequest := httptest.NewRequest("GET", "/database-recovery", nil)
	indexRecorder := httptest.NewRecorder()
	router.ServeHTTP(indexRecorder, indexRequest)
	indexBody, err := io.ReadAll(indexRecorder.Result().Body)
	if err != nil {
		t.Fatalf("read restricted index: %v", err)
	}
	if strings.Contains(string(indexBody), `vite-plugin-pwa:register-sw`) {
		t.Fatal("restricted index still registers a service worker")
	}
}

// setupStaticTestRouter 准备嵌入式 dist 缓存与空配置库，返回挂了 static 的 router。
func setupStaticTestRouter(t *testing.T, restricted bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	oldDefaultDistCacheDir := defaultDistCacheDir
	defaultDistCacheDir = extractSharedDist(t)
	t.Cleanup(func() {
		defaultDistCacheDir = oldDefaultDistCacheDir
	})
	t.Chdir(t.TempDir())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open config db: %v", err)
	}
	config.SetDb(db)

	router := gin.New()
	if restricted {
		StaticRestricted(router.Group("/"), func(handlers ...gin.HandlerFunc) {
			router.NoRoute(handlers...)
		})
	} else {
		Static(router.Group("/"), func(handlers ...gin.HandlerFunc) {
			router.NoRoute(handlers...)
		})
	}
	return router
}

func getBody(t *testing.T, router *gin.Engine, path string) (int, string, http.Header) {
	t.Helper()
	request := httptest.NewRequest("GET", path, nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatalf("read %s body: %v", path, err)
	}
	return recorder.Code, string(body), recorder.Result().Header
}

// TestLocalPingSelectorInjection 验证探测方式选择器脚本只在 /admin 页面注入，
// 公开首页不注入，受限监听（StaticRestricted）不注入。
// wantScriptTag 刻意使用字面量而非导出常量：本测试要能在未引入该常量的裸基线
// commit 上直接编译运行（双快照先红后绿对照）。
const wantScriptTag = `<script src="/__komari_local_ping.js" defer></script>`

func TestLocalPingSelectorInjection(t *testing.T) {
	router := setupStaticTestRouter(t, false)

	code, body, _ := getBody(t, router, "/admin/ping")
	if code != 200 || !strings.Contains(body, wantScriptTag) {
		t.Fatalf("/admin/ping status=%d injected=%v, want 200 with script tag",
			code, strings.Contains(body, wantScriptTag))
	}

	// /admin 精确匹配注入；/adminfoo 非后台路径不注入。
	code, body, _ = getBody(t, router, "/admin")
	if code != 200 || !strings.Contains(body, wantScriptTag) {
		t.Fatalf("/admin status=%d injected=%v, want 200 with script tag",
			code, strings.Contains(body, wantScriptTag))
	}
	code, body, _ = getBody(t, router, "/adminfoo")
	if code != 200 || strings.Contains(body, "__komari_local_ping.js") {
		t.Fatalf("/adminfoo status=%d injected=%v, want 200 without script tag",
			code, strings.Contains(body, "__komari_local_ping.js"))
	}

	code, body, header := getBody(t, router, "/__komari_local_ping.js")
	if code != 200 {
		t.Fatalf("/__komari_local_ping.js status = %d, want 200", code)
	}
	if ct := header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("/__komari_local_ping.js Content-Type = %q, want javascript", ct)
	}
	if !strings.Contains(body, "探测方式") || !strings.Contains(body, "local4") {
		t.Fatal("/__komari_local_ping.js body does not look like the selector script")
	}

	code, body, _ = getBody(t, router, "/")
	if code != 200 || strings.Contains(body, "__komari_local_ping.js") {
		t.Fatalf("/ status=%d injected=%v, want 200 without script tag",
			code, strings.Contains(body, "__komari_local_ping.js"))
	}
}

func TestLocalPingSelectorNotInjectedInRestricted(t *testing.T) {
	router := setupStaticTestRouter(t, true)

	code, body, _ := getBody(t, router, "/admin/ping")
	if code != 200 || strings.Contains(body, "__komari_local_ping.js") {
		t.Fatalf("restricted /admin/ping status=%d injected=%v, want no injection",
			code, strings.Contains(body, "__komari_local_ping.js"))
	}
}

// localPingSelectorDOMStub 是被测脚本所需的最小 DOM 模型：窗口、文档、
// Event、HTMLInputElement、.km-pingtask-task-form 表单、
// input[name="ping_target"]、按钮 click/input 事件与 focus 计数。
// MutationObserver 仅收集回调，由 stub.fireChange() 手动触发。
const localPingSelectorDOMStub = `
var window = globalThis;
var __observers = [];

function makeEvent(type) {
	return { type: type, preventDefault: function () {} };
}
function Event(type) {
	return makeEvent(type);
}
window.Event = Event;
function HTMLInputElement() {}
window.HTMLInputElement = HTMLInputElement;

function makeEl(tag) {
	var el = {
		tag: tag,
		attrs: {},
		listeners: {},
		children: [],
		parentElement: null,
		style: {},
		textContent: ""
	};
	el.setAttribute = function (k, v) { el.attrs[k] = String(v); };
	el.getAttribute = function (k) {
		return Object.prototype.hasOwnProperty.call(el.attrs, k) ? el.attrs[k] : null;
	};
	el.addEventListener = function (type, fn) {
		(el.listeners[type] = el.listeners[type] || []).push(fn);
	};
	el.dispatchEvent = function (ev) {
		var ls = el.listeners[ev.type] || [];
		for (var i = 0; i < ls.length; i++) {
			ls[i].call(el, ev);
		}
		return true;
	};
	el.appendChild = function (c) {
		c.parentElement = el;
		el.children.push(c);
		return c;
	};
	el.insertBefore = function (n, ref) {
		n.parentElement = el;
		var i = ref ? el.children.indexOf(ref) : -1;
		if (i >= 0) {
			el.children.splice(i, 0, n);
		} else {
			el.children.push(n);
		}
		return n;
	};
	el.querySelectorAll = function (sel) {
		var out = [];
		if (sel === "button") {
			for (var i = 0; i < el.children.length; i++) {
				if (el.children[i].tag === "button") {
					out.push(el.children[i]);
				}
			}
		}
		return out;
	};
	return el;
}

function MutationObserver(cb) {
	__observers.push(cb);
	this.observe = function () {};
}
window.MutationObserver = MutationObserver;

var __envs = [];
var document = {
	readyState: "complete",
	body: makeEl("body"),
	createElement: function (tag) { return makeEl(tag); },
	addEventListener: function () {},
	querySelectorAll: function () {
		var out = [];
		for (var i = 0; i < __envs.length; i++) {
			out.push(__envs[i].form);
		}
		return out;
	}
};
window.document = document;

function newEnv(initial) {
	var input = makeEl("input");
	input.name = "ping_target";
	input.type = "text";
	input.value = initial;
	input.focused = false;
	input.focus = function () { input.focused = true; };
	var holder = makeEl("div");
	holder.appendChild(input);
	var form = makeEl("form");
	form.__target = input;
	form.__trigger = makeEl("button");
	form.__trigger.role = "combobox";
	form.querySelector = function (sel) {
		if (sel === 'input[name="ping_target"]') { return form.__target; }
		if (sel === 'button[role="combobox"]') { return form.__trigger; }
		return null;
	};
	form.querySelectorAll = function (sel) {
		if (sel === 'input:not([type="hidden"])') { return [input]; }
		return [];
	};
	holder.parentElement = form;
	form.parentElement = makeEl("div");
	var env = { input: input, form: form };
	env.bar = function () {
		var kids = form.children;
		for (var i = 0; i < kids.length; i++) {
			if (kids[i].getAttribute("data-komari-localping-bar") === "1") {
				return kids[i];
			}
		}
		return null;
	};
	env.findButton = function (mode) {
		var b = env.bar();
		if (!b) { return null; }
		var kids = b.children;
		for (var i = 0; i < kids.length; i++) {
			if (kids[i].getAttribute("data-mode") === mode) {
				return kids[i];
			}
		}
		return null;
	};
	env.fireChange = function () {
		for (var i = 0; i < __observers.length; i++) {
			__observers[i]();
		}
	};
	env.click = function (mode) {
		var btn = env.findButton(mode);
		if (!btn) {
			throw new Error("button " + mode + " missing");
		}
		btn.dispatchEvent(makeEvent("click"));
	};
	__envs.push(env);
	return env;
}
`

// localPingSelectorDOMDriver 断言「探测方式」选择器的行为闭环：
// 每种初始 Target 值经 detectMode 反推的模式必须正确高亮在
// data-active-mode 上；点击「节点反向 Ping（原版）」后，本机选择器值
// 必须被清空并聚焦（避免高亮「节点反向 Ping」却把 local4/local6 提交
// 到后端），外部地址必须原样保留不聚焦。
// 覆盖 RFC 3986 前导 scheme 剥离与 path/query 内嵌 :// 不被误判成顶层
// scheme（local4/a?next=http://x、http://[local6]:8080/a?next=http://x、
// http://example.com/cb?u=http://local4），以及 '@' 分隔的 userinfo
// （http://user@ipv4.example.com/ 不误判 @ipv4 选择器）。
// 与 Go ParseTarget 严格对齐的负例同样按 agent 反推：非 http:// 顶层
// scheme（https://local4/）、userinfo 段内的选择器 token（foo@local4）
// 与未闭合方括号主机段（[local6）——三者后端必拒收，UI 不得误高亮。
const localPingSelectorDOMDriver = `
function verify() {
	var cases = [
		{ value: "local4/a?next=http://x", mode: "v4", clearOnAgent: true },
		{ value: "local4:8080?x=http://y", mode: "v4", clearOnAgent: true },
		{ value: "http://[local6]:8080/a?next=http://x", mode: "v6", clearOnAgent: true },
		{ value: "http://example.com/cb?u=http://local4", mode: "agent", clearOnAgent: false },
		{ value: "http://user@ipv4.example.com/", mode: "agent", clearOnAgent: false },
		{ value: "https://local4/", mode: "agent", clearOnAgent: false },
		{ value: "foo@local4", mode: "agent", clearOnAgent: false },
		{ value: "[local6", mode: "agent", clearOnAgent: false }
	];
	for (var i = 0; i < cases.length; i++) {
		var c = cases[i];
		var env = newEnv(c.value);
		env.fireChange();
		var bar = env.bar();
		if (!bar) {
			throw new Error("[" + c.value + "] selector bar not mounted");
		}
		var got = bar.getAttribute("data-active-mode");
		if (got !== c.mode) {
			throw new Error("[" + c.value + "] mode = " + got + ", want " + c.mode);
		}
		env.input.focused = false;
		env.click("agent");
		if (c.clearOnAgent) {
			if (env.input.value !== "") {
				throw new Error("[" + c.value + "] agent click left value = " + env.input.value + ", want cleared");
			}
			if (!env.input.focused) {
				throw new Error("[" + c.value + "] agent click did not focus the input");
			}
			if (env.bar().getAttribute("data-active-mode") !== "agent") {
				throw new Error("[" + c.value + "] agent click did not activate agent mode");
			}
		} else {
			if (env.input.value !== c.value) {
				throw new Error("[" + c.value + "] agent click changed external target to " + env.input.value + ", want kept");
			}
			if (env.input.focused) {
				throw new Error("[" + c.value + "] agent click unexpectedly focused the input");
			}
		}
	}
	return true;
}
`

// TestLocalPingSelectorDOMBehavior 用仓库自带的 jsruntime 在真实 JS 引擎里
// 执行嵌入的选择器脚本 + 自包含 DOM 桩，验证 detectMode 的模式反推与
// 「节点反向 Ping」按钮的清理行为（见 driver 注释）。
// 裸基线 GET /__komari_local_ping.js 返回 404 直接失败；旧 detectMode
// 按朴素 indexOf("://") 剥离，会把 local4/a?next=http://x 等 path/query
// 内嵌 :// 的目标切成尾段误判 agent（FAIL），修复后 PASS。
func TestLocalPingSelectorDOMBehavior(t *testing.T) {
	router := setupStaticTestRouter(t, false)

	code, body, header := getBody(t, router, "/__komari_local_ping.js")
	if code != 200 {
		t.Fatalf("/__komari_local_ping.js status = %d, want 200", code)
	}
	if ct := header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("/__komari_local_ping.js Content-Type = %q, want javascript", ct)
	}

	rt, err := jsruntime.New(
		localPingSelectorDOMStub+"\n"+body+"\n"+localPingSelectorDOMDriver,
		jsruntime.Options{BaseDir: t.TempDir(), Console: io.Discard, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("create jsruntime: %v", err)
	}
	defer rt.Close()
	if err := rt.Call("verify"); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
