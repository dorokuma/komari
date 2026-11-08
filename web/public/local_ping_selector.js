// Komari 本机正向出站探测 —— /admin 延迟监测任务弹窗「探测方式」选择器。
//
// 仅在检测到 Ping 任务新建/编辑表单出现时挂载（MutationObserver，幂等）。
// 提供三选一分段控件：
//   - 节点反向 Ping（原版）：保持手动输入外部目标地址；
//   - 本机直连 IPv4：一键填入 local4（tcp 联动 local4:80，http 联动 http://local4/）；
//   - 本机直连 IPv6：一键填入 local6（tcp 联动 [local6]:80，http 联动 http://[local6]/），
//     v6-only / WARP 节点推荐。
// 前端结构不匹配时静默降级，不抛错。
(function () {
	"use strict";
	if (window.__komariLocalPingMounted) {
		return;
	}
	window.__komariLocalPingMounted = true;

	var BAR_ATTR = "data-komari-localping-bar";
	var INPUT_ATTR = "data-komari-localping-input";
	// 目标输入框未找到时仅打印一次告警（上游前端改版导致 DOM 锚点漂移时便于定位）。
	var targetWarned = false;

	function warnTargetMissing() {
		if (targetWarned || !window.console || !window.console.warn) {
			return;
		}
		targetWarned = true;
		window.console.warn(
			"[komari-localping] ping task target input not found; selector skipped");
	}

	var MODES = {
		agent: { label: "节点反向 Ping（原版）" },
		v4: { label: "本机直连 IPv4（local4）" },
		v6: { label: "本机直连 IPv6（local6 · v6-only/WARP 推荐）" }
	};

	function setInputValue(input, value) {
		if (!input || input.value === value) {
			return;
		}
		var proto = Object.getPrototypeOf(input);
		var desc = Object.getOwnPropertyDescriptor(proto, "value") ||
			Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
		if (desc && desc.set) {
			desc.set.call(input, value);
		} else {
			input.value = value;
		}
		input.dispatchEvent(new Event("input", { bubbles: true }));
		input.dispatchEvent(new Event("change", { bubbles: true }));
	}

	// 读取当前表单 Type 下拉（Radix Select trigger：button[role="combobox"]）。
	function currentType(form) {
		try {
			var trigger = form.querySelector('button[role="combobox"]');
			var text = (trigger && trigger.textContent || "").trim().toLowerCase();
			if (text === "tcp" || text === "http") {
				return text;
			}
			return "icmp";
		} catch (e) {
			return "icmp";
		}
	}

	function valueFor(type, mode) {
		if (mode === "v4") {
			if (type === "tcp") {
				return "local4:80";
			}
			if (type === "http") {
				return "http://local4/";
			}
			return "local4";
		}
		if (mode === "v6") {
			if (type === "tcp") {
				return "[local6]:80";
			}
			if (type === "http") {
				return "http://[local6]/";
			}
			return "local6";
		}
		return "";
	}

	// 从已有 Target 值反推探测方式（编辑弹窗自动高亮）。
	// 与后端 localping.ParseTarget 使用同一套语法规则：
	//   1) 仅当头部匹配 RFC 3986 scheme（ALPHA *(ALPHA/DIGIT/+/-/.)
	//      后接 ://）才剥离前导 scheme——path/query 内嵌的 ://
	//      （local4/a?next=http://x、http://[local6]:8080/a?next=http://x）
	//      其前缀含 '/' '?' ':' 等非法 scheme 字符，绝不被误判成顶层 scheme；
	//   2) 剥出的顶层 scheme 非 http://（https://、ws:// 等）时选择器目标
	//      后端必拒，直接按 agent 反推，不误高亮成本机直连；
	//   3) authority 取到首个 /?#；
	//   4) 按 Go 端 isSelectorAtPrefix 一致的规则切 '@'：仅当 s[i]==='@'
	//      且 (i===0 或前一字符为 '['/'@') 且后续以 @ipv4/@ipv6 开头且
	//      第 6 字符为串尾或 ':]@/?#' 之一时，该 '@' 属于选择器简写本身，
	//      其余 '@' 是 userinfo 分隔符；切出 userinfo 段（atSegments
	//      长度 >1，如 foo@local4、[x]@local4）时后端必拒，同样按 agent
	//      反推；
	//   5) 末段是 hostport：以 '[' 开头但没有配对闭合 ']'（如 [local6、
	//      [@ipv6:443）后端必拒，按 agent 反推；否则提取主机 token（剥前
	//      导 '[' 并按 ']' ':' 截断），命中 local4/local6 判本机模式。
	function isSelectorAtPrefix(s, i) {
		if (s.charAt(i) !== "@") {
			return false;
		}
		if (i !== 0 && s.charAt(i - 1) !== "[" && s.charAt(i - 1) !== "@") {
			return false;
		}
		var tail = s.slice(i);
		if (tail.indexOf("@ipv4") !== 0 && tail.indexOf("@ipv6") !== 0) {
			return false;
		}
		return i + 5 === s.length || ":]@/?#".indexOf(s.charAt(i + 5)) >= 0;
	}

	function splitAuthorityByUserinfoAt(s) {
		var segs = [];
		var start = 0;
		for (var i = 0; i < s.length; i++) {
			if (s.charAt(i) !== "@" || isSelectorAtPrefix(s, i)) {
				continue;
			}
			segs.push(s.slice(start, i));
			start = i + 1;
		}
		segs.push(s.slice(start));
		return segs;
	}

	// 提取单段 authority/hostport 的主机 token：剥前导 '['，按 ']' ':'
	// 截断（与 Go 端 splitLocalHostPort/selectorHostOf 的取法一致）。
	function hostTokenOf(seg) {
		var h = seg;
		if (h.charAt(0) === "[") {
			h = h.slice(1);
		}
		var cut = h.search(/[\]:]/);
		if (cut >= 0) {
			h = h.slice(0, cut);
		}
		return h;
	}

	function detectMode(value) {
		var v = String(value || "").trim();
		if (!v) {
			return "agent";
		}
		var rest = v;
		var schemeMatch = rest.match(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//);
		if (schemeMatch) {
			if (schemeMatch[0].toLowerCase() !== "http://") {
				// 顶层 scheme 非 http:// 时后端必拒本机选择器（https://local4/、
				// ws://local4:8080），UI 不误高亮。
				return "agent";
			}
			rest = rest.slice(schemeMatch[0].length);
		}
		var authority = rest;
		var cut = authority.search(/[\/?#]/);
		if (cut >= 0) {
			authority = authority.slice(0, cut);
		}
		var atSegments = splitAuthorityByUserinfoAt(authority);
		if (atSegments.length !== 1) {
			// 含 '@' userinfo 分隔符的目标（foo@local4、[x]@local4）后端必拒，
			// UI 不误高亮。（合法裸 @ipv4/@ipv6 与 [@ipv6] 的选择器自有 '@'
			// 不产生切分点，仍走到这里时 length === 1。）
			return "agent";
		}
		var hostSeg = atSegments[0];
		if (hostSeg.charAt(0) === "[" && hostSeg.indexOf("]") < 0) {
			// 主机段 '[' 无配对 ']'（[local6、[@ipv6:443）：后端必拒，UI
			// 不误高亮；合法 [local6]:80、[@ipv6]:443 有闭合 ']'，正常走 token。
			return "agent";
		}
		var found = "";
		for (var i = atSegments.length - 1; i >= 0 && !found; i--) {
			var token = hostTokenOf(atSegments[i]);
			if (token === "local4" || token === "@ipv4") {
				found = "v4";
			} else if (token === "local6" || token === "@ipv6") {
				found = "v6";
			}
		}
		return found || "agent";
	}

	// 定位表单中的 Target 输入框：
	//   - 新建表单：input[name="ping_target"]
	//   - 编辑表单：无 name，取 Type 下拉之后的第一个文本输入框
	function findTargetInput(form) {
		var named = form.querySelector('input[name="ping_target"]');
		if (named) {
			return named;
		}
		var inputs = Array.prototype.slice.call(
			form.querySelectorAll('input:not([type="hidden"])'));
		var textInputs = inputs.filter(function (el) {
			return !el.type || el.type === "text";
		});
		return textInputs.length >= 2 ? textInputs[1] : null;
	}

	function syncActive(bar, mode) {
		Array.prototype.forEach.call(bar.querySelectorAll("button"), function (btn) {
			var active = btn.getAttribute("data-mode") === mode;
			btn.setAttribute("data-active", active ? "1" : "0");
			btn.style.fontWeight = active ? "600" : "400";
			btn.style.background = active
				? "var(--accent-a4, rgba(0,0,0,.08))"
				: "transparent";
		});
	}

	function mountBar(form) {
		if (!form || form.querySelector("[" + BAR_ATTR + "]")) {
			return;
		}
		var input = findTargetInput(form);
		if (!input) {
			warnTargetMissing();
			return;
		}
		input.setAttribute(INPUT_ATTR, "1");

		var bar = document.createElement("div");
		bar.setAttribute(BAR_ATTR, "1");
		bar.setAttribute("role", "group");
		bar.setAttribute("aria-label", "探测方式");
		bar.style.cssText =
			"display:flex;gap:4px;flex-wrap:wrap;font-weight:400;margin:2px 0;";

		Object.keys(MODES).forEach(function (mode) {
			var btn = document.createElement("button");
			btn.type = "button";
			btn.setAttribute("data-mode", mode);
			btn.textContent = MODES[mode].label;
			btn.title = mode === "agent"
				? "由节点探测手动填写的目标地址（原版语义）"
				: "服务端直接探测节点自报的公网 " +
					(mode === "v4" ? "IPv4" : "IPv6") + " 地址";
			btn.style.cssText =
				"flex:1 1 auto;min-width:110px;padding:4px 8px;font-size:12px;" +
				"border:1px solid var(--gray-a6,#8884);border-radius:6px;cursor:pointer;" +
				"background:transparent;color:inherit;line-height:1.4;";
			btn.addEventListener("click", function (ev) {
				ev.preventDefault();
				var type = currentType(form);
				if (mode !== "agent") {
					setInputValue(input, valueFor(type, mode));
				} else if (detectMode(input.value) !== "agent") {
					// 输入框仍残留本机选择器时清空并聚焦，避免界面高亮
					// 「节点反向 Ping」却把 local4/local6 提交到后端。
					setInputValue(input, "");
					input.focus();
				}
				syncActive(bar, mode);
				bar.setAttribute("data-active-mode", mode);
			});
			bar.appendChild(btn);
		});

		var anchor = input.parentElement || input;
		anchor.parentElement.insertBefore(bar, anchor);

		// Type 变化（local 模式下）联动改写 Target。
		var trigger = form.querySelector('button[role="combobox"]');
		if (trigger && window.MutationObserver) {
			var typeObserver = new MutationObserver(function () {
				var mode = bar.getAttribute("data-active-mode");
				if (mode === "v4" || mode === "v6") {
					setInputValue(input, valueFor(currentType(form), mode));
				}
			});
			typeObserver.observe(trigger, {
				childList: true,
				subtree: true,
				characterData: true
			});
		}

		// 用户手动编辑输入框时实时重算探测方式，避免手填外部地址后
		// 再切 Type 被本机选择器值覆盖。
		input.addEventListener("input", function () {
			var m = detectMode(input.value);
			syncActive(bar, m);
			bar.setAttribute("data-active-mode", m);
		});

		// 首次挂载同步初始模式与高亮：打开已有 local4/local6 任务的编辑
		// 弹窗后直接切换 Type 下拉也能自动改写端口/scheme。
		var initialMode = detectMode(input.value);
		syncActive(bar, initialMode);
		bar.setAttribute("data-active-mode", initialMode);
	}

	function scan(root) {
		try {
			var forms = (root || document).querySelectorAll(
				'.km-pingtask-task-form form, form:has(input[name="ping_target"])');
			Array.prototype.forEach.call(forms, mountBar);
		} catch (e) {
			// :has 不支持或结构不符时静默降级。
			try {
				Array.prototype.forEach.call(
					document.querySelectorAll(".km-pingtask-task-form form"),
					mountBar);
			} catch (e2) { /* silent */ }
		}
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", function () { scan(); });
	} else {
		scan();
	}
	if (window.MutationObserver) {
		new MutationObserver(function () { scan(); })
			.observe(document.body, { childList: true, subtree: true });
	}
})();
