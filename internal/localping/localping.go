// Package localping 实现服务端本机正向出站延迟探测。
//
// 延迟监测（ping）任务原本只有「反向」语义：服务端把目标地址下发给 agent，
// 由 agent 探测并把 RTT 回传。本包新增「正向」语义：管理员把任务目标写成
// 本机选择器 local4/@ipv4（IPv4）或 local6/@ipv6（IPv6，v6-only/WARP 节点
// 推荐）后，服务端直接探测各节点自报的公网 IP。
//
// 节点自报 IP 不可信，所有地址必须先通过 ValidatePublicProbeIP 的公网单播
// 强校验（SSRF 防线），非法地址绝不发包。
package localping

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// 本机选择器 token：local4/local6 为推荐标准值，@ipv4/@ipv6 为兼容简写。
const (
	selectorV4     = "local4"
	selectorV4Alt  = "@ipv4"
	selectorV6     = "local6"
	selectorV6Alt  = "@ipv6"
	defaultTCPPort = "80"
)

// Spec 是本机正向探测目标的解析结果。
type Spec struct {
	// V6 为 true 时探测走 IPv6（local6/@ipv6），否则走 IPv4。
	V6 bool
	// Port 是 tcp/http 探测端口；未显式给出时为默认 "80"。icmp 恒为空。
	Port string
	// Path 是 http 探测的 path+query（含前导 "/"），icmp/tcp 恒为空。
	Path string
}

// selectorFamily 返回 token 是否为本机选择器及其协议族（true 表示 IPv6）。
func selectorFamily(token string) (v6 bool, ok bool) {
	switch token {
	case selectorV4, selectorV4Alt:
		return false, true
	case selectorV6, selectorV6Alt:
		return true, true
	}
	return false, false
}

// ParseTarget 解析延迟监测任务目标。
//
// 返回的 isLocal 为 true 表示目标主机位锚定了本机选择器，应走服务端正向探测；
// 为 false 且 err 为 nil 表示普通外部目标，交由 agent 反向探测；err 非空表示
// 目标主机位是选择器但语法不合法（如 https://、非法端口、userinfo、icmp 带
// 端口/路径等）。
func ParseTarget(pingType, target string) (spec Spec, isLocal bool, err error) {
	switch pingType {
	case "icmp", "tcp", "http":
	default:
		return Spec{}, false, fmt.Errorf("unsupported ping type %q (want icmp|tcp|http)", pingType)
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return Spec{}, false, fmt.Errorf("target is empty")
	}
	switch pingType {
	case "icmp":
		return parseICMPTarget(target)
	case "tcp":
		return parseTCPTarget(target)
	default:
		return parseHTTPTarget(target)
	}
}

// splitLeadingScheme 仅按 RFC 3986 切分前导 scheme：仅当 "://" 存在且
// "://" 之前的部分严格满足 scheme 语法（首字节 ASCII 字母，其余字节为
// 字母/数字/'+'/'-'/'.'——因此绝不含 '/'、'?'、'#'、':'、'@'、'['、']'）
// 时才切出 scheme 并返回小写；否则原样返回完整输入。
// 关键是 path/query 内嵌的 "://"（如 local4/a?next=http://x、
// local4:8080?x=http://y 中的 "http://"）其前缀含 '?'/'/'/':' 等非法
// scheme 字符，ok=false，绝不会被误判成顶层 scheme。
func splitLeadingScheme(s string) (scheme, rest string, ok bool) {
	i := strings.Index(s, "://")
	if i <= 0 {
		return "", s, false
	}
	if !isSchemeSyntax(s[:i]) {
		return "", s, false
	}
	return strings.ToLower(s[:i]), s[i+3:], true
}

// isSchemeSyntax 判定 s 是否严格满足 RFC 3986 scheme 语法：
// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
func isSchemeSyntax(s string) bool {
	if s == "" || !isASCIILetter(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if isASCIILetter(c) || (c >= '0' && c <= '9') ||
			c == '+' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// splitAuthorityAndTail 按首个 '?' / '/' / '#' 把输入切成 authority 与
// tail（tail 含起始分隔符，可为空）。调用前须先用 splitLeadingScheme
// 剥离前导 scheme，保证 authority 内不再含 "://" 的歧义。
func splitAuthorityAndTail(s string) (authority, tail string) {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

func parseICMPTarget(target string) (Spec, bool, error) {
	if v6, ok := selectorFamily(target); ok {
		return Spec{V6: v6}, true, nil
	}
	_, rest, _ := splitLeadingScheme(target)
	authority, _ := splitAuthorityAndTail(rest)
	// 选择器 token 误写在 '@' 两侧（local4@127.0.0.1、foo@local4 等）→ 报错。
	if err := rejectMisplacedSelector(authority); err != nil {
		return Spec{}, false, err
	}
	// 主机位是选择器但带端口/路径/scheme 等多余语法（http://local4、
	// local4:80、local4/?u=http://x 等）→ 明确语法错误而非静默回退。
	if selectorHostOf(target) != "" {
		return Spec{}, false, fmt.Errorf(
			"icmp local probe target must be a bare %q/%q/%q/%q selector without port or path: %q",
			selectorV4, selectorV4Alt, selectorV6, selectorV6Alt, target)
	}
	return Spec{}, false, nil
}

func parseTCPTarget(target string) (Spec, bool, error) {
	_, rest, hasScheme := splitLeadingScheme(target)
	authority, tail := splitAuthorityAndTail(rest)
	// 选择器 token 误写在 '@' 两侧（foo@local4/x?u=http://z 的 authority
	// foo@local4 等）→ 报错；此检查先于主机位判定，不误伤外部 host:port。
	if err := rejectMisplacedSelector(authority); err != nil {
		return Spec{}, false, err
	}
	if hasScheme || tail != "" {
		// 目标带顶层 scheme 或 path?query：主机位若是选择器（http://local4:443、
		// local4:443/path、local4/?u=http://x 等）绝不能透传给 agent；外部
		// 地址（tcp://1.2.3.4:80 等）正常透传。
		_, _, isLocal, splitErr := splitLocalHostPort(authority)
		if selectorHostOf(target) != "" || splitErr != nil || isLocal {
			if splitErr != nil {
				return Spec{}, false, splitErr
			}
			return Spec{}, false, fmt.Errorf(
				"tcp local probe target must be a bare %q/%q/%q/%q selector[:port] without scheme or path: %q",
				selectorV4, selectorV4Alt, selectorV6, selectorV6Alt, target)
		}
		return Spec{}, false, nil
	}
	v6, port, isLocal, err := splitLocalHostPort(authority)
	if err != nil {
		return Spec{}, false, err
	}
	if !isLocal {
		return Spec{}, false, nil
	}
	if port == "" {
		port = defaultTCPPort
	}
	if err := validatePort(port); err != nil {
		return Spec{}, false, err
	}
	return Spec{V6: v6, Port: port}, true, nil
}

func parseHTTPTarget(target string) (Spec, bool, error) {
	// 仅当目标带合法的顶层 scheme:// 才剥离；path/query 内嵌的 "://"
	// （local4/a?next=http://x、local4:8080?x=http://y）不视作 scheme。
	scheme, rest, hasScheme := splitLeadingScheme(target)
	if !hasScheme {
		scheme = "http"
		rest = target
	}

	// authority 是 host[:port]（可带 [..]/userinfo@），tail 是 path?query#frag。
	authority, tail := splitAuthorityAndTail(rest)
	// 选择器 token 误写在 '@' 两侧（userinfo 或主机位）时对称拦截：
	// foo@local4、foo@[local6]:443、local4@127.0.0.1、@ipv4@127.0.0.1、
	// foo@@ipv6、[x]@local4、[x]@@ipv6、a@local4@b，绝不当作外部目标透传。
	// 按与 splitAuthorityByUserinfoAt 一致的 '@' 分隔规则切分后逐段检查，
	// 选择器简写自有的 '@'（[@ipv6]、foo@@ipv6）不会被误当分隔符。
	if err := rejectMisplacedSelector(authority); err != nil {
		return Spec{}, false, err
	}
	// 剥离 userinfo 后主机位才是 hostport；userinfo 可以是任意片段（包括
	// '[x]' 这种方括号开头的段），绝不能因 authority 首字符为 '@' 或 '['
	// 就跳过剥离。
	segs := splitAuthorityByUserinfoAt(authority)
	hasUserinfo := len(segs) > 1
	authority = segs[len(segs)-1]

	v6, port, isLocal, err := splitLocalHostPort(authority)
	if err != nil {
		return Spec{}, false, err
	}
	if !isLocal {
		// 主机位不是选择器：外部 URL 正常透传（含 http://example.com/cb?u=http://x
		// 与 ftp://example.com 等任意 scheme）。
		return Spec{}, false, nil
	}
	if hasUserinfo {
		return Spec{}, false, fmt.Errorf("local probe target does not support userinfo: %q", target)
	}
	if scheme != "http" {
		// https:// 无主机名可做 TLS SNI，其余 scheme（ftp/ws 等）更无本机
		// 探测语义：一律报错而非透传。
		return Spec{}, false, fmt.Errorf(
			"%s:// local selector is not supported: only http:// (or a bare selector) may anchor a local probe target; raw node IP probing has no hostname for TLS SNI (%q)",
			scheme, target)
	}
	if port == "" {
		port = defaultTCPPort
	}
	if err := validatePort(port); err != nil {
		return Spec{}, false, err
	}
	// 借一个合法 host 让 net/url 校验并提取 path/query（选择器 token 本身
	// 无法通过 bracket-host 的 IP 字面量校验，因此不解析原始 authority）。
	u, err := url.Parse("http://127.0.0.1" + tail)
	if err != nil {
		return Spec{}, false, fmt.Errorf("invalid local probe URL %q: %w", target, err)
	}
	pathAndQuery := u.EscapedPath()
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	if u.RawQuery != "" {
		pathAndQuery += "?" + u.RawQuery
	}
	return Spec{V6: v6, Port: port, Path: pathAndQuery}, true, nil
}

// rejectMisplacedSelector 对称拦截 '@' 两侧误写的本机选择器 token。
//
// 入参必须已经是剥离前导 scheme 且截掉 tail（'/?#'）后的 authority 片段；
// 不再内部剥 "://"，path/query 内嵌的 "://" 由调用方经
// splitLeadingScheme/splitAuthorityAndTail 先行归一，绝不影响 '@' 判定。
//
// 先按 splitAuthorityByUserinfoAt 把 authority 切成 userinfo 各段与末段
// hostport（选择器简写自有的 '@'——如 [@ipv6]、foo@@ipv6 内 @ipv6 的
// '@'——不作为分隔符），再对每一段的「主机位」做选择器校验，包括：
//   - userinfo 段本身恰为选择器 token 或方括号选择器（local4@127.0.0.1、
//     @ipv4@127.0.0.1、[local6]@127.0.0.1:80）→ 语法错误；
//   - userinfo 段的主机位是选择器（[x]@local4、[x]@@ipv6、a@local4@b 的
//     中段 local4）→ 语法错误；
//   - 末段 hostport 语法不合法（splitLocalHostPort 报错）→ 原样返回错误。
//
// 以上任一中即返回非 nil 错误，绝不把携带选择器 token 的目标当作外部目标
// 透传给 agent；'[' 开头的输入也不再短路放行（'[x]@local4' 的方括号段是
// userinfo 而非方括号选择器）。
func rejectMisplacedSelector(authority string) error {
	segs := splitAuthorityByUserinfoAt(authority)
	if len(segs) <= 1 {
		return nil
	}
	for _, seg := range segs {
		if _, ok := selectorFamily(seg); ok {
			return fmt.Errorf("local selector %q must not be used as userinfo: %q", seg, authority)
		}
		if _, _, isLocal, err := splitLocalHostPort(seg); err != nil || isLocal {
			if err != nil {
				return err
			}
			return fmt.Errorf("local selector in host part does not support userinfo: %q", authority)
		}
		if tok := selectorHostOf(seg); tok != "" {
			return fmt.Errorf("local selector %q must not be used as userinfo: %q", tok, authority)
		}
	}
	return nil
}

// isSelectorAtPrefix 判定 s[i] 的 '@' 是否属于 @ipv4/@ipv6 选择器简写本身，
// 而非 userinfo 分隔符。选择器自有的 '@' 只可能出现在三种位置：串首
// （@ipv4）、'[' 之后（[@ipv6]）、或另一个 '@' 之后（foo@@ipv6 的 userinfo
// foo@ 与主机位 @ipv6 相邻时，第二个 '@' 属于主机位选择器）。其余位置的
// '@' 一律是 userinfo 分隔符。
func isSelectorAtPrefix(s string, i int) bool {
	if s[i] != '@' {
		return false
	}
	if i != 0 && s[i-1] != '[' && s[i-1] != '@' {
		return false
	}
	if !strings.HasPrefix(s[i:], "@ipv4") && !strings.HasPrefix(s[i:], "@ipv6") {
		return false
	}
	return i+5 == len(s) || strings.IndexByte(":]@/?#", s[i+5]) >= 0
}

// splitAuthorityByUserinfoAt 按所有非 isSelectorAtPrefix 的 '@' 位置切分
// authority：末段是 hostport，其余段是 userinfo。选择器简写自有的 '@'
// 不产生切分点。
func splitAuthorityByUserinfoAt(s string) []string {
	var segs []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '@' || isSelectorAtPrefix(s, i) {
			continue
		}
		segs = append(segs, s[start:i])
		start = i + 1
	}
	return append(segs, s[start:])
}

// selectorHostOf 仅提取目标主机位：若主机位恰为选择器 token 则返回该 token，
// 否则返回 ""。用于识别「主机位是选择器但整体带了多余语法」的错误目标。
// 先经 splitLeadingScheme 剥合法前导 scheme，再经 splitAuthorityAndTail
// 截 tail——path/query 内嵌的 "://"（local4/a?next=http://x）绝不被
// 误当成顶层 scheme。
func selectorHostOf(target string) string {
	_, s, _ := splitLeadingScheme(target)
	s, _ = splitAuthorityAndTail(s)
	// 与 parseHTTPTarget 一致：按选择器自有的 '@' 感知切分后取末段
	// hostport，[x]@local4 的方括号 userinfo 段不会阻止主机位识别。
	segs := splitAuthorityByUserinfoAt(s)
	s = segs[len(segs)-1]
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			// 未闭合的 '['：同样按 ':' 截断后匹配选择器，保持与
			// splitLocalHostPort 一致（icmp 裸选择器也必须报错而非回退）。
			rest := s[1:]
			if cut := strings.Index(rest, ":"); cut >= 0 {
				rest = rest[:cut]
			}
			if _, ok := selectorFamily(rest); ok {
				return rest
			}
			return ""
		}
		s = s[1:end]
	} else if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	if _, ok := selectorFamily(s); ok {
		return s
	}
	return ""
}

// splitLocalHostPort 解析 host[:port] 或 [host]:port 形态的 hostport。
// isLocal=false 表示主机位不是本机选择器（外部目标，err 恒为 nil）；
// isLocal=true 且 err!=nil 表示主机位是选择器但语法不合法。
func splitLocalHostPort(s string) (v6 bool, port string, isLocal bool, err error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			// 未闭合的 '['：按 :/?# 截断取主机位 token（'@' 属于选择器简写
			// 本身，不剥离）。token 命中选择器时必须报错，绝不能当作外部
			// 目标回退下发。
			rest := s[1:]
			if cut := strings.IndexAny(rest, ":/?#"); cut >= 0 {
				rest = rest[:cut]
			}
			if fam, ok := selectorFamily(rest); ok {
				return fam, "", true, fmt.Errorf("invalid bracketed local selector %q", s)
			}
			return false, "", false, nil
		}
		inner := s[1:end]
		rest := s[end+1:]
		fam, ok := selectorFamily(inner)
		if !ok {
			return false, "", false, nil // 真正的 IPv6 字面量等，按外部目标处理。
		}
		if !fam {
			return false, "", true, fmt.Errorf("IPv4 local selector must not use brackets: %q", s)
		}
		if rest == "" {
			return true, "", true, nil
		}
		if !strings.HasPrefix(rest, ":") || rest == ":" {
			return false, "", true, fmt.Errorf("unexpected suffix after bracketed local selector: %q", s)
		}
		return true, rest[1:], true, nil
	}

	host := s
	// '@' 前缀属于 @ipv4/@ipv6 选择器简写本身，不参与分隔符扫描。
	offset := 0
	if strings.HasPrefix(s, "@") {
		offset = 1
	}
	if i := strings.IndexAny(s[offset:], ":/?#"); i >= 0 {
		cut := offset + i
		if s[cut] != ':' {
			if _, ok := selectorFamily(s[:cut]); ok {
				return false, "", true, fmt.Errorf("local selector %q must not carry path/query: %q", s[:cut], s)
			}
			return false, "", false, nil
		}
		host = s[:cut]
		port = s[cut+1:]
		if strings.IndexAny(port, ":/?#") >= 0 {
			if _, ok := selectorFamily(host); ok {
				return false, "", true, fmt.Errorf("local selector %q has invalid port suffix %q", host, port)
			}
			return false, "", false, nil
		}
		if port == "" {
			if _, ok := selectorFamily(host); ok {
				return false, "", true, fmt.Errorf("local selector %q has an empty port", s)
			}
			return false, "", false, nil
		}
	}
	fam, ok := selectorFamily(host)
	if !ok {
		return false, "", false, nil
	}
	return fam, port, true, nil
}

func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("empty port")
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return fmt.Errorf("invalid port %q", port)
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("port %q out of range 1-65535", port)
	}
	return nil
}
