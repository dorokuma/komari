package localping

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	logger "github.com/komari-monitor/komari/utils/log"
)

const (
	// probeTimeout 是单次探测的超时上限。
	probeTimeout = 3 * time.Second
	// retryThresholdMs：首次探测成功但 RTT 超过该值时最多复测一次，
	// 兼顾偶发毛刺与 interval=1s 下单轮耗时收敛。
	retryThresholdMs = 1000
	// tcpRetransmitGapMs：tcp 复测时 first-second 超过该值判定疑似 SYN 重传，
	// 按失败 -1 处理（对齐 komari-agent）。
	tcpRetransmitGapMs = 800
)

// probe 按探测类型执行一次本机正向探测，返回 RTT 毫秒，失败返回 -1。
func probe(ctx context.Context, pingType string, spec Spec, addr netip.Addr) int {
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	switch pingType {
	case "icmp":
		return probeICMP(probeCtx, spec.V6, addr)
	case "tcp":
		return probeTCP(probeCtx, spec, addr)
	case "http":
		return probeHTTP(probeCtx, spec, addr)
	}
	return -1
}

// networkFamily 返回 tcp4/tcp6（net.Dialer）与 ip4/ip6（pro-bing）网络名。
func networkFamily(v6 bool) (tcpNet, ipNet string) {
	if v6 {
		return "tcp6", "ip6"
	}
	return "tcp4", "ip4"
}

// dialTarget 返回 addr:port 的可拨号地址；IPv6 自动加方括号。
func dialTarget(addr netip.Addr, port string) string {
	return net.JoinHostPort(addr.String(), port)
}

func probeICMP(ctx context.Context, v6 bool, addr netip.Addr) int {
	_, ipNet := networkFamily(v6)
	run := func(privileged bool) (int, error) {
		pinger, err := probing.NewPinger(addr.String())
		if err != nil {
			return -1, err
		}
		pinger.SetNetwork(ipNet)
		pinger.SetPrivileged(privileged)
		pinger.Count = 1
		pinger.Timeout = probeTimeout
		if err := pinger.RunWithContext(ctx); err != nil {
			return -1, err
		}
		stats := pinger.Statistics()
		if stats == nil || stats.PacketsRecv == 0 {
			return -1, nil
		}
		return int(stats.AvgRtt.Milliseconds()), nil
	}
	return probeICMPWithRunner(ctx, run, warnICMPPermissionOnce)
}

// probeICMPWithRunner 提炼 probeICMP 的特权→非特权回退与超阈值复测控制
// 流，run/warn 可注入以便单测直接断言回退与单次告警语义（生产路径行为
// 与内联实现完全一致）：
//   - run(privileged=true) 成功即返回其 RTT；
//   - 仅当错误判定为权限不足（EPERM/EACCES 等）时才回退 run(false)；
//     非特权仍权限失败时调 warn 一次性告警，其余失败静默返回 -1；
//   - 首轮 RTT 超过 retryThresholdMs 且 ctx 未取消时复测一轮取复测值。
func probeICMPWithRunner(ctx context.Context, run func(privileged bool) (int, error), warn func(error)) int {
	// 优先原始套接字（需要 CAP_NET_RAW）；权限不足时自动回退 Linux
	// ping_group_range 非特权 datagram ICMP，并重试一次。
	runOnce := func() int {
		val, err := run(true)
		if err == nil || ctx.Err() != nil {
			return val
		}
		if !isICMPPermissionError(err) {
			return -1
		}
		val, err = run(false)
		if err != nil {
			if isICMPPermissionError(err) {
				warn(err)
			}
			return -1
		}
		return val
	}
	first := runOnce()
	if first > retryThresholdMs && ctx.Err() == nil {
		if second := runOnce(); second >= 0 {
			return second
		}
	}
	return first
}

// isICMPPermissionError 判定错误是否由权限不足（缺 CAP_NET_RAW / 未开启
// ping_group_range）引起，区分于超时、DNS 失败等一般失败。
func isICMPPermissionError(err error) bool {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied")
}

var icmpPermissionWarnOnce sync.Once

// icmpPermissionWarnLog 是告警动作本身，提炼为包内可替换变量以便单测
// 直接覆盖生产 warnICMPPermissionOnce 的 sync.Once 去重语义。
var icmpPermissionWarnLog = func(err error) {
	logger.Warnf("localping",
		"local ICMP probe unavailable: %v; grant CAP_NET_RAW or configure net.ipv4.ping_group_range for unprivileged ICMP", err)
}

// warnICMPPermissionOnce 进程内只打印一次：非特权 ICMP 回退仍因权限失败，
// 提示需要 CAP_NET_RAW 或 net.ipv4.ping_group_range 配置。
func warnICMPPermissionOnce(err error) {
	icmpPermissionWarnOnce.Do(func() { icmpPermissionWarnLog(err) })
}

func probeTCP(ctx context.Context, spec Spec, addr netip.Addr) int {
	tcpNet, _ := networkFamily(spec.V6)
	dial := func() int {
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: probeTimeout}).DialContext(
			ctx, tcpNet, dialTarget(addr, spec.Port))
		if err != nil {
			return -1
		}
		_ = conn.Close()
		return int(time.Since(start).Milliseconds())
	}
	first := dial()
	if first > retryThresholdMs && ctx.Err() == nil {
		second := dial()
		// 首测显著慢于复测疑似 SYN 重传，记失败（对齐 komari-agent）。
		if second >= 0 && first-second > tcpRetransmitGapMs {
			return -1
		}
		if second >= 0 {
			return second
		}
	}
	return first
}

func probeHTTP(ctx context.Context, spec Spec, addr netip.Addr) int {
	tcpNet, _ := networkFamily(spec.V6)
	// Transport 强制按协议族直接拨号目标 IP，URL host 写真实地址（选择器 token
	// 无法通过 net/url 的 bracket-host 校验），路径取自解析结果。
	dialContext := func(dialCtx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: probeTimeout}).DialContext(
			dialCtx, tcpNet, dialTarget(addr, spec.Port))
	}
	run := func() int {
		transport := &http.Transport{
			Proxy:             nil, // 显式不走环境代理，探测必须直连目标。
			DisableKeepAlives: true,
			DialContext:       dialContext,
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{
			Timeout:   probeTimeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // 不跟随跳转，按首个响应码判定。
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://"+dialTarget(addr, spec.Port)+spec.Path, nil)
		if err != nil {
			return -1
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return -1
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			return -1
		}
		return int(time.Since(start).Milliseconds())
	}
	first := run()
	if first > retryThresholdMs && ctx.Err() == nil {
		if second := run(); second >= 0 {
			return second
		}
	}
	return first
}

// ValidatePublicProbeIP 校验节点自报的公网探测 IP（SSRF 防线）。
// 仅放行对应协议族的公网单播地址，拒绝一切私网/保留/组播/映射地址。
func ValidatePublicProbeIP(raw string, wantV6 bool) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP literal %q", raw)
	}
	if addr.Is4In6() {
		return netip.Addr{}, fmt.Errorf("IPv4-mapped address %q is not allowed", raw)
	}
	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("address %q with zone is not allowed", raw)
	}
	if wantV6 != addr.Is6() {
		return netip.Addr{}, fmt.Errorf("address %q family does not match selector", raw)
	}
	// IPv6 仅放行 2000::/3 全球单播段：自动阻断 ::/96 v4-compatible、
	// 64:ff9b::/96 与 64:ff9b:1::/48 NAT64、100::/64 丢弃前缀、fc00::/7、
	// fe80::/10、ff00::/8 等一切非全球单播前缀。
	if addr.Is6() && !v6GlobalUnicastPrefix.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("address %q is outside the 2000::/3 global unicast range", raw)
	}
	if !addr.IsGlobalUnicast() ||
		addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("address %q is not a public unicast address", raw)
	}
	for _, p := range deniedPrefixes(addr.Is6()) {
		if p.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("address %q is in denied range %s", raw, p)
		}
	}
	return addr, nil
}

var (
	deniedV4Prefixes = mustPrefixes(
		"0.0.0.0/8",          // 本网段
		"100.64.0.0/10",      // CGNAT
		"192.0.0.0/24",       // RFC 6890 IETF 协议分配（含 192.0.0.8）
		"192.0.2.0/24",       // TEST-NET-1
		"192.88.99.0/24",     // RFC 7526 废弃 6to4 中继任播
		"198.18.0.0/15",      // 基准测试网段（常见透明代理 fake-ip）
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"240.0.0.0/4",        // 保留
		"255.255.255.255/32", // 广播
	)
	// deniedV6Prefixes 显式拦截 2000::/3 内外的特殊/转换用途前缀，
	// 与 v6GlobalUnicastPrefix 白名单构成双重防线。
	deniedV6Prefixes = mustPrefixes(
		"64:ff9b::/96",   // NAT64 IPv4/IPv6 转换
		"64:ff9b:1::/48", // NAT64 本地转换前缀
		"100::/64",       // Discard-Only 地址块
		"2001::/23",      // IETF 协议保留（覆盖 Teredo 2001::/32、基准测试 2001:2::/48、ORCHID 2001:10::/28 与 2001:20::/28 等）
		"2001:db8::/32",  // 文档示例前缀
		"2002::/16",      // 6to4
		"3fff::/20",      // RFC 9637 文档前缀
		"5f00::/16",      // RFC 9602 SRv6 SID
	)
	// v6GlobalUnicastPrefix 是 IPv6 全球单播段白名单（RFC 4291）。
	v6GlobalUnicastPrefix = netip.MustParsePrefix("2000::/3")
)

func deniedPrefixes(v6 bool) []netip.Prefix {
	if v6 {
		return deniedV6Prefixes
	}
	return deniedV4Prefixes
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}
