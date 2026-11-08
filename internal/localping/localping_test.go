package localping

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/komari-monitor/komari/database/models"
)

func TestParseTargetSelectorTable(t *testing.T) {
	type want struct {
		isLocal bool
		v6      bool
		port    string
		path    string
	}
	tests := []struct {
		name     string
		pingType string
		target   string
		wantErr  bool
		want     want
	}{
		// icmp：只允许裸选择器 token。
		{name: "icmp v4", pingType: "icmp", target: "local4", want: want{isLocal: true}},
		{name: "icmp v4 alt", pingType: "icmp", target: "@ipv4", want: want{isLocal: true}},
		{name: "icmp v6", pingType: "icmp", target: "local6", want: want{isLocal: true, v6: true}},
		{name: "icmp v6 alt", pingType: "icmp", target: "@ipv6", want: want{isLocal: true, v6: true}},
		{name: "icmp selector with port", pingType: "icmp", target: "local4:80", wantErr: true},
		{name: "icmp selector with path", pingType: "icmp", target: "local6/x", wantErr: true},
		{name: "icmp bracketed v6 selector", pingType: "icmp", target: "[local6]", wantErr: true},
		{name: "icmp external ip", pingType: "icmp", target: "1.1.1.1", want: want{}},
		{name: "icmp external host", pingType: "icmp", target: "example.com", want: want{}},
		// 未闭合 '[' 的选择器必须报错，绝不回退外部目标。
		{name: "icmp unclosed bracket v6", pingType: "icmp", target: "[local6", wantErr: true},
		{name: "icmp unclosed bracket v6 alt", pingType: "icmp", target: "[@ipv6", wantErr: true},
		{name: "icmp unclosed bracket external", pingType: "icmp", target: "[fe80::1", want: want{}},

		// tcp：选择器可带端口，缺省 80。
		{name: "tcp v4 bare", pingType: "tcp", target: "local4", want: want{isLocal: true, port: "80"}},
		{name: "tcp v4 port", pingType: "tcp", target: "local4:443", want: want{isLocal: true, port: "443"}},
		{name: "tcp v4 alt port", pingType: "tcp", target: "@ipv4:22", want: want{isLocal: true, port: "22"}},
		{name: "tcp v6 bare", pingType: "tcp", target: "local6", want: want{isLocal: true, v6: true, port: "80"}},
		{name: "tcp v6 port", pingType: "tcp", target: "local6:8443", want: want{isLocal: true, v6: true, port: "8443"}},
		{name: "tcp v6 bracket", pingType: "tcp", target: "[local6]:443", want: want{isLocal: true, v6: true, port: "443"}},
		{name: "tcp v6 alt bracket", pingType: "tcp", target: "[@ipv6]:443", want: want{isLocal: true, v6: true, port: "443"}},
		{name: "tcp v4 bracketed", pingType: "tcp", target: "[local4]:80", wantErr: true},
		{name: "tcp port zero", pingType: "tcp", target: "local4:0", wantErr: true},
		{name: "tcp port overflow", pingType: "tcp", target: "local4:65536", wantErr: true},
		{name: "tcp port non-numeric", pingType: "tcp", target: "local4:abc", wantErr: true},
		{name: "tcp empty port", pingType: "tcp", target: "local4:", wantErr: true},
		{name: "tcp v6 bracket empty port", pingType: "tcp", target: "[local6]:", wantErr: true},
		{name: "tcp external hostport", pingType: "tcp", target: "1.1.1.1:80", want: want{}},
		{name: "tcp external ipv6", pingType: "tcp", target: "[::1]:80", want: want{}},
		{name: "tcp external v6 host", pingType: "tcp", target: "::1", want: want{}},
		// 未闭合 '[' 的选择器必须报错；真正 IPv6 字面量仍按外部目标处理。
		{name: "tcp unclosed bracket v6", pingType: "tcp", target: "[local6:443", wantErr: true},
		{name: "tcp unclosed bracket v4 alt", pingType: "tcp", target: "[@ipv4", wantErr: true},
		{name: "tcp unclosed bracket v6 alt", pingType: "tcp", target: "[@ipv6:443", wantErr: true},
		{name: "tcp unclosed bracket ipv6 literal", pingType: "tcp", target: "[fe80::1", want: want{}},

		// 选择器 token 误写在 '@' 两侧（userinfo 或主机位）必须报错，绝不
		// 当作外部目标透传。
		{name: "tcp userinfo selector host", pingType: "tcp", target: "foo@local4", wantErr: true},
		{name: "tcp userinfo selector hostport", pingType: "tcp", target: "foo@local4:443", wantErr: true},
		{name: "tcp userinfo selector bracket host", pingType: "tcp", target: "foo@[local6]:443", wantErr: true},
		{name: "tcp userinfo selector alt host", pingType: "tcp", target: "foo@@ipv6", wantErr: true},
		{name: "tcp selector userinfo external host", pingType: "tcp", target: "local4@127.0.0.1", wantErr: true},
		{name: "icmp selector userinfo external host", pingType: "icmp", target: "local4@127.0.0.1", wantErr: true},
		{name: "icmp selector alt userinfo external host", pingType: "icmp", target: "@ipv4@127.0.0.1", wantErr: true},
		{name: "tcp external userinfo hostport", pingType: "tcp", target: "user@1.1.1.1:22", want: want{}},
		// userinfo 以方括号打头时也必须剥离检查：'[x]@' 开头的方括号段是
		// userinfo 而非方括号选择器，绝不能因首字符 '[' 短路放行。
		{name: "icmp bracket userinfo selector host", pingType: "icmp", target: "[x]@local4", wantErr: true},
		{name: "tcp bracket userinfo selector hostport", pingType: "tcp", target: "[x]@local4:443", wantErr: true},
		{name: "http bracket userinfo selector host", pingType: "http", target: "http://[x]@local4/y", wantErr: true},
		{name: "icmp bracket userinfo selector alt", pingType: "icmp", target: "[x]@@ipv6", wantErr: true},
		{name: "tcp bracketed selector as userinfo", pingType: "tcp", target: "[local6]@127.0.0.1:80", wantErr: true},
		{name: "icmp mid-string misplaced selector", pingType: "icmp", target: "a@local4@b", wantErr: true},
		// 同型反例：方括号 userinfo + 外部主机位正常透传；选择器前缀域名
		// （local4.evil.com）也非选择器，正常透传。
		{name: "http bracket userinfo external host", pingType: "http", target: "http://[x]@example.com/y", want: want{}},
		{name: "http userinfo selector-prefixed host", pingType: "http", target: "http://foo@local4.evil.com/", want: want{}},

		// http：http:// 可带端口与路径，https:// 显式报错。
		{name: "http v4 bare", pingType: "http", target: "local4", want: want{isLocal: true, port: "80", path: "/"}},
		{name: "http v4 scheme", pingType: "http", target: "http://local4", want: want{isLocal: true, port: "80", path: "/"}},
		{name: "http v4 port path query", pingType: "http", target: "http://local4:8080/health?a=1", want: want{isLocal: true, port: "8080", path: "/health?a=1"}},
		{name: "http v6 scheme", pingType: "http", target: "http://local6", want: want{isLocal: true, v6: true, port: "80", path: "/"}},
		{name: "http v6 bracket", pingType: "http", target: "http://[local6]:8080/x", want: want{isLocal: true, v6: true, port: "8080", path: "/x"}},
		{name: "http v6 alt bracket", pingType: "http", target: "http://[@ipv6]", want: want{isLocal: true, v6: true, port: "80", path: "/"}},
		{name: "http v6 no scheme path", pingType: "http", target: "local6/p", want: want{isLocal: true, v6: true, port: "80", path: "/p"}},
		{name: "http v4 alt selector", pingType: "http", target: "http://@ipv4", want: want{isLocal: true, port: "80", path: "/"}},
		{name: "https v4 rejected", pingType: "http", target: "https://local4", wantErr: true},
		{name: "https v6 bracket rejected", pingType: "http", target: "https://[local6]/", wantErr: true},
		{name: "https alt rejected", pingType: "http", target: "https://@ipv4", wantErr: true},
		{name: "http userinfo rejected", pingType: "http", target: "http://user@local4", wantErr: true},
		{name: "http selector userinfo external host", pingType: "http", target: "http://local4@127.0.0.1", wantErr: true},
		{name: "http selector alt userinfo external host", pingType: "http", target: "http://@ipv4@127.0.0.1", wantErr: true},
		{name: "http bad port rejected", pingType: "http", target: "http://local4:99999", wantErr: true},
		{name: "http unclosed bracket rejected", pingType: "http", target: "http://[@ipv6", wantErr: true},

		// 选择器主机位被 scheme:// 或 path?query 包裹同样必须报错，且
		// path/query 内嵌的 :// 不得被误判成顶层 scheme。
		{name: "icmp selector host with scheme", pingType: "icmp", target: "http://local4", wantErr: true},
		{name: "icmp selector host with path embedded scheme", pingType: "icmp", target: "local4/?u=http://x", wantErr: true},
		{name: "icmp selector userinfo query embedded scheme", pingType: "icmp", target: "local4@127.0.0.1?x=http://z", wantErr: true},
		{name: "tcp selector host with scheme", pingType: "tcp", target: "http://local4:443", wantErr: true},
		{name: "tcp selector host with path", pingType: "tcp", target: "local4:443/path", wantErr: true},
		{name: "tcp selector userinfo path embedded scheme", pingType: "tcp", target: "foo@local4/x?u=http://z", wantErr: true},
		{name: "tcp external with scheme passthrough", pingType: "tcp", target: "tcp://1.2.3.4:80", want: want{}},
		// http：scheme 必须是 http（https/ftp/ws 等均不支持本机选择器语义），
		// 但 path/query 可含内嵌 :// 参数。
		{name: "http selector ws scheme rejected", pingType: "http", target: "ws://local4:8080", wantErr: true},
		{name: "http selector ftp scheme rejected", pingType: "http", target: "ftp://local4", wantErr: true},
		{name: "http v4 embedded scheme in query", pingType: "http", target: "local4/a?next=http://x", want: want{isLocal: true, port: "80", path: "/a?next=http://x"}},
		{name: "http v4 port query embedded scheme", pingType: "http", target: "local4:8080?x=http://y", want: want{isLocal: true, port: "8080", path: "/?x=http://y"}},
		{name: "http external with embedded scheme", pingType: "http", target: "http://example.com/cb?u=http://x", want: want{}},
		{name: "http external ftp scheme passthrough", pingType: "http", target: "ftp://example.com", want: want{}},

		// Oracle 反例：userinfo 中出现 ipv4 字样但主机位是外部域名，必须不误判。
		{name: "http userinfo external", pingType: "http", target: "http://user@ipv4.example.com/", want: want{}},
		{name: "http external", pingType: "http", target: "http://example.com/a", want: want{}},
		{name: "https external", pingType: "http", target: "https://example.com", want: want{}},
		{name: "http selector lookalike host", pingType: "http", target: "http://local4.example.com", want: want{}},

		// 非法 type 一律报错。
		{name: "bad type", pingType: "udp", target: "local4", wantErr: true},
		{name: "empty target", pingType: "icmp", target: "  ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, isLocal, err := ParseTarget(tt.pingType, tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q, %q) expected error, got spec=%+v isLocal=%v",
						tt.pingType, tt.target, spec, isLocal)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q, %q) unexpected error: %v", tt.pingType, tt.target, err)
			}
			if isLocal != tt.want.isLocal {
				t.Fatalf("ParseTarget(%q, %q) isLocal=%v, want %v",
					tt.pingType, tt.target, isLocal, tt.want.isLocal)
			}
			if !isLocal {
				return
			}
			if spec.V6 != tt.want.v6 || spec.Port != tt.want.port || spec.Path != tt.want.path {
				t.Fatalf("ParseTarget(%q, %q) spec=%+v, want v6=%v port=%q path=%q",
					tt.pingType, tt.target, spec, tt.want.v6, tt.want.port, tt.want.path)
			}
		})
	}
}

func TestValidatePublicProbeIP(t *testing.T) {
	v4OK := []string{"1.1.1.1", "8.8.8.8", "203.0.0.10"}
	v4Bad := []string{
		"", "not-an-ip", "256.1.1.1",
		"0.0.0.0", "0.1.2.3",
		"10.0.0.1", "172.16.0.1", "192.168.1.1",
		"127.0.0.1", "127.0.0.53",
		"169.254.1.1", "224.0.0.1", "239.1.1.1",
		"100.64.1.1", "100.100.2.2",
		"198.18.0.1", "198.19.255.1",
		"192.0.0.1", "192.0.0.8", "192.88.99.1",
		"192.0.2.1", "198.51.100.1", "203.0.113.1",
		"240.0.0.1", "255.255.255.255",
		"::1", "fe80::1", "fc00::1", "2001:db8::1",
		"::ffff:192.168.1.1", "::ffff:8.8.8.8",
	}
	v6OK := []string{"2606:4700:4700::1111", "2400:3200::1", "2001:4860:4860::8888"}
	v6Bad := []string{
		"", "not-an-ip",
		"::", "::1",
		"fe80::1", "fe80::1%eth0",
		"fc00::1", "fd00::1",
		"ff02::1", "ff00::1",
		"2001:db8::1", "2001:db8:dead::beef",
		"1.1.1.1", "8.8.8.8",
		"::ffff:1.1.1.1", "::ffff:192.168.1.1",
		// 转换/特殊用途前缀反例：全部落在 2000::/3 之外或被黑名单拦截。
		"::7f00:1",          // v4-compatible（::/96），不在 2000::/3
		"64:ff9b::7f00:1",   // NAT64 well-known prefix
		"64:ff9b::a01:101",  // NAT64 内嵌 10.1.1.1
		"64:ff9b:1::7f00:1", // NAT64 本地转换前缀
		"100::1",            // Discard-Only 100::/64
		"2002:7f00:1::1",    // 6to4 内嵌 127.0.0.1
		"2001::7f00:1",      // Teredo 内嵌 127.0.0.1（2001::/23 保留）
		"2001:2::1",         // 基准测试 2001:2::/48
		"2001:20::1",        // ORCHIDv2
		"3fff::1",           // RFC 9637 文档前缀
		"5f00::1",           // RFC 9602 SRv6 SID
	}
	for _, raw := range v4OK {
		if addr, err := ValidatePublicProbeIP(raw, false); err != nil || !addr.Is4() {
			t.Errorf("ValidatePublicProbeIP(%q, v4) = %v, %v; want valid v4", raw, addr, err)
		}
	}
	for _, raw := range v4Bad {
		if addr, err := ValidatePublicProbeIP(raw, false); err == nil {
			t.Errorf("ValidatePublicProbeIP(%q, v4) unexpectedly accepted %v", raw, addr)
		}
	}
	for _, raw := range v6OK {
		if addr, err := ValidatePublicProbeIP(raw, true); err != nil || !addr.Is6() {
			t.Errorf("ValidatePublicProbeIP(%q, v6) = %v, %v; want valid v6", raw, addr, err)
		}
	}
	for _, raw := range v6Bad {
		if addr, err := ValidatePublicProbeIP(raw, true); err == nil {
			t.Errorf("ValidatePublicProbeIP(%q, v6) unexpectedly accepted %v", raw, addr)
		}
	}
}

// allowAllValidator 测试钩子：绕过公网校验以便用 loopback 验证真实拨号逻辑。
func allowAllValidator(raw string, _ bool) (netip.Addr, error) {
	return netip.ParseAddr(strings.TrimSpace(raw))
}

func drain(t *testing.T, sink chan models.PingRecord) []models.PingRecord {
	t.Helper()
	var out []models.PingRecord
	for {
		select {
		case rec := <-sink:
			out = append(out, rec)
		case <-time.After(200 * time.Millisecond):
			return out
		}
	}
}

func TestRunnerWritesMinusOneForInvalidIP(t *testing.T) {
	sink := make(chan models.PingRecord, 4)
	r := &Runner{
		WriteRecord: func(_ context.Context, rec models.PingRecord) error {
			sink <- rec
			return nil
		},
	}
	t.Cleanup(r.Wait)
	var probed atomic.Int32
	r.Probe = func(context.Context, string, Spec, netip.Addr) int {
		probed.Add(1)
		return 5
	}

	r.Run(context.Background(), 7, "client-a", "tcp",
		Spec{Port: "80"}, "192.168.1.1")
	r.Wait()
	got := drain(t, sink)
	if len(got) != 1 || got[0].Value != -1 || got[0].Client != "client-a" || got[0].TaskId != 7 {
		t.Fatalf("records = %+v, want single Value=-1 record", got)
	}
	if probed.Load() != 0 {
		t.Fatalf("probe called %d times for invalid IP, want 0", probed.Load())
	}
}

func TestRunnerDeduplicatesInflight(t *testing.T) {
	sink := make(chan models.PingRecord, 8)
	release := make(chan struct{})
	entered := make(chan struct{})
	var enteredOnce sync.Once
	var calls atomic.Int32
	r := &Runner{
		ValidateIP: allowAllValidator,
		Probe: func(context.Context, string, Spec, netip.Addr) int {
			calls.Add(1)
			enteredOnce.Do(func() { close(entered) })
			<-release
			return 42
		},
		WriteRecord: func(_ context.Context, rec models.PingRecord) error {
			sink <- rec
			return nil
		},
	}
	t.Cleanup(r.Wait)

	for i := 0; i < 4; i++ {
		r.Run(context.Background(), 9, "client-b", "tcp", Spec{Port: "80"}, "127.0.0.1")
	}
	// 确定性屏障：首个 goroutine 已进入 Probe，其余同键请求已被 in-flight
	// 去重跳过，之后才放行结果。
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("probe goroutine did not enter Probe within 5s")
	}
	close(release)
	r.Wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("probe called %d times, want 1 (in-flight dedup)", n)
	}
	got := drain(t, sink)
	if len(got) != 1 || got[0].Value != 42 {
		t.Fatalf("records = %+v, want single Value=42 record", got)
	}
}

func TestRunnerRecoversProbePanic(t *testing.T) {
	sink := make(chan models.PingRecord, 4)
	var calls atomic.Int32
	r := &Runner{
		ValidateIP: allowAllValidator,
		Probe: func(context.Context, string, Spec, netip.Addr) int {
			if calls.Add(1) == 1 {
				panic("boom")
			}
			return 12
		},
		WriteRecord: func(_ context.Context, rec models.PingRecord) error {
			sink <- rec
			return nil
		},
	}
	t.Cleanup(r.Wait)

	r.Run(context.Background(), 1, "c", "tcp", Spec{Port: "80"}, "127.0.0.1")
	r.Wait()
	// panic 后同键 in-flight 已释放，下一轮调度正常执行。
	r.Run(context.Background(), 1, "c", "tcp", Spec{Port: "80"}, "127.0.0.1")
	r.Wait()

	if calls.Load() != 2 {
		t.Fatalf("probe called %d times, want 2", calls.Load())
	}
	got := drain(t, sink)
	if len(got) != 1 || got[0].Value != 12 {
		t.Fatalf("records = %+v, want single Value=12 record after panic recovery", got)
	}
}

// TestRunnerDropsResultAfterContextCancel 回归：同一 taskID 先用不可取消的
// context.Background() 跑过一轮后，再用可取消 ctx 跑同一 taskID 并在探测
// 进行中 cancel——第二轮结果必须丢弃。旧实现把任务级 ctx 按 taskID 缓存，
// 第二轮忽略新传入的可取消父 ctx，取消后仍会写出记录（跨父 ctx 别名污
// 染）。
func TestRunnerDropsResultAfterContextCancel(t *testing.T) {
	sink := make(chan models.PingRecord, 4)
	release := make(chan struct{})
	entered := make(chan struct{})
	var enteredOnce sync.Once
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{
		ValidateIP: allowAllValidator,
		Probe: func(_ context.Context, _ string, _ Spec, _ netip.Addr) int {
			if calls.Add(1) == 1 {
				return 30 // 第一轮不阻塞，直接完成写点。
			}
			enteredOnce.Do(func() { close(entered) })
			<-release
			return 30
		},
		WriteRecord: func(_ context.Context, rec models.PingRecord) error {
			sink <- rec
			return nil
		},
	}
	t.Cleanup(r.Wait)

	// 第一轮：不可取消的 context.Background() 完成并写出一条记录，确立
	// “同一 taskID 曾在其它父 ctx 下跑过”的前置状态。
	r.Run(context.Background(), 3, "c", "tcp", Spec{Port: "80"}, "127.0.0.1")
	r.Wait()

	// 第二轮：同 taskID 换用可取消父 ctx，探测进行中取消。
	r.Run(ctx, 3, "c", "tcp", Spec{Port: "80"}, "127.0.0.1")
	// 确定性屏障：确认探测已在途后再取消。
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("probe goroutine did not enter Probe within 5s")
	}
	cancel() // 探测进行中取消：结果必须被丢弃。
	close(release)
	r.Wait()

	got := drain(t, sink)
	if len(got) != 1 || got[0].Value != 30 {
		t.Fatalf("records after cancel = %+v, want only the first-run record (Value=30)", got)
	}
}

// TestRunnerCancelDeletingBlocksConcurrentAllow 覆盖删除在途窗口的状态机闭环：
// CancelTasks 返回的 finish 未调用前，AllowTasks 不得提前解封；finish(true)
// 立墓碑后，已删任务再次删除走 finish(false) 早退也不得误清墓碑；主键复用
// 时显式 AllowTasks 才恢复探测。
func TestRunnerCancelDeletingBlocksConcurrentAllow(t *testing.T) {
	sink := make(chan models.PingRecord, 4)
	r := &Runner{
		ValidateIP: allowAllValidator,
		Probe: func(context.Context, string, Spec, netip.Addr) int {
			return 1
		},
		WriteRecord: func(_ context.Context, rec models.PingRecord) error {
			sink <- rec
			return nil
		},
	}
	t.Cleanup(r.Wait)
	run := func() {
		r.Run(context.Background(), 7, "client-x", "tcp", Spec{Port: "80"}, "127.0.0.1")
		r.Wait()
	}

	// ① 删除进行中（finish 未调用）：AllowTasks 不解 taskDeleting，写入 0 条。
	finish := r.CancelTasks([]uint{7})
	r.AllowTasks([]uint{7})
	run()
	if got := drain(t, sink); len(got) != 0 {
		t.Fatalf("during in-flight delete (taskDeleting>0), records = %+v, want none", got)
	}

	// ② finish(true) 提交墓碑后：Run 仍被拒绝。
	finish(true)
	run()
	if got := drain(t, sink); len(got) != 0 {
		t.Fatalf("after committed delete, records = %+v, want none", got)
	}

	// ③ 已删任务再次删除报 ErrRecordNotFound 早退：finish(false) 只释放引用
	// 计数，绝不误清既有墓碑。
	f2 := r.CancelTasks([]uint{7})
	f2(false)
	run()
	if got := drain(t, sink); len(got) != 0 {
		t.Fatalf("after aborted re-delete of tombstoned task, records = %+v, want none", got)
	}

	// ④ 主键复用：显式 AllowTasks 解除墓碑，任务恢复可探测。
	r.AllowTasks([]uint{7})
	run()
	got := drain(t, sink)
	if len(got) != 1 || got[0].TaskId != 7 {
		t.Fatalf("after AllowTasks on reused id, records = %+v, want 1 record", got)
	}
}

// TestProbeICMPUnprivilegedFallback 直接断言 probeICMPWithRunner 的特权→非
// 特权回退与单次告警语义：privileged=true 成功不回落；EPERM 自动回退并采用
// 非特权结果；非权限错误（超时）不回落返回 -1；双向权限失败走生产
// warnICMPPermissionOnce——把 icmpPermissionWarnLog 换成原子计数后，三次
// 调用共享进程级 icmpPermissionWarnOnce，总计告警恰为 1；若生产代码移除
// Once.Do 去重保护本用例立即 FAIL。
func TestProbeICMPUnprivilegedFallback(t *testing.T) {
	type call struct {
		val int
		err error
	}
	tests := []struct {
		name           string
		times          int // 连续调用次数（共用同一 warn）
		seq            []call
		wantEach       int
		wantPrivileged []bool
		wantWarns      int32
	}{
		{
			name:           "privileged success no fallback",
			times:          1,
			seq:            []call{{val: 12}},
			wantEach:       12,
			wantPrivileged: []bool{true},
			wantWarns:      0,
		},
		{
			name:           "eperm falls back to unprivileged",
			times:          1,
			seq:            []call{{val: -1, err: syscall.EPERM}, {val: 34}},
			wantEach:       34,
			wantPrivileged: []bool{true, false},
			wantWarns:      0,
		},
		{
			name:           "non-permission error no fallback",
			times:          1,
			seq:            []call{{val: -1, err: errors.New("i/o timeout")}},
			wantEach:       -1,
			wantPrivileged: []bool{true},
			wantWarns:      0,
		},
		{
			name:           "both denied warns once across runs",
			times:          3,
			seq:            []call{{val: -1, err: syscall.EACCES}, {val: -1, err: syscall.EACCES}},
			wantEach:       -1,
			wantPrivileged: []bool{true, false},
			wantWarns:      1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prevLog := icmpPermissionWarnLog
			icmpPermissionWarnOnce = sync.Once{}
			var warns atomic.Int32
			icmpPermissionWarnLog = func(error) { warns.Add(1) }
			t.Cleanup(func() {
				icmpPermissionWarnLog = prevLog
				icmpPermissionWarnOnce = sync.Once{}
			})
			for i := 0; i < tt.times; i++ {
				var gotPrivileged []bool
				run := func(privileged bool) (int, error) {
					gotPrivileged = append(gotPrivileged, privileged)
					if len(gotPrivileged) > len(tt.seq) {
						t.Fatalf("run called %d times in call %d, want %d",
							len(gotPrivileged), i+1, len(tt.seq))
					}
					c := tt.seq[len(gotPrivileged)-1]
					return c.val, c.err
				}
				if got := probeICMPWithRunner(context.Background(), run, warnICMPPermissionOnce); got != tt.wantEach {
					t.Fatalf("call %d: probeICMPWithRunner = %d, want %d", i+1, got, tt.wantEach)
				}
				if len(gotPrivileged) != len(tt.wantPrivileged) {
					t.Fatalf("call %d: privileged sequence = %v, want %v",
						i+1, gotPrivileged, tt.wantPrivileged)
				}
				for j := range tt.wantPrivileged {
					if gotPrivileged[j] != tt.wantPrivileged[j] {
						t.Fatalf("call %d: privileged sequence = %v, want %v",
							i+1, gotPrivileged, tt.wantPrivileged)
					}
				}
			}
			if got := warns.Load(); got != tt.wantWarns {
				t.Fatalf("warn count = %d, want %d", got, tt.wantWarns)
			}
		})
	}
}

func TestRunnerSkipsWhenSemaphoreFull(t *testing.T) {
	sink := make(chan models.PingRecord, 8)
	release := make(chan struct{})
	entered := make(chan struct{})
	var enteredOnce sync.Once
	var calls atomic.Int32
	r := &Runner{
		MaxConcurrent: 1,
		ValidateIP:    allowAllValidator,
		Probe: func(_ context.Context, _ string, _ Spec, _ netip.Addr) int {
			calls.Add(1)
			enteredOnce.Do(func() { close(entered) })
			<-release
			return 1
		},
		WriteRecord: func(_ context.Context, rec models.PingRecord) error {
			sink <- rec
			return nil
		},
	}
	t.Cleanup(r.Wait)

	r.Run(context.Background(), 1, "c1", "tcp", Spec{Port: "80"}, "127.0.0.1")
	// 确定性屏障：首个探测已进入 Probe 占住唯一并发槽。
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("probe goroutine did not enter Probe within 5s")
	}
	r.Run(context.Background(), 1, "c2", "tcp", Spec{Port: "80"}, "127.0.0.1")
	r.Run(context.Background(), 1, "c3", "tcp", Spec{Port: "80"}, "127.0.0.1")
	close(release)
	r.Wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("probe called %d times, want 1 (semaphore full skip)", n)
	}
	got := drain(t, sink)
	if len(got) != 1 || got[0].Client != "c1" {
		t.Fatalf("records = %+v, want single c1 record", got)
	}
}

func TestProbeTCPLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp4 loopback listen unavailable: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	addr := netip.MustParseAddr("127.0.0.1")
	if got := probe(context.Background(), "tcp", Spec{Port: port}, addr); got < 0 {
		t.Fatalf("tcp loopback probe = %d, want >= 0", got)
	}
	// 未监听端口应失败为 -1。
	deadLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp4 loopback listen unavailable: %v", err)
	}
	deadPort := strconv.Itoa(deadLn.Addr().(*net.TCPAddr).Port)
	deadLn.Close()
	if got := probe(context.Background(), "tcp", Spec{Port: deadPort}, addr); got != -1 {
		t.Fatalf("tcp dead-port probe = %d, want -1", got)
	}
}

func TestProbeHTTPLoopbackAndRedirect(t *testing.T) {
	var teapotHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/teapot", http.StatusFound)
	})
	mux.HandleFunc("/teapot", func(w http.ResponseWriter, _ *http.Request) {
		teapotHits.Add(1)
		w.WriteHeader(http.StatusTeapot)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener.Close()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp4 loopback listen unavailable: %v", err)
	}
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	addr := netip.MustParseAddr("127.0.0.1")

	if got := probe(context.Background(), "http", Spec{Port: port, Path: "/ok"}, addr); got < 0 {
		t.Fatalf("http 200 probe = %d, want >= 0", got)
	}
	// 不跟随 302：首个响应码 302 <400 记成功；若误跟随会命中 /teapot
	// 返回 418（记 -1）并增加 teapotHits，两路断言形成闭环判别。
	if got := probe(context.Background(), "http", Spec{Port: port, Path: "/redirect"}, addr); got < 0 {
		t.Fatalf("http 302 probe = %d, want >= 0 (no redirect follow)", got)
	}
	if got := teapotHits.Load(); got != 0 {
		t.Fatalf("/teapot hit %d time(s) during 302 probe, want 0 (redirect must not be followed)", got)
	}
	// >=400 记失败。
	if got := probe(context.Background(), "http", Spec{Port: port, Path: "/teapot"}, addr); got != -1 {
		t.Fatalf("http 418 probe = %d, want -1", got)
	}
	if got := teapotHits.Load(); got != 1 {
		t.Fatalf("/teapot hit %d time(s) after direct probe, want 1", got)
	}
}
