package utils

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/internal/localping"
	"github.com/komari-monitor/komari/internal/metricstore"
	"github.com/komari-monitor/komari/pkg/metric"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

// TestExecutePingTaskCancelledContext 验证 ctx 已取消时 executePingTask 对
// 本机选择器目标与外部目标都立即返回，不读库、不向 agent 下发任何事件。
func TestExecutePingTaskCancelledContext(t *testing.T) {
	agent_runtime.MarkV2Client(pingScheduleTestUUID)
	_ = agent_runtime.TakeV2Events(pingScheduleTestUUID, nil, 0) // 清空既有队列

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		localTask := models.PingTask{
			Id:      9002,
			Name:    "cancelled-local",
			Type:    "tcp",
			Target:  "local4:443",
			Clients: models.StringArray{pingScheduleTestUUID},
		}
		externalTask := models.PingTask{
			Id:      9003,
			Name:    "cancelled-external",
			Type:    "icmp",
			Target:  "1.1.1.1",
			Clients: models.StringArray{pingScheduleTestUUID},
		}
		executePingTask(ctx, localTask)
		executePingTask(ctx, externalTask)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("executePingTask did not return promptly on cancelled context")
	}
	if events := agent_runtime.TakeV2Events(pingScheduleTestUUID, nil, 0); len(events) != 0 {
		t.Fatalf("cancelled context dispatched %d event(s), want 0", len(events))
	}
}

// TestExecutePingTaskSkipsExpiredHTTPPresence 回归：HTTP POST 上报的 v2 节点
// 超过 35s 未报心跳即过期（postPresenceExpired 仅清 presenceOnly、不清
// v2Clients），本机正向探测（local4/local6 目标）绝不能继续探测已离线
// 节点——探测其过期自报 IP 无意义且会写孤儿点。
//
// 断言在线集语义为「活跃 WebSocket 连接 ∪ 未过期 presenceOnly」，而非
// IsAgentOnline（HTTP 节点超时后 v2Clients 残留仍返回 true）。裸基线
// （无本机选择器分支）与旧 IsAgentOnline 筛选实现均在本用例 FAIL：
//   - 裸基线把 local4:80 当普通外部目标向两个 v2 节点各下发一条事件；
//   - 旧实现不对 expiredUUID 发包但仍为其探测并落盘 Value=-1 点。
//
// 完成屏障是确定性的：localping.Default.Wait() 等全部在途探测 goroutine
// 走完写临界区（wg.Done 为首个 defer，LIFO 保证在 write 返回后才执行），
// metricstore.FlushPending 再排空 batcher 的 ping 待写队列（无 batcher 时
// WritePingRecord 同步直写、FlushPending 安全返回 nil）。屏障之后所有已
// 触发的探测点 100% 可被 GetStore().Query 查到，无需轮询。
func TestExecutePingTaskSkipsExpiredHTTPPresence(t *testing.T) {
	// 内存 store 的原始样本按 (series, 毫秒时间戳) 替换写：-count=N 快速
	// 重跑时若本轮写入与上一轮落在同一毫秒会被覆盖而非累加。先让出一个
	// 毫秒边界，保证增量断言在 -count=N 下同样确定（一次性让位，非轮询）。
	time.Sleep(2 * time.Millisecond)

	// 内存 metric store 用于核对本机探测是否落盘。
	if err := config.Set(metricstore.MetricDBDSNKey,
		"file:komari_utils_presence_metrics?mode=memory&cache=shared"); err != nil {
		t.Fatalf("set metric store dsn: %v", err)
	}
	if err := metricstore.InitializeStore(); err != nil {
		t.Fatalf("initialize metric store: %v", err)
	}

	db := dbcore.GetDBInstance()
	const onlineUUID = "utils-http-online-uuid"
	const expiredUUID = "utils-http-expired-uuid"
	clients := []models.Client{
		// 私网自报 IP：内存级 SSRF 校验（ValidatePublicProbeIP）立即拒绝，
		// 零网络发包即写 Value=-1，使「被探测与否」可直接由点数区分。
		{UUID: onlineUUID, Token: "utils-presence-online-token", IPv4: "192.168.1.10"},
		{UUID: expiredUUID, Token: "utils-presence-expired-token", IPv4: "192.168.1.11"},
	}
	if err := db.Create(&clients).Error; err != nil {
		t.Fatalf("create clients: %v", err)
	}
	t.Cleanup(func() {
		db.Where("uuid IN ?", []string{onlineUUID, expiredUUID}).Delete(&models.Client{})
	})

	// 模拟 HTTP v2 上报节点：在线节点 presence 未过期；离线节点 presence
	// 已被 postPresenceExpired 清除但 v2Clients 残留。
	agent_runtime.MarkV2Client(onlineUUID)
	agent_runtime.MarkV2Client(expiredUUID)
	agent_runtime.KeepAlivePresence(onlineUUID, 101, time.Minute)
	t.Cleanup(func() { agent_runtime.SetPresence(onlineUUID, 101, false) })
	agent_runtime.KeepAlivePresence(expiredUUID, 102, time.Minute)
	agent_runtime.SetPresence(expiredUUID, 102, false)
	if !agent_runtime.IsV2Client(expiredUUID) {
		t.Fatal("expired HTTP node lost v2Clients mark; precondition for reproducing the bug is gone")
	}
	_ = agent_runtime.TakeV2Events(onlineUUID, nil, 0)
	_ = agent_runtime.TakeV2Events(expiredUUID, nil, 0)

	countPoints := func(uuid string, taskID int) int {
		points, err := metricstore.GetStore().Query(context.Background(), metric.Query{
			MetricName: metricstore.MetricPingLatency,
			EntityID:   uuid,
			Tags:       map[string]string{"task_id": strconv.Itoa(taskID)},
			Start:      time.Now().Add(-time.Hour),
			End:        time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("query ping points for %s task %d: %v", uuid, taskID, err)
		}
		return len(points)
	}
	start9004 := countPoints(onlineUUID, 9004)
	start9006 := countPoints(onlineUUID, 9006)

	// 任务 9004 同时列出在线与离线节点：裸基线会向两者各下发一条事件
	// （FAIL 点 1）；正确实现绝不向 agent 下发本机探测任务。
	executePingTask(context.Background(), models.PingTask{
		Id:      9004,
		Name:    "presence-filter",
		Type:    "tcp",
		Target:  "local4:80",
		Clients: models.StringArray{expiredUUID, onlineUUID},
	})
	for _, uuid := range []string{onlineUUID, expiredUUID} {
		if events := agent_runtime.TakeV2Events(uuid, nil, 0); len(events) != 0 {
			t.Fatalf("local ping task dispatched %d event(s) to %s, want 0", len(events), uuid)
		}
	}

	// 仅含离线节点的任务 9005 与仅含在线节点的任务 9006。
	executePingTask(context.Background(), models.PingTask{
		Id:      9005,
		Name:    "presence-expired-only",
		Type:    "tcp",
		Target:  "local4:80",
		Clients: models.StringArray{expiredUUID},
	})
	executePingTask(context.Background(), models.PingTask{
		Id:      9006,
		Name:    "presence-online-only",
		Type:    "tcp",
		Target:  "local4:80",
		Clients: models.StringArray{onlineUUID},
	})

	// 确定性完成屏障：等待全部在途探测 goroutine 完成落盘，并排空
	// metricstore 批量写队列。此后点数断言无需轮询。
	localping.Default.Wait()
	if err := metricstore.FlushPending(context.Background()); err != nil {
		t.Fatalf("flush pending ping records: %v", err)
	}

	// 在线节点自报 IP 为私网地址，SSRF 校验拒绝后写 Value=-1：9004/9006
	// 各新增 1 点。点数按增量断言：-count=N 重复执行时内存 metric store
	// 跨次共享，累计点数会超过 1。
	if n := countPoints(onlineUUID, 9004) - start9004; n != 1 {
		t.Fatalf("online UUID gained %d point(s) for task 9004, want +1 (start %d)", n, start9004)
	}
	if n := countPoints(onlineUUID, 9006) - start9006; n != 1 {
		t.Fatalf("online UUID gained %d point(s) for task 9006, want +1 (start %d)", n, start9006)
	}

	// 离线节点绝不落盘：旧 IsAgentOnline 实现会为其写 Value=-1（FAIL 点 2）。
	if n := countPoints(expiredUUID, 9004); n != 0 {
		t.Fatalf("expired HTTP node has %d point(s) for task 9004, want 0", n)
	}
	if n := countPoints(expiredUUID, 9005); n != 0 {
		t.Fatalf("expired HTTP node has %d point(s) for task 9005, want 0", n)
	}
}
