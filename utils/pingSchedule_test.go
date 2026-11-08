package utils

import (
	"context"
	"testing"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

// TestMain 固定内存 SQLite 实例，避免测试间争抢 DSN（与其他包 TestMain 同款模式）。
func TestMain(m *testing.M) {
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:komari_utils_pingschedule_test?mode=memory&cache=shared"
	db := dbcore.GetDBInstance()
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	m.Run()
}

// 测试内构造的「在线」v2 客户端：DispatchPing 会向其事件队列 enqueue，
// 测试用 TakeV2Events 断言是否发生下发。
const pingScheduleTestUUID = "utils-pingschedule-test-uuid"

// TestExecutePingTaskSkipsInvalidLocalSelector 验证语法非法的本机选择器目标
// （如 https://local4、local4:99999）绝不回退下发给 agent，函数直接返回。
func TestExecutePingTaskSkipsInvalidLocalSelector(t *testing.T) {
	agent_runtime.MarkV2Client(pingScheduleTestUUID)
	_ = agent_runtime.TakeV2Events(pingScheduleTestUUID, nil, 0) // 清空既有队列

	badTargets := []struct {
		pingType string
		target   string
	}{
		{"http", "https://local4"},
		{"tcp", "local4:99999"},
		{"icmp", "local4:80"},
		{"tcp", "local4:"},
		// 未闭合方括号的选择器同样绝不回退下发给 agent。
		{"icmp", "[@ipv6"},
		// userinfo/中段 '@' 位置误写选择器同样绝不回退下发给 agent。
		{"icmp", "[x]@local4"},
		{"tcp", "[x]@local4:443"},
		{"http", "http://[x]@local4/y"},
		{"icmp", "[x]@@ipv6"},
		{"tcp", "[local6]@127.0.0.1:80"},
		{"icmp", "a@local4@b"},
		{"icmp", "[local6"},
		{"tcp", "[local6:443"},
		{"tcp", "[@ipv4"},
		{"http", "http://[@ipv6"},
		// 选择器 token 误写在 '@' 两侧（userinfo 或主机位）同样绝不回退
		// 下发给 agent。
		{"tcp", "foo@local4"},
		{"tcp", "foo@local4:443"},
		{"icmp", "local4@127.0.0.1"},
		{"http", "http://local4@127.0.0.1"},
		// 选择器主机位被 scheme:// 或 path?query 包裹同样绝不回退下发，且
		// path/query 内嵌的 :// 不得被误判成顶层 scheme。
		{"tcp", "http://local4:443"},
		{"tcp", "foo@local4/x?u=http://z"},
		{"icmp", "local4@127.0.0.1?x=http://z"},
		{"icmp", "local4/?u=http://x"},
		{"http", "ws://local4:8080"},
	}
	for _, tt := range badTargets {
		task := models.PingTask{
			Id:      9001,
			Name:    "bad-local-selector",
			Type:    tt.pingType,
			Target:  tt.target,
			Clients: models.StringArray{pingScheduleTestUUID},
		}
		executePingTask(context.Background(), task)
		events := agent_runtime.TakeV2Events(pingScheduleTestUUID, nil, 0)
		if len(events) != 0 {
			t.Fatalf("executePingTask(%s %q) dispatched %d event(s), want 0 (invalid local selector must not fall back to agent dispatch)",
				tt.pingType, tt.target, len(events))
		}
	}
}
