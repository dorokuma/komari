package jsonrpc

import (
	"context"
	"testing"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// addPingTaskRequest 构造 adminAddPingTask 的 JSON-RPC 请求。
func addPingTaskRequest(params map[string]any) (any, *rpc.JsonRpcError) {
	return adminAddPingTask(context.Background(), &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:addPingTask",
		Params:  params,
	})
}

func editPingTaskRequest(tasks []*models.PingTask) (any, *rpc.JsonRpcError) {
	return adminEditPingTask(context.Background(), &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:editPingTask",
		Params:  map[string]any{"tasks": tasks},
	})
}

func resetPingTaskTable(t *testing.T) {
	t.Helper()
	db := dbcore.GetDBInstance()
	if err := db.Where("1 = 1").Delete(&models.PingTask{}).Error; err != nil {
		t.Fatalf("reset ping tasks: %v", err)
	}
}

// TestAdminAddPingTaskLocalSelector 验证合法本机选择器目标放行、非法目标与非法
// type/端口被 InvalidParams 拦截。
func TestAdminAddPingTaskLocalSelector(t *testing.T) {
	resetPingTaskTable(t)

	valid := []map[string]any{
		{"name": "icmp4", "type": "icmp", "target": "local4", "interval": 60},
		{"name": "tcp6", "type": "tcp", "target": "[local6]:443", "interval": 30},
		{"name": "http4", "type": "http", "target": "http://local4:8080/health", "interval": 15},
		{"name": "ext", "type": "icmp", "target": "1.1.1.1", "interval": 60},
	}
	for _, params := range valid {
		res, jerr := addPingTaskRequest(params)
		if jerr != nil {
			t.Fatalf("addPingTask(%v) returned error: %v", params, jerr)
		}
		m, ok := res.(map[string]any)
		if !ok || m["task_id"] == nil {
			t.Fatalf("addPingTask(%v) result = %v, want {task_id}", params, res)
		}
	}

	invalid := []map[string]any{
		{"name": "https-local", "type": "http", "target": "https://local4", "interval": 60},
		{"name": "bad-port", "type": "tcp", "target": "local4:99999", "interval": 60},
		{"name": "bad-type", "type": "udp", "target": "local4", "interval": 60},
		{"name": "icmp-port", "type": "icmp", "target": "local4:80", "interval": 60},
		{"name": "no-interval", "type": "tcp", "target": "local4", "interval": 0},
		{"name": "empty-target", "type": "tcp", "target": "", "interval": 60},
	}
	for _, params := range invalid {
		res, jerr := addPingTaskRequest(params)
		if jerr == nil {
			t.Fatalf("addPingTask(%v) unexpectedly succeeded: %v", params, res)
		}
		if jerr.Code != rpc.InvalidParams {
			t.Fatalf("addPingTask(%v) error code = %d, want InvalidParams(%d): %v",
				params, jerr.Code, rpc.InvalidParams, jerr)
		}
	}
}

// TestAdminEditPingTaskLocalSelector 验证编辑任务的同款校验。
func TestAdminEditPingTaskLocalSelector(t *testing.T) {
	resetPingTaskTable(t)
	db := dbcore.GetDBInstance()
	seed := models.PingTask{
		Name: "seed", Type: "icmp", Target: "1.1.1.1", Interval: 60,
		Clients: models.StringArray{},
	}
	if err := db.Create(&seed).Error; err != nil {
		t.Fatalf("seed ping task: %v", err)
	}

	if _, jerr := editPingTaskRequest([]*models.PingTask{{
		Id: seed.Id, Name: "seed", Type: "tcp", Target: "local6:443", Interval: 45,
	}}); jerr != nil {
		t.Fatalf("editPingTask valid local6:443 returned error: %v", jerr)
	}
	var after models.PingTask
	if err := db.First(&after, seed.Id).Error; err != nil {
		t.Fatalf("reload ping task: %v", err)
	}
	if after.Target != "local6:443" || after.Type != "tcp" || after.Interval != 45 {
		t.Fatalf("edited task = %+v, want target local6:443 tcp interval 45", after)
	}

	rejected := []*models.PingTask{
		{Id: seed.Id, Name: "x", Type: "http", Target: "https://local6", Interval: 60},
		{Id: seed.Id, Name: "x", Type: "tcp", Target: "local4:abc", Interval: 60},
		{Id: seed.Id, Name: "x", Type: "udp", Target: "local4", Interval: 60},
		{Id: seed.Id, Name: "x", Type: "icmp", Target: "local4", Interval: -5},
	}
	for i, task := range rejected {
		if _, jerr := editPingTaskRequest([]*models.PingTask{task}); jerr == nil {
			t.Fatalf("editPingTask case %d (%+v) unexpectedly succeeded", i, task)
		} else if jerr.Code != rpc.InvalidParams {
			t.Fatalf("editPingTask case %d error code = %d, want InvalidParams", i, jerr.Code)
		}
	}
}

// TestAdminPingTaskMalformedBody 验证请求体绑定失败（字段类型不匹配）返回
// InvalidParams，而不是静默走参数校验。partial-bind 用例在「合法字段齐全 + 附带
// 类型错误字段」下断言：旧实现忽略 BindParams error 时会把任务写入库，因此
// 断言 InvalidParams 的同时必须断言记录数为 0。
func TestAdminPingTaskMalformedBody(t *testing.T) {
	resetPingTaskTable(t)
	db := dbcore.GetDBInstance()

	res, jerr := addPingTaskRequest(map[string]any{
		"name": "bad-type", "type": "icmp", "target": "1.1.1.1",
		"interval": "not-an-int",
	})
	if jerr == nil {
		t.Fatalf("addPingTask interval=string unexpectedly succeeded: %v", res)
	}
	if jerr.Code != rpc.InvalidParams {
		t.Fatalf("addPingTask malformed body error code = %d, want InvalidParams(%d): %v",
			jerr.Code, rpc.InvalidParams, jerr)
	}

	// 半绑定探针：其它字段全部合法，仅 clients 类型错误。若实现忽略
	// BindParams error，unmarshal 已填充的合法字段会通过校验并落库。
	res, jerr = addPingTaskRequest(map[string]any{
		"name": "partial-bind", "type": "icmp", "target": "1.1.1.1",
		"interval": 60, "clients": "not-an-array",
	})
	if jerr == nil {
		t.Fatalf("addPingTask clients=string unexpectedly succeeded: %v", res)
	}
	if jerr.Code != rpc.InvalidParams {
		t.Fatalf("addPingTask partial-bind error code = %d, want InvalidParams(%d): %v",
			jerr.Code, rpc.InvalidParams, jerr)
	}
	var count int64
	if err := db.Model(&models.PingTask{}).Where("name = ?", "partial-bind").Count(&count).Error; err != nil {
		t.Fatalf("count ping tasks: %v", err)
	}
	if count != 0 {
		t.Fatalf("partial-bind request created %d PingTask record(s), want 0", count)
	}

	_, jerr = adminDeletePingTask(context.Background(), &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:deletePingTask",
		Params:  map[string]any{"id": "not-a-number-array"},
	})
	if jerr == nil {
		t.Fatal("deletePingTask id=string unexpectedly succeeded")
	}
	if jerr.Code != rpc.InvalidParams {
		t.Fatalf("deletePingTask malformed body error code = %d, want InvalidParams(%d): %v",
			jerr.Code, rpc.InvalidParams, jerr)
	}

	// 编辑任务同样断言半绑定元素不得篡改原记录。
	seed := models.PingTask{
		Name: "seed-edit", Type: "icmp", Target: "8.8.8.8", Interval: 60,
		Clients: models.StringArray{},
	}
	if err := db.Create(&seed).Error; err != nil {
		t.Fatalf("seed ping task: %v", err)
	}
	_, jerr = adminEditPingTask(context.Background(), &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:editPingTask",
		Params: map[string]any{"tasks": []any{map[string]any{
			"id": seed.Id, "name": "tampered", "type": "icmp",
			"target": "9.9.9.9", "interval": 30,
			"clients": "not-an-array",
		}}},
	})
	if jerr == nil {
		t.Fatal("editPingTask clients=string unexpectedly succeeded")
	}
	if jerr.Code != rpc.InvalidParams {
		t.Fatalf("editPingTask partial-bind error code = %d, want InvalidParams(%d): %v",
			jerr.Code, rpc.InvalidParams, jerr)
	}
	var after models.PingTask
	if err := db.First(&after, seed.Id).Error; err != nil {
		t.Fatalf("reload seed ping task: %v", err)
	}
	if after.Name != "seed-edit" || after.Target != "8.8.8.8" || after.Interval != 60 {
		t.Fatalf("partial-bind edit mutated seed task: %+v", after)
	}

	_, jerr = adminEditPingTask(context.Background(), &rpc.JsonRpcRequest{
		Version: rpc.RPC_VERSION,
		Method:  "admin:editPingTask",
		Params:  map[string]any{"tasks": "not-an-array"},
	})
	if jerr == nil {
		t.Fatal("editPingTask tasks=string unexpectedly succeeded")
	}
	if jerr.Code != rpc.InvalidParams {
		t.Fatalf("editPingTask malformed body error code = %d, want InvalidParams(%d): %v",
			jerr.Code, rpc.InvalidParams, jerr)
	}
}
