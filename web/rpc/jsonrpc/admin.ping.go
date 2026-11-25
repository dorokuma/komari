package jsonrpc

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/database/tasks"
	"github.com/komari-monitor/komari/internal/localping"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// admin.ping.go
// 延迟监测任务（ping task）的 RPC2 方法（admin 命名空间）。

func init() {
	RegisterWithGroupAndMeta("addPingTask", rpc.RoleAdmin, adminAddPingTask, &rpc.MethodMeta{
		Name:    "admin:addPingTask",
		Summary: "Create a ping task",
		Returns: "{ task_id: uint }",
	})
	RegisterWithGroupAndMeta("deletePingTask", rpc.RoleAdmin, adminDeletePingTask, &rpc.MethodMeta{
		Name:    "admin:deletePingTask",
		Summary: "Delete ping tasks by ids",
		Returns: "null",
	})
	RegisterWithGroupAndMeta("editPingTask", rpc.RoleAdmin, adminEditPingTask, &rpc.MethodMeta{
		Name:    "admin:editPingTask",
		Summary: "Edit ping tasks",
		Returns: "null",
	})
	RegisterWithGroupAndMeta("getAllPingTasks", rpc.RoleAdmin, adminGetAllPingTasks, &rpc.MethodMeta{
		Name:    "admin:getAllPingTasks",
		Summary: "List all ping tasks",
		Returns: "PingTask[]",
	})
	RegisterWithGroupAndMeta("orderPingTask", rpc.RoleAdmin, adminOrderPingTask, &rpc.MethodMeta{
		Name:    "admin:orderPingTask",
		Summary: "Reorder ping tasks (map of id->weight)",
		Returns: "null",
	})
}

// validatePingTaskParams 统一校验延迟监测任务的 type/interval/name/target，
// 并对本机选择器目标（local4/local6）调用 localping.ParseTarget 校验语法。
func validatePingTaskParams(taskType, name, target string, interval int) *rpc.JsonRpcError {
	switch taskType {
	case "icmp", "tcp", "http":
	default:
		return rpc.MakeError(rpc.InvalidParams, "type must be one of icmp|tcp|http", nil)
	}
	if interval <= 0 {
		return rpc.MakeError(rpc.InvalidParams, "interval must be a positive number of seconds", nil)
	}
	if name == "" || target == "" {
		return rpc.MakeError(rpc.InvalidParams, "name and target are required", nil)
	}
	if _, _, err := localping.ParseTarget(taskType, target); err != nil {
		return rpc.MakeError(rpc.InvalidParams, "invalid target: "+err.Error(), nil)
	}
	return nil
}

func adminAddPingTask(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		Clients   []string `json:"clients"`
		DefaultOn bool     `json:"default_on"`
		Name      string   `json:"name"`
		Target    string   `json:"target"`
		TaskType  string   `json:"type"`
		Interval  int      `json:"interval"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid or missing request body: "+err.Error(), nil)
	}
	if err := validatePingTaskParams(params.TaskType, params.Name, params.Target, params.Interval); err != nil {
		return nil, err
	}
	taskID, err := tasks.AddPingTask(params.Clients, params.DefaultOn, params.Name, params.Target, params.TaskType, params.Interval)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	summary := fmt.Sprintf(
		"Create ping task: #%d %s (type=%s, target=%s, interval=%ds, default_on=%t)",
		taskID, params.Name, params.TaskType, params.Target, params.Interval, params.DefaultOn,
	)
	var detail string
	if len(params.Clients) > 0 {
		detail = "Clients: " + auditlog.JoinLabels(auditlog.FormatClientUUIDs(params.Clients))
	}
	auditlog.Log(ip, actor, auditlog.JoinLines(summary, detail), "info")
	return map[string]any{"task_id": taskID}, nil
}

func adminDeletePingTask(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		ID []uint `json:"id"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid or missing request body: "+err.Error(), nil)
	}
	if len(params.ID) == 0 {
		return nil, rpc.MakeError(rpc.InvalidParams, "id is required", nil)
	}
	var existing []models.PingTask
	_ = dbcore.GetDBInstance().Where("id IN ?", params.ID).Find(&existing).Error
	byID := make(map[uint]models.PingTask, len(existing))
	for _, task := range existing {
		byID[task.Id] = task
	}
	if err := tasks.DeletePingTask(params.ID); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	labels := make([]string, 0, len(params.ID))
	for _, id := range params.ID {
		if task, ok := byID[id]; ok && strings.TrimSpace(task.Name) != "" {
			labels = append(labels, fmt.Sprintf("%s(#%d, target=%s)", task.Name, id, task.Target))
		} else {
			labels = append(labels, fmt.Sprintf("#%d", id))
		}
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "Delete ping tasks: "+strings.Join(labels, ", "), "warn")
	return nil, nil
}

func adminEditPingTask(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		Tasks []*models.PingTask `json:"tasks"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid or missing request body: "+err.Error(), nil)
	}
	if len(params.Tasks) == 0 {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid request data", nil)
	}
	for _, task := range params.Tasks {
		if task == nil {
			return nil, rpc.MakeError(rpc.InvalidParams, "Invalid request data", nil)
		}
		if err := validatePingTaskParams(task.Type, task.Name, task.Target, task.Interval); err != nil {
			return nil, err
		}
	}
	if err := tasks.EditPingTask(params.Tasks); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	allClientUUIDs := make([]string, 0)
	for _, task := range params.Tasks {
		allClientUUIDs = append(allClientUUIDs, task.Clients...)
	}
	formattedAll := auditlog.FormatClientUUIDs(allClientUUIDs)
	clientLabels := make(map[string]string, len(allClientUUIDs))
	idx := 0
	for _, rawUUID := range allClientUUIDs {
		trimmed := strings.TrimSpace(rawUUID)
		if trimmed == "" {
			continue
		}
		if idx < len(formattedAll) {
			clientLabels[trimmed] = formattedAll[idx]
			idx++
		}
	}
	details := make([]string, 0, len(params.Tasks))
	for _, task := range params.Tasks {
		line := fmt.Sprintf(
			"#%d %s (type=%s, target=%s, interval=%ds, default_on=%t)",
			task.Id, task.Name, task.Type, task.Target, task.Interval, task.DefaultOn,
		)
		if len(task.Clients) > 0 {
			taskLabels := make([]string, 0, len(task.Clients))
			for _, rawUUID := range task.Clients {
				trimmed := strings.TrimSpace(rawUUID)
				if trimmed == "" {
					continue
				}
				if label := clientLabels[trimmed]; label != "" {
					taskLabels = append(taskLabels, label)
				} else {
					taskLabels = append(taskLabels, trimmed)
				}
			}
			if joined := auditlog.JoinLabels(taskLabels); joined != "" {
				line += " clients=[" + joined + "]"
			}
		}
		details = append(details, line)
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, auditlog.JoinLines(
		fmt.Sprintf("Edit ping tasks: count=%d", len(params.Tasks)),
		details...,
	), "info")
	return nil, nil
}

func adminGetAllPingTasks(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	list, err := tasks.GetAllPingTasks()
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	return list, nil
}

func adminOrderPingTask(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	// 参数为 { idStr: weight } 映射。
	order := map[uint]int{}
	var raw map[string]int
	if err := req.BindParams(&raw); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid or missing request body: "+err.Error(), nil)
	}
	for idStr, weight := range raw {
		id, err := parseUintKey(idStr)
		if err != nil {
			return nil, rpc.MakeError(rpc.InvalidParams, "Invalid task id: "+idStr, nil)
		}
		order[id] = weight
	}
	if err := tasks.UpdatePingTaskOrder(order); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, err.Error(), nil)
	}
	type item struct {
		id     uint
		weight int
	}
	items := make([]item, 0, len(order))
	for id, weight := range order {
		items = append(items, item{id: id, weight: weight})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].weight != items[j].weight {
			return items[i].weight < items[j].weight
		}
		return items[i].id < items[j].id
	})
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, fmt.Sprintf("#%d=%d", it.id, it.weight))
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, fmt.Sprintf("Order ping tasks: count=%d (%s)", len(items), strings.Join(parts, ", ")), "info")
	return nil, nil
}
