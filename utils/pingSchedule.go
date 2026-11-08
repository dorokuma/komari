package utils

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/localping"
	"github.com/komari-monitor/komari/internal/scheduler"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	logger "github.com/komari-monitor/komari/utils/log"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

// PingTaskManager 管理定时器和任务
type PingTaskManager struct {
	mu    sync.Mutex
	tasks map[int][]models.PingTask
}

var manager = &PingTaskManager{
	tasks: make(map[int][]models.PingTask),
}

// Reload 重载时间表
func (m *PingTaskManager) Reload(pingTasks []models.PingTask) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scheduler.RemovePrefix("ping:")
	m.tasks = make(map[int][]models.PingTask)

	// 按Interval分组任务
	taskGroups := make(map[int][]models.PingTask)
	activeIDs := make([]uint, 0, len(pingTasks))
	for _, task := range pingTasks {
		if task.Interval <= 0 {
			continue
		}
		taskGroups[task.Interval] = append(taskGroups[task.Interval], task)
		activeIDs = append(activeIDs, task.Id)
	}
	// 放行当前库中存在的任务 Id：覆盖 SQLite 主键复用（删除后新建拿回同
	// 一 Id）场景；已删任务不在 pingTasks 中仍保持删除标记，挡住所
	// 有尚未进锁的旧协程，已派生的旧世代协程由 taskEpoch 不匹配丢弃。
	localping.Default.AllowTasks(activeIDs)

	// 为每个唯一的Interval创建协程
	for interval, tasks := range taskGroups {
		interval := interval
		tasks := append([]models.PingTask(nil), tasks...)
		m.tasks[interval] = tasks
		if err := scheduler.AddContextFunc(fmt.Sprintf("ping:%d", interval), scheduler.Every(time.Duration(interval)*time.Second), false, func(ctx context.Context) {
			for _, task := range tasks {
				go executePingTask(ctx, task)
			}
		}); err != nil {
			return err
		}
	}
	return nil
}

// executePingTask 执行单个PingTask：
//   - 普通外部目标：沿用反向探测，把任务下发给各在线 agent（原语义不变）。
//   - 本机选择器目标（local4/local6）：服务端正向探测各节点自报的公网 IP。
func executePingTask(ctx context.Context, task models.PingTask) {
	spec, isLocal, err := localping.ParseTarget(task.Type, task.Target)
	if err != nil {
		// 非法本地选择器目标绝不回退下发给 agent（避免把 https://local4、
		// local4:99999 等语法错误的目标原样广播给远端探针）。
		logger.Warnf("pingSchedule", "skip ping task %d with invalid target %q (type=%q): %v",
			task.Id, task.Target, task.Type, err)
		return
	}
	if isLocal {
		executeLocalPingTask(ctx, task, spec)
		return
	}
	for _, clientUUID := range targetPingClientUUIDs(task) {
		select {
		case <-ctx.Done():
			// Context was canceled, stop sending pings.
			return
		default:
			// Context is still active, continue.
		}

		agent_runtime.DispatchPing(clientUUID, v2.PingParams{TaskID: task.Id, Type: task.Type, Target: task.Target})
	}
}

// executeLocalPingTask 服务端正向探测：只对真实在线节点执行，单条批量
// SQL 取出目标 IP 后经 localping.Default 并行扇出。
//
// 在线集用 agent_runtime.GetAllOnlineUUIDs（活跃 WebSocket 连接 ∪ 未过期
// HTTP presence），绝不能用 IsAgentOnline——它内部回退 IsV2Client，而
// v2Clients 是粘滞标记：HTTP POST 节点 35s 心跳超时后 postPresenceExpired
// 只清 presenceOnly 不清 v2Clients，会让已离线 HTTP 节点仍被持续探测其
// 过期自报 IP。（原版反向 DispatchPing 的 IsV2Client 分支是既有行为，
// 不受影响。）
func executeLocalPingTask(ctx context.Context, task models.PingTask, spec localping.Spec) {
	if ctx.Err() != nil {
		return
	}
	all := agent_runtime.GetAllOnlineUUIDs()
	onlineSet := make(map[string]struct{}, len(all))
	for _, uuid := range all {
		onlineSet[uuid] = struct{}{}
	}
	onlineUUIDs := make([]string, 0, len(task.Clients))
	for _, uuid := range task.Clients {
		if _, ok := onlineSet[uuid]; ok {
			onlineUUIDs = append(onlineUUIDs, uuid)
		}
	}
	if len(onlineUUIDs) == 0 {
		return
	}
	if ctx.Err() != nil {
		return
	}
	var clients []models.Client
	if err := dbcore.GetDBInstance().Model(&models.Client{}).
		Select("uuid, ipv4, ipv6").
		Where("uuid IN ?", onlineUUIDs).
		Find(&clients).Error; err != nil {
		logger.Errorf("pingSchedule", "local ping task %d failed to load client IPs: %v", task.Id, err)
		return
	}
	for _, client := range clients {
		rawIP := client.IPv4
		if spec.V6 {
			rawIP = client.IPv6
		}
		localping.Default.Run(ctx, task.Id, client.UUID, task.Type, spec, rawIP)
	}
}

// targetPingClientUUIDs 根据任务配置计算本次调度需要下发的在线服务器列表。
func targetPingClientUUIDs(task models.PingTask) []string {
	return task.Clients
}

// ReloadPingSchedule 加载或重载时间表
func ReloadPingSchedule(pingTasks []models.PingTask) error {
	return manager.Reload(pingTasks)
}
