package tasks

import (
	"context"
	"slices"
	"sort"
	"sync"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/localping"
	"github.com/komari-monitor/komari/internal/metricstore"
	"github.com/komari-monitor/komari/utils"
	"gorm.io/gorm"
)

// pingTaskMu 串行化全部 PingTask 变更与调度重载入口：删除时
// CancelTasks→Flush→删行→提交墓碑→重载的完整序列与其它入口的重载
// （读库→AllowTasks→重建调度表）互斥，消除「锁外读旧快照后反写调度表与
// AllowTasks」的竞态窗口。
var pingTaskMu sync.Mutex

// reloadPingScheduleLocked 在持有 pingTaskMu 期间读取任务表并重载调度，
// 必须与调用方在同一临界区内执行，保证快照与 AllowTasks/墓碑决策一致。
func reloadPingScheduleLocked() error {
	pingTasks, err := GetAllPingTasks()
	if err != nil {
		return err
	}
	return utils.ReloadPingSchedule(pingTasks)
}

// AddPingTask 创建延迟监测任务。defaultOn 表示新加入的服务器是否自动开启此监测。
func AddPingTask(clients []string, defaultOn bool, name string, target, task_type string, interval int) (uint, error) {
	pingTaskMu.Lock()
	defer pingTaskMu.Unlock()

	db := dbcore.GetDBInstance()
	normalizedClients := normalizePingClients(models.StringArray(clients))
	task := models.PingTask{
		Clients:   normalizedClients,
		DefaultOn: defaultOn,
		Name:      name,
		Type:      task_type,
		Target:    target,
		Interval:  interval,
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&task).Error; err != nil {
			return err
		}
		// Append by id to avoid races between concurrent create requests.
		return tx.Model(&models.PingTask{}).Where("id = ?", task.Id).Update("weight", int(task.Id)).Error
	})
	if err != nil {
		return 0, err
	}
	// SQLite 主键（非 AUTOINCREMENT）可能被复用：立即解除该 Id 的删除标
	// 记放行新任务；删除前旧世代残余协程已由 taskEpoch 不匹配挡在写点
	// 路径之外。
	localping.Default.AllowTasks([]uint{task.Id})
	_ = reloadPingScheduleLocked()
	return task.Id, nil
}

func DeletePingTask(id []uint) error {
	pingTaskMu.Lock()
	defer pingTaskMu.Unlock()

	// 删除前的同步栅栏：推进该批任务世代号、递增在途删除引用计数并取消
	// 全部在途探测。finish(committed) 由 sync.Once 保护：finish(true) 立
	// 墓碑（taskDeleted），finish(false) 仅释放引用计数、绝不触碰既有
	// 墓碑（并发重复删除报 ErrRecordNotFound 早退时不会误清）。
	finish := localping.Default.CancelTasks(id)
	defer func() { finish(false) }()

	// 排空 report batcher 中已入队未落盘的记录，确保接下来删除的是完整历史。
	if err := metricstore.FlushPending(context.Background()); err != nil {
		return err
	}
	// The metric store is independent from the main database, so clean it first
	// to avoid leaving history that can no longer be addressed through the task.
	if err := DeletePingRecords(id); err != nil {
		return err
	}

	db := dbcore.GetDBInstance()
	result := db.Where("id IN ?", id).Delete(&models.PingTask{})
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	if result.Error != nil {
		return result.Error
	}
	// 删行成功：提交墓碑（sync.Once 生效，defer 的 finish(false) 自动空转），
	// 随后在持锁状态下重载调度，杜绝并发 ReloadPingSchedule 反写旧快照。
	finish(true)
	return reloadPingScheduleLocked()
}

// EditPingTask 批量更新延迟监测任务配置。
func EditPingTask(tasks []*models.PingTask) error {
	pingTaskMu.Lock()
	defer pingTaskMu.Unlock()

	db := dbcore.GetDBInstance()
	for _, task := range tasks {
		task.Clients = normalizePingClients(task.Clients)
		// 使用 map 显式更新，避免 GORM struct Updates 跳过 false/0/空切片等零值。
		updates := map[string]interface{}{
			"name":        task.Name,
			"clients":     task.Clients,
			"all_clients": task.DefaultOn,
			"type":        task.Type,
			"target":      task.Target,
			"interval":    task.Interval,
		}
		result := db.Model(&models.PingTask{}).Where("id = ?", task.Id).Updates(updates)
		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
	}
	return reloadPingScheduleLocked()
}

// normalizePingClients 保持 clients 字段序列化为 JSON 数组，避免空值变成 null。
func normalizePingClients(clients models.StringArray) models.StringArray {
	if clients == nil {
		return models.StringArray{}
	}
	return clients
}

func GetAllPingTasks() ([]models.PingTask, error) {
	db := dbcore.GetDBInstance()
	var tasks []models.PingTask
	if err := db.Order("weight ASC").Order("id ASC").Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

// GetPingTasksByClient 获取指定服务器需要执行的延迟监测任务。
func GetPingTasksByClient(uuid string) []models.PingTask {
	db := dbcore.GetDBInstance()
	var tasks []models.PingTask
	if err := db.Where("clients LIKE ?", `%"`+uuid+`"%`).Order("weight ASC").Order("id ASC").Find(&tasks).Error; err != nil {
		return nil
	}
	return tasks
}

func UpdatePingTaskOrder(order map[uint]int) error {
	if len(order) == 0 {
		return nil
	}

	pingTaskMu.Lock()
	defer pingTaskMu.Unlock()

	db := dbcore.GetDBInstance()
	err := db.Transaction(func(tx *gorm.DB) error {
		// Validate all ids before changing any weights. The update response is
		// not a reliable existence check because some drivers report zero rows
		// when the new value equals the current value.
		ids := make([]uint, 0, len(order))
		for id := range order {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

		var existing int64
		if err := tx.Model(&models.PingTask{}).Where("id IN ?", ids).Count(&existing).Error; err != nil {
			return err
		}
		if existing != int64(len(ids)) {
			return gorm.ErrRecordNotFound
		}

		for _, id := range ids {
			if err := tx.Model(&models.PingTask{}).Where("id = ?", id).Update("weight", order[id]).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return reloadPingScheduleLocked()
}

// ping 记录已完全迁移到 metric store（指标 ping.latency_ms），运行期读写全部走
// metric store，旧 ping_records 表不再参与。

func SavePingRecord(record models.PingRecord) error {
	return metricstore.WritePingRecord(context.Background(), record)
}

func DeletePingRecords(id []uint) error {
	return metricstore.DeletePingRecordsByTask(context.Background(), id)
}

func DeleteAllPingRecords() error {
	return metricstore.DeleteAllPingRecords(context.Background())
}

func ReloadPingSchedule() error {
	pingTaskMu.Lock()
	defer pingTaskMu.Unlock()
	return reloadPingScheduleLocked()
}

// AddDefaultOnClientUUID 在新客户端注册后，把该 UUID 追加到所有 default_on=true 的任务的 clients 中（去重）。
func AddDefaultOnClientUUID(uuid string) error {
	pingTaskMu.Lock()
	defer pingTaskMu.Unlock()

	db := dbcore.GetDBInstance()
	var tasks []models.PingTask
	if err := db.Where("all_clients = ?", true).Find(&tasks).Error; err != nil {
		return err
	}
	changed := false
	for _, task := range tasks {
		if slices.Contains(task.Clients, uuid) {
			continue
		}
		next := append(models.StringArray{}, task.Clients...)
		next = append(next, uuid)
		if err := db.Model(&models.PingTask{}).Where("id = ?", task.Id).Update("clients", next).Error; err != nil {
			return err
		}
		changed = true
	}
	if changed {
		return reloadPingScheduleLocked()
	}
	return nil
}
