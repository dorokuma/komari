package tasks

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/internal/localping"
	"github.com/komari-monitor/komari/internal/metricstore"
	"github.com/komari-monitor/komari/pkg/metric"
	"gorm.io/gorm"
)

func TestClearTaskResultsByTimeBeforeUsesUTCTimeValue(t *testing.T) {
	resetTaskTables(t)
	db := dbcore.GetDBInstance()

	taskID := "task-cleanup-time"
	if err := db.Create(&models.Task{TaskId: taskID, Command: "true"}).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	cutoff := time.Date(2026, 7, 17, 12, 0, 0, 123456789, time.UTC)
	results := []models.TaskResult{
		{TaskId: taskID, Client: "old", CreatedAt: cutoff.Add(-time.Nanosecond)},
		{TaskId: taskID, Client: "boundary", CreatedAt: cutoff},
		{TaskId: taskID, Client: "new", CreatedAt: cutoff.Add(time.Nanosecond)},
	}
	if err := db.Create(&results).Error; err != nil {
		t.Fatalf("create task results: %v", err)
	}

	localCutoff := cutoff.In(time.FixedZone("UTC+8", 8*60*60))
	if err := ClearTaskResultsByTimeBefore(localCutoff); err != nil {
		t.Fatalf("clear task results: %v", err)
	}
	var remaining []models.TaskResult
	if err := db.Where("task_id = ?", taskID).Order("created_at").Find(&remaining).Error; err != nil {
		t.Fatalf("load remaining results: %v", err)
	}
	if len(remaining) != 2 || remaining[0].Client != "boundary" || remaining[1].Client != "new" {
		t.Fatalf("remaining results = %#v, want boundary and new", remaining)
	}
}

func TestGetAllPingTasksOrdersByWeightThenID(t *testing.T) {
	resetTaskTables(t)
	db := dbcore.GetDBInstance()

	tasks := []models.PingTask{
		{Name: "third", Weight: 2, Type: "icmp", Target: "third.example", Interval: 60},
		{Name: "first", Weight: 0, Type: "icmp", Target: "first.example", Interval: 60},
		{Name: "second", Weight: 0, Type: "icmp", Target: "second.example", Interval: 60},
	}
	if err := db.Create(&tasks).Error; err != nil {
		t.Fatalf("create ping tasks: %v", err)
	}

	ordered, err := GetAllPingTasks()
	if err != nil {
		t.Fatalf("get ordered ping tasks: %v", err)
	}
	if len(ordered) != len(tasks) {
		t.Fatalf("ordered ping task count = %d, want %d", len(ordered), len(tasks))
	}
	if ordered[0].Id != tasks[1].Id || ordered[1].Id != tasks[2].Id || ordered[2].Id != tasks[0].Id {
		t.Fatalf("ping task order = %#v, want ids [%d %d %d]", ordered, tasks[1].Id, tasks[2].Id, tasks[0].Id)
	}
}

func TestUpdatePingTaskOrderAllowsUnchangedWeights(t *testing.T) {
	resetTaskTables(t)
	db := dbcore.GetDBInstance()

	items := []models.PingTask{
		{Name: "first", Weight: 0, Type: "icmp", Target: "first.example", Interval: 60},
		{Name: "second", Weight: 1, Type: "icmp", Target: "second.example", Interval: 60},
	}
	if err := db.Create(&items).Error; err != nil {
		t.Fatalf("create ping tasks: %v", err)
	}

	if err := UpdatePingTaskOrder(map[uint]int{
		items[0].Id: 0,
		items[1].Id: 2,
	}); err != nil {
		t.Fatalf("update ping task order: %v", err)
	}

	var first, second models.PingTask
	if err := db.First(&first, items[0].Id).Error; err != nil {
		t.Fatalf("load first ping task: %v", err)
	}
	if err := db.First(&second, items[1].Id).Error; err != nil {
		t.Fatalf("load second ping task: %v", err)
	}
	if first.Weight != 0 || second.Weight != 2 {
		t.Fatalf("weights = [%d, %d], want [0, 2]", first.Weight, second.Weight)
	}
}

func TestGetPingTasksByClientOrdersByWeightThenID(t *testing.T) {
	resetTaskTables(t)
	db := dbcore.GetDBInstance()

	items := []models.PingTask{
		{Name: "third", Weight: 2, Clients: models.StringArray{"node-a"}, Type: "icmp", Target: "third.example", Interval: 60},
		{Name: "first", Weight: 0, Clients: models.StringArray{"node-a"}, Type: "icmp", Target: "first.example", Interval: 60},
		{Name: "other", Weight: 1, Clients: models.StringArray{"node-b"}, Type: "icmp", Target: "other.example", Interval: 60},
	}
	if err := db.Create(&items).Error; err != nil {
		t.Fatalf("create ping tasks: %v", err)
	}

	ordered := GetPingTasksByClient("node-a")
	if len(ordered) != 2 || ordered[0].Id != items[1].Id || ordered[1].Id != items[0].Id {
		t.Fatalf("ping task order = %#v, want ids [%d %d]", ordered, items[1].Id, items[0].Id)
	}
}

// TestDeletePingTaskPurgesInflightLocalProbes 端到端验证删除任务的时序闭环：
// 删除发起时第 1 次探测在途且被同步取消（DeletePingTask 返回时历史点数为
// 0），同一 Id 复用重建后旧世代探测即使迟返也绝不能写孤儿点，新世代探测
// 正常落盘。Probe 全程为同一闭包（按 clientUUID 分支区分世代），杜绝运行
// 期重写 localping.Default.Probe 字段的竞态。
func TestDeletePingTaskPurgesInflightLocalProbes(t *testing.T) {
	resetTaskTables(t)
	db := dbcore.GetDBInstance()
	ctx := context.Background()
	// 第 1 次在途探测专用可取消父 ctx：正常路径下由 DeletePingTask 内部
	// CancelTasks 先取消子 probeCtx；本测试的兜底取消仅用于回归场景——
	// 万一未来 CancelTasks 丢失取消，t.Cleanup 先 cancel 本父 ctx 能立即
	// 唤醒 <-probeCtx.Done() 与 <-release，绝不永久卡死 Wait()。
	inflightParentCtx, cancelInflightParent := context.WithCancel(ctx)

	// metric store 指向临时 SQLite 文件（InitializeStore 读 config DB；
	// dbcore 初始化时已 config.SetDb）。
	if err := config.Set(metricstore.MetricDBDSNKey,
		filepath.ToSlash(filepath.Join(t.TempDir(), "metrics.db"))); err != nil {
		t.Fatalf("set metric store dsn: %v", err)
	}
	if err := metricstore.InitializeStore(); err != nil {
		t.Fatalf("initialize metric store: %v", err)
	}
	metricstore.StartReportBatcher()
	t.Cleanup(func() {
		if err := metricstore.StopReportBatcher(ctx); err != nil {
			t.Errorf("stop report batcher: %v", err)
		}
	})

	task := models.PingTask{
		Name: "delete-local", Type: "tcp", Target: "local4:443",
		Interval: 60, Clients: models.StringArray{},
	}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create ping task: %v", err)
	}

	// 已入 pingQueue 待落盘的一条历史记录：删除前必须刷盘再清除。
	if err := metricstore.WritePingRecord(ctx, models.PingRecord{
		Client: "node-q", TaskId: task.Id, Value: 12, Time: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("queue pending ping record: %v", err)
	}

	// 在途本机探测：真实 localping.Default Runner + 真实 metricstore 写路径。
	// 单一 Probe 闭包按调用序号区分世代（Probe 签名拿不到 clientUUID）：第
	// 1 次为旧世代在途探测——进入后关闭 entered，监听 probeCtx.Done() 向
	// canceledCh 发送取消信号，然后继续阻塞在 release 上保持「在途」，最终
	// 返回 42；后续调用为新世代，立即返回 7。杜绝运行期重写
	// localping.Default.Probe 字段的竞态。
	prevValidate := localping.Default.ValidateIP
	prevProbe := localping.Default.Probe
	localping.Default.ValidateIP = func(raw string, _ bool) (netip.Addr, error) {
		return netip.ParseAddr(strings.TrimSpace(raw))
	}
	entered := make(chan struct{})
	canceledCh := make(chan struct{}, 1)
	release := make(chan struct{})
	var closeReleaseOnce sync.Once
	var probeCalls atomic.Int32
	localping.Default.Probe = func(probeCtx context.Context, _ string, _ localping.Spec, _ netip.Addr) int {
		if probeCalls.Add(1) != 1 {
			return 7 // 新世代探测：不阻塞，直接返回 RTT 7。
		}
		close(entered)
		// 阻塞等待删除取消本探测的 context：发送取消信号后继续阻塞在
		// release 上保持「在途」，模拟真实探针 ctx 取消后仍需时间退出。
		<-probeCtx.Done()
		canceledCh <- struct{}{}
		<-release
		return 42
	}
	t.Cleanup(func() {
		// 先取消第 1 次在途探测的父 ctx：即便 CancelTasks 回归未能取消
		// probeCtx，也能立即唤醒 <-probeCtx.Done()，再放行 release 并等
		// Wait() 有界退出。
		cancelInflightParent()
		closeReleaseOnce.Do(func() { close(release) })
		localping.Default.Wait()
		localping.Default.ValidateIP = prevValidate
		localping.Default.Probe = prevProbe
	})

	localping.Default.Run(inflightParentCtx, task.Id, "node-inflight", "tcp", localping.Spec{Port: "443"}, "127.0.0.1")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("probe goroutine did not enter Probe within 5s")
	}

	// 探测仍在途（release 未放行）即同步执行删除：CancelTasks 必须取消该
	// 探测的 context，Flush 队列并清除历史与任务行。
	if err := DeletePingTask([]uint{task.Id}); err != nil {
		t.Fatalf("DeletePingTask: %v", err)
	}
	select {
	case <-canceledCh:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight probe ctx was not cancelled by DeletePingTask")
	}

	// 删除返回后该 task_id 的历史点数必须为 0（待写队列已刷盘并清除）。
	store := metricstore.GetStore()
	points, err := store.Query(ctx, metric.Query{
		MetricName: metricstore.MetricPingLatency,
		Tags:       map[string]string{"task_id": strconv.Itoa(int(task.Id))},
		Start:      time.Now().Add(-time.Hour),
		End:        time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("query ping latency after delete: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("task %d has %d ping point(s) right after delete, want 0 (orphan points resurrected): %+v",
			task.Id, len(points), points)
	}

	// 主键复用：在旧世代探测仍阻塞在途时以同一 Id 重建任务行并重载调度
	// （AllowTasks 解除墓碑放行新世代）。
	if err := db.Create(&models.PingTask{
		Id: task.Id, Name: "reuse-id", Type: "tcp", Target: "local4:443",
		Interval: 60, Clients: models.StringArray{},
	}).Error; err != nil {
		t.Fatalf("recreate ping task with reused id: %v", err)
	}
	if err := ReloadPingSchedule(); err != nil {
		t.Fatalf("reload ping schedule after re-add: %v", err)
	}

	// 放行旧世代：它迟返的 42 必须被 epoch 不匹配（或已取消 ctx）拦截丢弃；
	// 同时发起的新世代探测返回 7 正常落盘。
	closeReleaseOnce.Do(func() { close(release) })
	localping.Default.Run(ctx, task.Id, "node-new", "tcp", localping.Spec{Port: "443"}, "127.0.0.1")
	localping.Default.Wait()
	if err := metricstore.FlushPending(ctx); err != nil {
		t.Fatalf("flush pending after re-add: %v", err)
	}
	points, err = store.Query(ctx, metric.Query{
		MetricName: metricstore.MetricPingLatency,
		Tags:       map[string]string{"task_id": strconv.Itoa(int(task.Id))},
		Start:      time.Now().Add(-time.Hour),
		End:        time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("query ping latency after re-add: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("recreated task %d has %d ping point(s), want 1 (stale generation point must be dropped)",
			task.Id, len(points))
	}
	if points[0].Value != 7 {
		t.Fatalf("recreated task %d point value = %v, want 7 (new generation only)", task.Id, points[0].Value)
	}
}

// TestDeletePingTaskConcurrentReloadDoesNotResurrect 验证删除与并发重载的
// 状态机闭环：pingTaskMu 串行化后，无论 DeletePingTask 与 ReloadPingSchedule
// 如何交错，已删任务都不会被锁外旧快照反写回调度表；并发重复删除必须恰
// 一次成功、其余返回 ErrRecordNotFound 且不破坏既有墓碑（taskDeleting
// 归零后 taskDeleted 仍在）。
func TestDeletePingTaskConcurrentReloadDoesNotResurrect(t *testing.T) {
	resetTaskTables(t)
	db := dbcore.GetDBInstance()
	ctx := context.Background()

	if err := config.Set(metricstore.MetricDBDSNKey,
		filepath.ToSlash(filepath.Join(t.TempDir(), "metrics.db"))); err != nil {
		t.Fatalf("set metric store dsn: %v", err)
	}
	if err := metricstore.InitializeStore(); err != nil {
		t.Fatalf("initialize metric store: %v", err)
	}
	metricstore.StartReportBatcher()
	t.Cleanup(func() {
		if err := metricstore.StopReportBatcher(ctx); err != nil {
			t.Errorf("stop report batcher: %v", err)
		}
	})

	task := models.PingTask{
		Name: "delete-concurrent", Type: "tcp", Target: "local4:443",
		Interval: 60, Clients: models.StringArray{},
	}
	if err := db.Create(&task).Error; err != nil {
		t.Fatalf("create ping task: %v", err)
	}

	// 统计本机探测落盘次数：删除后墓碑必须让 Run 写入恒为 0。
	prevValidate := localping.Default.ValidateIP
	prevProbe := localping.Default.Probe
	prevWrite := localping.Default.WriteRecord
	localping.Default.ValidateIP = func(raw string, _ bool) (netip.Addr, error) {
		return netip.ParseAddr(strings.TrimSpace(raw))
	}
	localping.Default.Probe = func(context.Context, string, localping.Spec, netip.Addr) int {
		return 9
	}
	var writes atomic.Int32
	localping.Default.WriteRecord = func(context.Context, models.PingRecord) error {
		writes.Add(1)
		return nil
	}
	t.Cleanup(func() {
		localping.Default.Wait()
		localping.Default.ValidateIP = prevValidate
		localping.Default.Probe = prevProbe
		localping.Default.WriteRecord = prevWrite
	})

	// 交错执行：两次并发删除（恰一次成功）+ 并发全量重载。
	type opResult struct {
		ok       bool
		notFound bool
	}
	results := make(chan opResult, 3)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := DeletePingTask([]uint{task.Id})
			results <- opResult{ok: err == nil, notFound: errors.Is(err, gorm.ErrRecordNotFound)}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := ReloadPingSchedule()
		results <- opResult{ok: err == nil}
	}()
	wg.Wait()
	close(results)

	// 恰一次删除成功 + 一次重载成功 = 2 个 ok；第二次删除必须
	// ErrRecordNotFound 早退（finish(false) 不误清墓碑）。
	var succeeded, notFound int
	for res := range results {
		if res.ok {
			succeeded++
		}
		if res.notFound {
			notFound++
		}
	}
	if notFound != 1 {
		t.Fatalf("concurrent re-delete returned %d ErrRecordNotFound, want exactly 1", notFound)
	}
	if succeeded != 2 {
		t.Fatalf("successful ops = %d, want 2 (one delete + one reload)", succeeded)
	}

	// 已删任务行必须不存在；重载快照不得把它反写回调度表（Runner 层由
	// 墓碑兜底，写入恒为 0）。
	var count int64
	if err := db.Model(&models.PingTask{}).Where("id = ?", task.Id).Count(&count).Error; err != nil {
		t.Fatalf("count ping task rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("task %d row resurrected after delete+reload interleave", task.Id)
	}
	localping.Default.Run(ctx, task.Id, "node-after", "tcp", localping.Spec{Port: "443"}, "127.0.0.1")
	localping.Default.Wait()
	if got := writes.Load(); got != 0 {
		t.Fatalf("deleted task %d wrote %d record(s) after delete+reload, want 0", task.Id, got)
	}
}

// TestMain pins a single shared in-memory database. dbcore.Initialize runs
// once per process, so per-test DSN assignment would be ignored and leave the
// tests fighting over whichever DSN happened to win.
func TestMain(m *testing.M) {

	flags.DatabaseType = flags.DatabaseTypeSQLite

	flags.DatabaseFile = "file:komari_tasks_test?mode=memory&cache=shared"

	db := dbcore.GetDBInstance()

	if sqlDB, err := db.DB(); err == nil {

		sqlDB.SetMaxOpenConns(1)

	}

	os.Exit(m.Run())

}

// resetTaskTables clears the shared in-memory tables so repeated runs and
// shuffled execution start from a clean slate.
func resetTaskTables(t *testing.T) {

	t.Helper()

	db := dbcore.GetDBInstance()

	for _, model := range []any{&models.Task{}, &models.TaskResult{}, &models.PingTask{}} {

		if err := db.Where("1 = 1").Delete(model).Error; err != nil {

			t.Fatalf("reset %T: %v", model, err)

		}

	}

	t.Cleanup(func() {

		db := dbcore.GetDBInstance()

		for _, model := range []any{&models.Task{}, &models.TaskResult{}, &models.PingTask{}} {

			_ = db.Where("1 = 1").Delete(model).Error

		}

	})

}
