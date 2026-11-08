package localping

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/metricstore"
	logger "github.com/komari-monitor/komari/utils/log"
)

// MaxConcurrentLocalProbes 全局本机正向探测并发上限；满载时跳过本次 tick，
// 不堆积协程。
const MaxConcurrentLocalProbes = 32

// Runner 本机正向探测执行器：按 (taskID, clientUUID) 原子去重 + 全局非阻塞
// 信号量限流的并行扇出。探测 goroutine 统一 recover 记日志，绝不让 panic
// 扩散到调度器。
type Runner struct {
	// MaxConcurrent 全局并发上限，<=0 时用 MaxConcurrentLocalProbes。
	// 信号量容量由 ensure() 在首次调用时一次性初始化，后续修改本字段
	// 不影响已建好的并发槽。
	MaxConcurrent int

	// ValidateIP 校验自报 IP，nil 时用 ValidatePublicProbeIP（测试可注入
	// 允许 loopback 的校验器）。
	ValidateIP func(raw string, wantV6 bool) (netip.Addr, error)
	// Probe 执行单次探测，nil 时用包内默认实现。
	Probe func(ctx context.Context, pingType string, spec Spec, addr netip.Addr) int
	// WriteRecord 落盘探测结果，nil 时用 metricstore.WritePingRecord。
	WriteRecord func(ctx context.Context, rec models.PingRecord) error

	once      sync.Once
	semaphore chan struct{}
	inflight  sync.Map // (taskID, clientUUID) -> struct{}
	wg        sync.WaitGroup

	// taskMu 串行化在途探测注册、CancelTasks 取消、写前检查与
	// WriteRecord 临界区；删除任务时 CancelTasks 持锁到在途写入结束。
	taskMu sync.Mutex
	// taskEpoch 单调世代号：CancelTasks 只增不减，旧世代残余协程即使未来
	// taskDeleted 解除也因 epoch 不匹配绝不能写点。
	taskEpoch   map[uint]uint64
	taskDeleted map[uint]struct{}
	// taskDeleting 在途删除引用计数：CancelTasks 进入时 +1，返回的 finish
	// 无论提交与否都会 -1。计数 >0 表示该 taskID 正处于「已取消在途探测、
	// 尚未落库提交」的窗口，bindProbe/write 一律拒绝；finish(false) 归零
	// 后任务恢复可探测（删除早退、任务行仍在库里）。
	taskDeleting map[uint]int
	// inflightCancel 按在途键注册本次调用的探测 cancel，供 CancelTasks
	// 精确取消；不缓存跨调用的任务级 context，杜绝父 ctx 别名污染。
	inflightCancel map[uint]map[string]context.CancelFunc
}

// Default 是调度器共用的全局执行器。
var Default = &Runner{}

// Run 启动一次针对单个客户端的本机正向探测（立即返回，内部 goroutine 执行）。
// 同一 (taskID, clientUUID) 仍在途时直接跳过；并发槽满载时同样跳过。
// rawIP 非法时绝不发网络包，ctx 未取消时写入 Value=-1 便于管理员发现节点
// 自报 IP 无效。
func (r *Runner) Run(ctx context.Context, taskID uint, clientUUID, pingType string, spec Spec, rawIP string) {
	r.ensure()

	key := fmt.Sprintf("%d:%s", taskID, clientUUID)
	if _, loaded := r.inflight.LoadOrStore(key, struct{}{}); loaded {
		return // 上一轮同键探测仍在途，跳过本次 tick。
	}
	select {
	case r.semaphore <- struct{}{}:
	default:
		r.inflight.Delete(key)
		return // 并发槽满载，跳过不堆积协程。
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			if rec := recover(); rec != nil {
				logger.Errorf("localping", "local probe panic (task=%d client=%s): %v", taskID, clientUUID, rec)
			}
		}()
		defer r.inflight.Delete(key)
		defer func() { <-r.semaphore }()

		probeCtx, cancel, epoch, ok := r.bindProbe(ctx, taskID, key)
		if !ok {
			return // 任务已删除或父 ctx 已取消，绝不发包也不写点。
		}
		defer cancel() // goroutine 退出时必然释放父 context 的子节点。
		defer r.unbindProbe(taskID, key)

		val := -1
		addr, err := r.validateIP(rawIP, spec.V6)
		switch {
		case err != nil:
			logger.Warnf("localping", "skip local probe (task=%d client=%s): invalid reported IP %q: %v",
				taskID, clientUUID, rawIP, err)
		case probeCtx.Err() != nil:
			// 父 ctx 已取消或任务已被删除：不发包也不写点。
		default:
			val = r.probe(probeCtx, pingType, spec, addr)
		}
		if probeCtx.Err() != nil {
			return // 调度已失效或任务已删除，丢弃结果，绝不写孤儿点。
		}
		r.write(probeCtx, taskID, epoch, models.PingRecord{
			Client: clientUUID,
			TaskId: taskID,
			Value:  val,
			Time:   time.Now().UTC(),
		})
	}()
}

// bindProbe 为探测 goroutine 派生仅属于本次调用的可取消 context 并注册到
// 在途表：每次 Run 独立继承调用方传入的父 ctx（同一 taskID 绝不在多个父
// ctx 间缓存别名），CancelTasks 可按 taskID 精确取消全部在途探测。父 ctx
// 已取消或任务已被 CancelTasks 标记删除时返回 ok=false，调用方须放弃本次
// 探测。
func (r *Runner) bindProbe(parent context.Context, taskID uint, key string) (context.Context, context.CancelFunc, uint64, bool) {
	r.ensure()
	r.taskMu.Lock()
	defer r.taskMu.Unlock()
	if parent.Err() != nil {
		return nil, nil, 0, false
	}
	if r.taskDeleting[taskID] > 0 {
		return nil, nil, 0, false
	}
	if _, deleted := r.taskDeleted[taskID]; deleted {
		return nil, nil, 0, false
	}
	epoch := r.taskEpoch[taskID]
	probeCtx, cancel := context.WithCancel(parent)
	if inner, ok := r.inflightCancel[taskID]; ok {
		inner[key] = cancel
	} else {
		r.inflightCancel[taskID] = map[string]context.CancelFunc{key: cancel}
	}
	return probeCtx, cancel, epoch, true
}

// unbindProbe 摘除本 goroutine 在 bindProbe 注册的在途 cancel（外层 map 空
// 时删 taskID 键）。与退出路径的 defer cancel() 配套，保证零 context 泄
// 漏、零注册残留。
func (r *Runner) unbindProbe(taskID uint, key string) {
	r.taskMu.Lock()
	defer r.taskMu.Unlock()
	if inner, ok := r.inflightCancel[taskID]; ok {
		delete(inner, key)
		if len(inner) == 0 {
			delete(r.inflightCancel, taskID)
		}
	}
}

// CancelTasks 删除任务前的同步栅栏：推进 ids 的世代号并递增在途删除引用
// 计数（bindProbe/write 同步拒绝），取消该批任务全部在途探测的 context，
// 并持锁到已进入 WriteRecord 临界区的在途写入完成才返回。入参 ids 先去重，
// 保证同批次重复 ID 不会使引用计数失衡。
//
// 返回的 finish 由 sync.Once 保护，删除流程结束后必须恰好调用一次：
//   - finish(true)：删除提交，写入 taskDeleted 墓碑并释放引用计数，后续
//     Run 永久跳过（直到 AllowTasks/主键复用解除）。
//   - finish(false)：删除早退，仅递减引用计数让任务恢复可探测；绝不触碰
//     taskDeleted，以免并发重复删除早退时误清前一次已提交的墓碑。
func (r *Runner) CancelTasks(ids []uint) (finish func(committed bool)) {
	r.ensure()
	unique := make([]uint, 0, len(ids))
	seen := make(map[uint]struct{}, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}

	r.taskMu.Lock()
	for _, id := range unique {
		// 世代号单调递增、永不回退：旧世代残余协程即使未来 taskDeleted
		// 解除（如 SQLite 主键被新任务复用）也因 epoch 不匹配绝不能写点。
		r.taskEpoch[id]++
		r.taskDeleting[id]++
		for _, cancel := range r.inflightCancel[id] {
			cancel()
		}
		delete(r.inflightCancel, id)
	}
	r.taskMu.Unlock()

	var once sync.Once
	return func(committed bool) {
		once.Do(func() {
			r.taskMu.Lock()
			defer r.taskMu.Unlock()
			for _, id := range unique {
				r.taskDeleting[id]--
				if r.taskDeleting[id] <= 0 {
					delete(r.taskDeleting, id)
				}
				if committed {
					r.taskDeleted[id] = struct{}{}
				}
			}
			// taskEpoch 保持递增不回退。
		})
	}
}

// AllowTasks 解除 ids 的删除标记：用于任务行确认存在之后放行该 taskID 的
// 后续探测（AddPingTask 新建、ReloadPingSchedule 全量重载）。只清除
// taskDeleted 墓碑，绝不修改 taskDeleting 引用计数——正处于删除提交流程
// 中的任务不会被并发 AllowTasks 提前解封。不重置 taskEpoch——删除前已派生
// 的旧世代协程仍因 epoch 不匹配被丢弃，杜绝 SQLite 主键复用后旧协程写孤
// 儿点。
func (r *Runner) AllowTasks(ids []uint) {
	r.ensure()
	r.taskMu.Lock()
	defer r.taskMu.Unlock()
	for _, id := range ids {
		delete(r.taskDeleted, id)
	}
}

// Wait 等待全部在途探测结束（测试与关闭流程使用）。
func (r *Runner) Wait() {
	r.ensure()
	r.wg.Wait()
}

func (r *Runner) ensure() {
	r.once.Do(func() {
		if r.MaxConcurrent <= 0 {
			r.MaxConcurrent = MaxConcurrentLocalProbes
		}
		r.semaphore = make(chan struct{}, r.MaxConcurrent)
		r.taskEpoch = make(map[uint]uint64)
		r.taskDeleted = make(map[uint]struct{})
		r.taskDeleting = make(map[uint]int)
		r.inflightCancel = make(map[uint]map[string]context.CancelFunc)
	})
}

func (r *Runner) validateIP(raw string, v6 bool) (netip.Addr, error) {
	r.ensure()
	// 钩子为 nil 时回退生产默认实现：测试 Cleanup 把字段恢复成 nil 后
	// 后续调用仍走公网强校验，不会因 ensure() 一次性回写而永久继承
	// 被注入的放宽实现。
	validate := r.ValidateIP
	if validate == nil {
		validate = ValidatePublicProbeIP
	}
	return validate(raw, v6)
}

func (r *Runner) probe(ctx context.Context, pingType string, spec Spec, addr netip.Addr) int {
	r.ensure()
	fn := r.Probe
	if fn == nil {
		fn = probe
	}
	return fn(ctx, pingType, spec, addr)
}

func (r *Runner) write(probeCtx context.Context, taskID uint, epoch uint64, rec models.PingRecord) {
	r.ensure()
	// 持 taskMu 串行化写前检查与入队：CancelTasks 返回后绝不写被删任务，
	// 且已进入本临界区的写入必在 CancelTasks 返回前完成入队。持 taskMu
	// 调用 WriteRecord 用于保证 CancelTasks 排空在途写入——无 batcher
	// 直写时锁持有时间上界为底层 store 的写锁，不构成死锁（WriteRecord
	// 不回头取 taskMu）。
	r.taskMu.Lock()
	defer r.taskMu.Unlock()
	if r.taskDeleting[taskID] > 0 {
		return // 删除进行中（未提交）：拒绝写入，等待 finish 决定去留。
	}
	if _, deleted := r.taskDeleted[taskID]; deleted {
		return
	}
	if r.taskEpoch[taskID] != epoch {
		return // 任务世代已推进（删除/重建），丢弃旧世代结果。
	}
	if probeCtx.Err() != nil {
		return // 本 goroutine 的探测 ctx 已取消（父 ctx/删除），丢弃结果。
	}
	writeRecord := r.WriteRecord
	if writeRecord == nil {
		writeRecord = metricstore.WritePingRecord
	}
	if err := writeRecord(context.Background(), rec); err != nil {
		logger.Warnf("localping", "write local ping record failed (task=%d client=%s): %v",
			rec.TaskId, rec.Client, err)
	}
}
