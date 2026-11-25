package connection

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ConnInfo describes one WebSocket connection passed to interceptor
// callbacks. ID matches the owning SafeConn.
type ConnInfo struct {
	ID         int64
	Path       string
	RemoteIP   string
	UserAgent  string
	ClientUUID string
}

// FrameInterceptor is the optional hook chain around WebSocket connections
// and frames. The provider is wired once at startup by internal/server (the
// plugin manager); a nil interceptor leaves every connection untouched.
type FrameInterceptor interface {
	// OnConnect runs right after the upgrade. A denied connection is closed
	// by the caller; plugins bear the consequences of rejecting endpoints
	// such as /api/rpc2.
	OnConnect(info *ConnInfo) (deny bool, reason string)
	// OnMessage inspects one inbound frame; OnSend one outbound frame. They
	// return the possibly replaced payload and whether the frame is dropped.
	OnMessage(info *ConnInfo, frameType int, data []byte) (newType int, newData []byte, drop bool)
	OnSend(info *ConnInfo, frameType int, data []byte) (newType int, newData []byte, drop bool)
	// OnClose notifies that the connection ended.
	OnClose(info *ConnInfo)
}

// frameInterceptor is the process-wide WebSocket hook provider.
var frameInterceptor FrameInterceptor

// SetFrameInterceptor wires the plugin hook chain into every WebSocket
// connection. It must be called once at startup, before connections arrive.
func SetFrameInterceptor(i FrameInterceptor) { frameInterceptor = i }

// Interceptor returns the process-wide frame interceptor, or nil when no
// provider is wired.
func Interceptor() FrameInterceptor { return frameInterceptor }

// errTooManyDroppedFrames fails the read loop after a plugin dropped too many
// frames in a row, so a connection on a fully filtered endpoint cannot spin
// forever.
var errTooManyDroppedFrames = errors.New("too many frames dropped by plugin hooks")

// maxConsecutiveDroppedFrames bounds the internal re-read loop.
const maxConsecutiveDroppedFrames = 16

// writeDeadline caps every frame write so a half-open peer (sleeping laptop,
// dead reverse proxy) cannot block a writer goroutine forever on a full TCP
// send buffer. controlWriteTimeout bounds how long a control frame may wait
// for a stuck data write before scheduling a force-close of the connection,
// and maxControlWaitCancel bounds that final wait.
const (
	writeDeadline        = 10 * time.Second
	controlWriteTimeout  = 5 * time.Second
	maxControlWaitCancel = 15 * time.Second
)

// SafeConn wraps a websocket connection with a mutex so concurrent writes
// cannot interleave frames, and funnels every frame through the optional
// plugin interceptor when one is attached.
type SafeConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
	ID   int64

	// closeOnce / closeDone decouple Close from the write mutex: closing the
	// underlying socket must never wait for a writer blocked on a half-open
	// connection, otherwise a stuck write would deadlock every cleanup path.
	closeOnce sync.Once
	closeDone chan struct{}

	// hookMu only protects the interceptor attachment, never socket I/O.
	hookMu      sync.Mutex
	interceptor FrameInterceptor
	info        *ConnInfo
}

func NewSafeConn(conn *websocket.Conn) *SafeConn {
	return &SafeConn{
		conn:      conn,
		mu:        sync.Mutex{},
		ID:        time.Now().UnixNano(),
		closeDone: make(chan struct{}),
	}
}

// SetInterceptor attaches the hook provider and the connection identity. It
// must be called before any frame is read or written.
func (sc *SafeConn) SetInterceptor(info *ConnInfo, interceptor FrameInterceptor) {
	sc.hookMu.Lock()
	defer sc.hookMu.Unlock()
	sc.info = info
	sc.interceptor = interceptor
}

func (sc *SafeConn) hookState() (FrameInterceptor, *ConnInfo) {
	sc.hookMu.Lock()
	defer sc.hookMu.Unlock()
	return sc.interceptor, sc.info
}

// readFrame reads one frame and runs the wsMessage hook chain. Frames
// dropped by hooks are transparently skipped, so callers only ever see
// processed frames.
func (sc *SafeConn) readFrame() (int, []byte, error) {
	for dropped := 0; ; {
		messageType, data, err := sc.conn.ReadMessage()
		if err != nil {
			return 0, nil, err
		}
		interceptor, info := sc.hookState()
		if interceptor == nil || info == nil {
			return messageType, data, nil
		}
		newType, newData, drop := interceptor.OnMessage(info, messageType, data)
		if !drop {
			return newType, newData, nil
		}
		if dropped++; dropped >= maxConsecutiveDroppedFrames {
			return 0, nil, errTooManyDroppedFrames
		}
	}
}

// writeFrame runs the wsSend hook chain then writes one frame. A dropped
// frame is silently skipped; a nil interceptor writes through immediately.
// Every write carries writeDeadline so a half-open peer fails fast instead of
// pinning sc.mu (and every control frame / Close behind it) for minutes.
func (sc *SafeConn) writeFrame(messageType int, data []byte) error {
	interceptor, info := sc.hookState()
	newType, newData := messageType, data
	if interceptor != nil && info != nil {
		var drop bool
		newType, newData, drop = interceptor.OnSend(info, messageType, data)
		if drop {
			return nil
		}
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.writeFrameLocked(newType, newData)
}

func (sc *SafeConn) writeFrameLocked(messageType int, data []byte) error {
	deadline := time.Now().Add(writeDeadline)
	if err := sc.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return sc.conn.WriteMessage(messageType, data)
}

func (sc *SafeConn) WriteMessage(messageType int, data []byte) error {
	return sc.writeFrame(messageType, data)
}

// WriteControl sends a control frame. Control frames must not pile up behind
// a data write stuck on a half-open peer: when sc.mu is not acquired within
// controlWriteTimeout the connection is closed underneath the blocked writer
// so both paths fail fast instead of deadlocking session cleanup.
func (sc *SafeConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	interceptor, info := sc.hookState()
	newType, newData := messageType, data
	if interceptor != nil && info != nil {
		var drop bool
		newType, newData, drop = interceptor.OnSend(info, messageType, data)
		if drop {
			return nil
		}
	}
	if !sc.acquireWriteLock(controlWriteTimeout) {
		return errWriteLockTimeout
	}
	defer sc.mu.Unlock()
	if deadline.IsZero() {
		deadline = time.Now().Add(writeDeadline)
	}
	return sc.conn.WriteControl(newType, newData, deadline)
}

var errWriteLockTimeout = errors.New("write lock timeout: closing half-open connection")

// acquireWriteLock takes sc.mu but gives up (closing the connection) after
// timeout so a control writer can always break a stuck data write. Close is
// deferred to maxControlWaitCancel to give a slow-but-alive writer time to
// finish before we pull the socket out from under it. When the caller gives
// up the helper goroutine releases the mutex itself as soon as the stuck
// writer unblocks, so the lock is never orphaned.
func (sc *SafeConn) acquireWriteLock(timeout time.Duration) bool {
	locked := make(chan struct{})
	claimed := make(chan struct{})
	abandon := make(chan struct{})
	go func() {
		sc.mu.Lock()
		close(locked)
		select {
		case <-abandon:
			// The caller gave up before or while the lock was acquired:
			// release it immediately so the mutex is never orphaned.
			sc.mu.Unlock()
		case <-claimed:
			// Ownership transferred to the caller, which unlocks after writing.
		}
	}()
	claim := func() bool {
		close(claimed)
		return true
	}
	giveUp := func() bool {
		close(abandon)
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-locked:
		return claim()
	case <-sc.closeDone:
		select {
		case <-locked:
			return claim()
		default:
			return giveUp()
		}
	case <-timer.C:
		select {
		case <-locked:
			return claim()
		default:
		}
		// A data frame write is stuck past its own deadline: the peer is
		// half-open. Closing the socket is the only way to interrupt the
		// kernel-level write(2) the mutex holder is parked in.
		time.AfterFunc(maxControlWaitCancel, func() { _ = sc.Close() })
		select {
		case <-locked:
			return claim()
		case <-sc.closeDone:
			return giveUp()
		case <-time.After(maxControlWaitCancel + writeDeadline):
			// The stuck writer never woke even after the socket close; give up
			// rather than blocking the cleanup path forever.
			return giveUp()
		}
	}
}

// WriteJSON encodes v then sends it as one text frame through the wsSend
// hook chain.
func (sc *SafeConn) WriteJSON(v interface{}) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return err
	}
	return sc.writeFrame(websocket.TextMessage, buf.Bytes())
}

// Close shuts the underlying socket immediately without waiting for the write
// mutex. A data write blocked in the kernel on a half-open peer must never
// deadlock session cleanup: closing the socket interrupts that write, after
// which the writer releases sc.mu on its own. OnClose runs exactly once.
func (sc *SafeConn) Close() error {
	var err error
	var interceptor FrameInterceptor
	var info *ConnInfo
	sc.closeOnce.Do(func() {
		close(sc.closeDone)
		sc.hookMu.Lock()
		interceptor, info = sc.interceptor, sc.info
		sc.interceptor = nil
		sc.hookMu.Unlock()
		err = sc.conn.Close()
	})
	if interceptor != nil && info != nil {
		interceptor.OnClose(info)
	}
	return err
}

// SetReadLimit caps inbound frame size; see websocket.Conn.SetReadLimit.
func (sc *SafeConn) SetReadLimit(limit int64) {
	sc.conn.SetReadLimit(limit)
}

func (sc *SafeConn) ReadMessage() (int, []byte, error) {
	return sc.readFrame()
}

func (sc *SafeConn) ReadJSON(v interface{}) error {
	_, data, err := sc.readFrame()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (sc *SafeConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

func (sc *SafeConn) SetPingHandler(h func(string) error) {
	sc.conn.SetPingHandler(h)
}

func (sc *SafeConn) SetPongHandler(h func(string) error) {
	sc.conn.SetPongHandler(h)
}

func (sc *SafeConn) GetConn() *websocket.Conn {
	return sc.conn
}

// SetCloseHandler forwards to the underlying connection (used by the
// terminal sessions to clean up on close).
func (sc *SafeConn) SetCloseHandler(h func(code int, text string) error) {
	sc.conn.SetCloseHandler(h)
}
