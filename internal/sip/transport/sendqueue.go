package transport

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SendOption changes how a message is sent.
type SendOption int

// NoWait makes a send never wait for room in a stream connection's send queue.
// It is for messages sent from the goroutine that reads a connection, such as a
// 100 Trying, the ACK for a failure response or the answer to a retransmission:
// that goroutine must not wait for its peer, which may itself be waiting for us
// to read. Such a message may use a reserve beyond SendQueueBytes, so it is not
// refused merely because a burst filled the queue; a peer that does not read
// through the reserve too loses its connection.
const NoWait SendOption = 1

func noWait(opts []SendOption) bool {
	for _, o := range opts {
		if o == NoWait {
			return true
		}
	}
	return false
}

// sendQueue holds the bytes waiting for a stream flow's writer goroutine.
//
// Every write to a stream goes through one, so a write never runs on a caller's
// goroutine. A caller that originates a message waits, for at most WriteTimeout,
// while the queue is over its limit, so a burst is paced by the peer. If no room
// comes, only that send fails: a peer can be reading, just slower than the burst
// arrives, and closing its connection would throw away everything already
// queued for it. A peer that stops reading altogether is closed by the writer,
// whose write then misses its deadline. A NoWait caller never waits; a NoWait
// message that does not fit even in the reserve closes the connection, since
// the goroutine reading it has no other way to make progress.
type sendQueue struct {
	budget *queueBudget

	mu sync.Mutex
	// bufs are the messages not yet taken by the writer; queued counts them
	// and the batch the writer is writing, against limit.
	bufs   [][]byte
	queued int
	limit  int
	closed bool
	// progress is when the queue last went from empty to holding output, or
	// its writer last wrote a chunk, in Unix nanoseconds, which tells a stalled
	// peer from a slow one.
	progress atomic.Int64
	// wake tells the writer there is work; room tells a waiting sender that the
	// writer has made progress; done is closed with the queue.
	wake chan struct{}
	room chan struct{}
	done chan struct{}
}

func newSendQueue(limit int, budget *queueBudget) *sendQueue {
	q := &sendQueue{budget: budget, limit: limit, wake: make(chan struct{}, 1), room: make(chan struct{}, 1), done: make(chan struct{})}
	q.progress.Store(time.Now().UnixNano())
	return q
}

// queueBudget is the output every send queue of a transport may hold together
// (Config.MaxQueuedBytes). Per-connection limits keep one peer from using much;
// the budget keeps all of them together inside the task's memory.
type queueBudget struct {
	used atomic.Int64
	max  int64
}

func (b *queueBudget) reserve(n int) bool {
	for {
		u := b.used.Load()
		if u+int64(n) > b.max {
			return false
		}
		if b.used.CompareAndSwap(u, u+int64(n)) {
			return true
		}
	}
}

func (b *queueBudget) release(n int) { b.used.Add(-int64(n)) }

type pushResult int

const (
	pushed       pushResult = iota
	queueFull               // over this connection's limit, or its reserve for NoWait
	waitTimedOut            // no room came within the timeout
	overBudget              // over the transport's budget
	queueGone               // the connection has closed
)

// tryPush queues b if it fits within max and the transport's budget. A message
// is always accepted into an empty queue, budget permitting, so a limit below
// the largest message cannot make a connection unusable.
func (q *sendQueue) tryPush(b []byte, max int) pushResult {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return queueGone
	}
	if q.queued > 0 && q.queued+len(b) > max {
		return queueFull
	}
	if !q.budget.reserve(len(b)) {
		return overBudget
	}
	if q.queued == 0 {
		// A stall is measured from when output became pending, so a queue that
		// was merely idle, or whose writer has yet to run, does not look stalled.
		q.progress.Store(time.Now().UnixNano())
	}
	q.bufs = append(q.bufs, b)
	q.queued += len(b)
	notify(q.wake)
	if q.queued < q.limit {
		// Let the next waiting sender look too.
		notify(q.room)
	}
	return pushed
}

// push queues b. A NoWait push may fill the queue to twice its limit; another
// push waits until deadline for the queue to drop below its limit. Neither
// waits for the transport's budget.
func (q *sendQueue) push(b []byte, wait bool, deadline time.Time) pushResult {
	if !wait {
		return q.tryPush(b, 2*q.limit)
	}
	var expired <-chan time.Time
	for {
		if r := q.tryPush(b, q.limit); r != queueFull {
			return r
		}
		if expired == nil {
			t := time.NewTimer(time.Until(deadline))
			defer t.Stop()
			expired = t.C
		}
		select {
		case <-q.room:
		case <-q.done:
			return queueGone
		case <-expired:
			return waitTimedOut
		}
	}
}

func notify(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// take returns everything queued; closed reports that the writer should stop.
func (q *sendQueue) take() (bufs [][]byte, closed bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	bufs, q.bufs = q.bufs, nil
	return bufs, q.closed
}

// stall returns what the queue holds and how long its writer has gone without
// progress.
func (q *sendQueue) stall(now time.Time) (queued int, idle time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.queued, now.Sub(time.Unix(0, q.progress.Load()))
}

// written releases n bytes the writer has sent.
func (q *sendQueue) written(n int) {
	q.mu.Lock()
	if !q.closed {
		q.queued -= n
		q.budget.release(n)
	}
	q.mu.Unlock()
	notify(q.room)
}

// size returns the bytes the queue holds, the batch being written included.
func (q *sendQueue) size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.queued
}

// close drops what is queued, returns its bytes to the budget, stops the writer
// and releases waiting senders.
func (q *sendQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	q.bufs = nil
	q.budget.release(q.queued)
	q.queued = 0
	close(q.done)
	notify(q.wake)
}

// writeChunk is how much the writer hands the kernel at a time.
const writeChunk = 32 << 10

// socketSendBuffer caps the kernel's send buffer of every stream socket. Linux
// grows it to several MiB by itself, which is memory the queue budget cannot
// see, and reports a full socket writable again only once a large part of it
// has drained; with a slow reader that wait alone could exceed WriteTimeout. A
// small buffer keeps waiting output in the accounted queue and makes the write
// deadline mean "no progress". 128 KiB per round trip is far more than SIP needs
// inside a VPC or across the internet.
const socketSendBuffer = 128 << 10

// capSendBuffer applies socketSendBuffer to a TCP connection; other connections,
// such as a test's pipe, are left alone.
func capSendBuffer(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetWriteBuffer(socketSendBuffer)
	}
}

// writeAll writes b in chunks, each with its own deadline, so WriteTimeout
// measures how long the peer goes without taking any data rather than how long a
// whole message takes. A peer reading slowly but steadily keeps its connection;
// one that stops reading loses it after WriteTimeout.
func (t *Transport) writeAll(f *flow, b []byte) error {
	for len(b) > 0 {
		n := min(len(b), writeChunk)
		if err := f.conn.SetWriteDeadline(time.Now().Add(t.cfg.WriteTimeout)); err != nil {
			return err
		}
		if _, err := f.conn.Write(b[:n]); err != nil {
			return err
		}
		f.q.progress.Store(time.Now().UnixNano())
		b = b[n:]
	}
	return nil
}

// writeLoop writes a stream flow's queue until the flow closes. A write that
// fails, or makes no progress for WriteTimeout, closes the connection, since part
// of a message may have been sent and the peer could not find the start of the
// next.
func (t *Transport) writeLoop(f *flow) {
	defer t.wg.Done()
	for range f.q.wake {
		bufs, closed := f.q.take()
		if closed {
			return
		}
		for _, b := range bufs {
			if err := t.writeAll(f, b); err != nil {
				if !f.closed.Load() {
					t.stats.writeErrors.Add(1)
				}
				t.closeFlow(f)
				return
			}
			f.q.written(len(b))
		}
	}
}
