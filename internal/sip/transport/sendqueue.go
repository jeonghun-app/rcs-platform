package transport

import (
	"sync"
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
// while the queue is over its limit, so a burst is paced by the peer; a NoWait
// caller never waits. A queue that stays full closes its connection: its peer is
// not reading, and cannot slow anyone else down for longer than that.
type sendQueue struct {
	mu sync.Mutex
	// bufs are the messages not yet taken by the writer; queued counts them
	// and the batch the writer is writing, against limit.
	bufs   [][]byte
	queued int
	limit  int
	closed bool
	// wake tells the writer there is work; room tells a waiting sender that the
	// writer has made progress; done is closed with the queue.
	wake chan struct{}
	room chan struct{}
	done chan struct{}
}

func newSendQueue(limit int) *sendQueue {
	return &sendQueue{limit: limit, wake: make(chan struct{}, 1), room: make(chan struct{}, 1), done: make(chan struct{})}
}

// tryPush queues b if it fits within max. A message is always accepted into an
// empty queue, so a limit below the largest message cannot make a connection
// unusable.
func (q *sendQueue) tryPush(b []byte, max int) (ok, closed bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false, true
	}
	if q.queued > 0 && q.queued+len(b) > max {
		return false, false
	}
	q.bufs = append(q.bufs, b)
	q.queued += len(b)
	notify(q.wake)
	if q.queued < q.limit {
		// Let the next waiting sender look too.
		notify(q.room)
	}
	return true, false
}

// push queues b. A NoWait push may fill the queue to twice its limit; another
// push waits up to timeout for the queue to drop below its limit. ok is false
// when it could not; closed reports that the queue was closed meanwhile.
func (q *sendQueue) push(b []byte, wait bool, timeout time.Duration) (ok, closed bool) {
	if !wait {
		return q.tryPush(b, 2*q.limit)
	}
	var deadline <-chan time.Time
	for {
		if ok, closed := q.tryPush(b, q.limit); ok || closed {
			return ok, closed
		}
		if deadline == nil {
			t := time.NewTimer(timeout)
			defer t.Stop()
			deadline = t.C
		}
		select {
		case <-q.room:
		case <-q.done:
			return false, true
		case <-deadline:
			return false, false
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

// written releases n bytes the writer has sent.
func (q *sendQueue) written(n int) {
	q.mu.Lock()
	q.queued -= n
	q.mu.Unlock()
	notify(q.room)
}

// close drops what is queued, stops the writer and releases waiting senders.
func (q *sendQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	q.bufs = nil
	close(q.done)
	notify(q.wake)
}

// writeLoop writes a stream flow's queue until the flow closes. A write that
// fails or misses WriteTimeout closes the connection, since part of a message
// may have been sent and the peer could not find the start of the next.
func (t *Transport) writeLoop(f *flow) {
	defer t.wg.Done()
	for range f.q.wake {
		bufs, closed := f.q.take()
		if closed {
			return
		}
		for _, b := range bufs {
			err := f.conn.SetWriteDeadline(time.Now().Add(t.cfg.WriteTimeout))
			if err == nil {
				_, err = f.conn.Write(b)
			}
			if err != nil {
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
