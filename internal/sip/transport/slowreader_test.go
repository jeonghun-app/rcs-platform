package transport

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// QA regression (PR #35 re-verification, N1): a core peer that keeps reading
// (16 KiB every 50 ms) while 128 senders offer a burst far larger than the send
// queue. Sends that find no room in time may fail, but the connection to a peer
// that is reading must stay up, with everything already queued for it. QA ran
// this with the default WriteTimeout; 5 s keeps the test shorter.
//
// The peer is a pipe behind a connection that ignores write deadlines, so a
// loaded host that slows the reader cannot make the writer's deadline pass
// (#266): only the transport closing the connection for another reason can
// fail the test. The deadline itself is TestWriteThatTimesOutClosesTheConnection's.
func TestSlowButReadingPeerKeepsItsConnectionUnderABurst(t *testing.T) {
	server, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	go func() {
		buf := make([]byte, 16<<10)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	tr, _ := newTransport(t, Config{Dialer: pipeDialer{noWriteDeadline{server}}, WriteTimeout: 5 * time.Second})
	listen(t, tr, ListenerConfig{Network: TCP})
	body := []byte(strings.Repeat("x", 64<<10))
	var failed, sent atomic.Int64
	var wg sync.WaitGroup
	for g := range 128 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 4 {
				req := newRequest(t, "MESSAGE", fmt.Sprintf("SIP/2.0/TCP p.invalid;branch=z9hG4bKb%d-%d", g, i))
				req.Body = body
				if _, err := tr.SendRequest(req, pipeDst); err != nil {
					failed.Add(1)
				} else {
					sent.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	s := tr.Stats()
	if s.QueueOverflows > 0 || s.Dialed != 1 || s.OpenOutbound != 1 {
		t.Errorf("failed sends=%d; QueueOverflows=%d Dialed=%d OpenOutbound=%d: the connection to a reading peer was closed",
			failed.Load(), s.QueueOverflows, s.Dialed, s.OpenOutbound)
	}
	if sent.Load() == 0 || uint64(failed.Load()) != s.QueueWaitTimeouts {
		t.Errorf("sent %d, failed %d, QueueWaitTimeouts %d", sent.Load(), failed.Load(), s.QueueWaitTimeouts)
	}
}

// noWriteDeadline is a connection whose writes never time out, as to a peer
// that always reads in time.
type noWriteDeadline struct{ net.Conn }

func (noWriteDeadline) SetWriteDeadline(time.Time) error { return nil }

func TestLargeMessageToASteadyReaderIsNotCutByTheWriteTimeout(t *testing.T) {
	// The whole message takes about 1.6 s to drain, longer than WriteTimeout,
	// but the peer takes 32 KiB every 100 ms, so the writer makes progress
	// ten times per WriteTimeout.
	//
	// On a loaded host the peer's 100 ms can stretch past WriteTimeout, and
	// then cutting the connection is right (#155). So a cut fails the test
	// only if it came sooner than WriteTimeout after the peer's last read;
	// a cut after a longer pause is the host's doing, and the run is tried
	// again.
	const writeTimeout = time.Second
	for attempt := 1; attempt <= 5; attempt++ {
		read, pause := steadyReaderRun(t, writeTimeout)
		switch {
		case read >= 512<<10:
			return
		case pause < writeTimeout:
			t.Fatalf("peer read %d bytes; the connection was cut %v after the peer's last read, within WriteTimeout %v", read, pause, writeTimeout)
		}
		t.Logf("attempt %d: the peer paused %v, past WriteTimeout; trying again", attempt, pause)
	}
	t.Skip("the host kept the peer from reading for longer than WriteTimeout in every attempt")
}

// steadyReaderRun sends a 512 KiB message to a peer that reads 32 KiB every
// 100 ms, and returns how much it read and, if it was cut off, how long
// after its last read the cut came.
func steadyReaderRun(t *testing.T, writeTimeout time.Duration) (read int, pause time.Duration) {
	t.Helper()
	tr, peer := pipeTransport(t, Config{WriteTimeout: writeTimeout})
	type result struct {
		n     int
		pause time.Duration
	}
	got := make(chan result, 1)
	// lastRead is when the peer last took bytes, for the wait below.
	var lastRead atomic.Int64
	lastRead.Store(time.Now().UnixNano())
	// last, from which the pause before a cut is counted, is never later
	// than the moment the writer set the deadline that cut it: first the
	// start, before anything is sent, then the call of each Read that took
	// a chunk. The peer's buffer is writeChunk, so one Read takes a whole
	// Write, and net.Pipe does not let the Write return, and the writer set
	// the next chunk's deadline, before that Read has taken it.
	start := time.Now()
	go func() {
		buf := make([]byte, writeChunk)
		total, last := 0, start
		for {
			before := time.Now()
			n, err := peer.Read(buf)
			total += n
			if err != nil {
				got <- result{total, time.Since(last)}
				return
			}
			last = before
			lastRead.Store(time.Now().UnixNano())
			if total >= 512<<10 {
				got <- result{total, 0}
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKbig")
	req.Body = make([]byte, 512<<10)
	if _, err := tr.SendRequest(req, pipeDst); err != nil {
		t.Fatal(err)
	}
	// The peer ends either way, by reading everything or by being cut off,
	// so the wait is on progress, not on the whole message: a loaded host
	// can take longer than any fixed bound to drain it (#155). Only a writer
	// that neither writes nor gives up keeps the peer waiting.
	for {
		select {
		case r := <-got:
			if r.n >= 512<<10 {
				if s := tr.Stats(); s.WriteErrors != 0 || s.OpenOutbound != 1 {
					t.Fatalf("stats = %+v", s)
				}
			}
			return r.n, r.pause
		case <-time.After(100 * time.Millisecond):
			if time.Since(time.Unix(0, lastRead.Load())) > waitFor+writeTimeout {
				t.Fatal("the writer neither wrote nor gave up")
			}
		}
	}
}

// Flush waits for the output a connection had queued when it was called,
// however long it takes a peer that keeps reading; gives up on a writer
// that makes no progress for its stall time; and does not wait for output
// queued after it (QA of #366).
func TestFlushWaitsForQueuedOutputUnlessTheWriterStalls(t *testing.T) {
	for _, tc := range []struct {
		name string
		// stuck holds the peer after the first chunk; paused holds it until
		// Flush starts; busy keeps sending while Flush runs.
		stuck, paused, busy bool
	}{
		{name: "a peer that reads"},
		{name: "a peer that stops reading", stuck: true},
		{name: "a peer that reads, with output queued meanwhile", busy: true},
		// Stuck for longer than the stall time before Flush, reading again
		// once it starts: the stall time counts from the start of Flush.
		{name: "a peer that reads again as Flush starts", paused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, peer := net.Pipe()
			held, resume := make(chan struct{}), make(chan struct{})
			t.Cleanup(func() { close(held); peer.Close() })
			var read atomic.Int64
			go func() {
				buf := make([]byte, writeChunk)
				for {
					n, err := peer.Read(buf)
					if read.Add(int64(n)) >= writeChunk && tc.stuck {
						<-held // hold the rest back until the test ends
						return
					}
					if tc.paused {
						<-resume
					}
					if err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
			tr, _ := newTransport(t, Config{Dialer: pipeDialer{noWriteDeadline{server}}})
			listen(t, tr, ListenerConfig{Network: TCP})
			req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKflush")
			req.Body = []byte(strings.Repeat("x", 8*writeChunk))
			if _, err := tr.SendRequest(req, pipeDst); err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			defer close(stop)
			if tc.busy {
				go func() {
					for i := 0; ; i++ {
						select {
						case <-stop:
							return
						default:
						}
						more := newRequest(t, "OPTIONS", fmt.Sprintf("SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKmore%d", i))
						if _, err := tr.SendRequest(more, pipeDst); err != nil {
							return
						}
					}
				}()
			}
			// Long enough that a loaded host cannot make a reading peer look
			// stalled; short for the one that has stopped.
			stall := 10 * time.Second
			switch {
			case tc.stuck:
				stall = 300 * time.Millisecond
			case tc.paused:
				stall = time.Second
				eventually(t, "the first chunk to be read", func() bool { return read.Load() >= writeChunk })
				time.Sleep(stall + stall/2)
			}
			done := make(chan struct{})
			go func() {
				if tc.paused {
					close(resume)
				}
				tr.Flush(time.Now().Add(time.Hour), stall)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("Flush did not return")
			}
			if got := read.Load(); tc.stuck == (got >= int64(len(req.Body))) {
				t.Fatalf("the peer read %d bytes of the %d-byte body when Flush returned", got, len(req.Body))
			}
		})
	}
}
