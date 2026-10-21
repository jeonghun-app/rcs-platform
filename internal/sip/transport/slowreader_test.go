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
// this with the default WriteTimeout; 5 s keeps the test shorter while leaving a
// wide margin over the 50 ms the reader sleeps.
//
// On a loaded host the reader itself can be kept from reading for longer than
// WriteTimeout, and then cutting the connection is right (#266, as #155 for
// the test below). The writer cuts only a write of one writeChunk that made no
// headway for WriteTimeout, which needs a full receive buffer that the peer
// took at most two 16 KiB reads from in that time: somewhere it went a third
// of WriteTimeout without reading. So a cut fails the test only if the peer
// never paused for a quarter of WriteTimeout; after a longer pause it is the
// host's doing, and the run is tried again.
func TestSlowButReadingPeerKeepsItsConnectionUnderABurst(t *testing.T) {
	const writeTimeout = 5 * time.Second
	for attempt := 1; attempt <= 3; attempt++ {
		r := slowReaderBurst(t, writeTimeout)
		if !r.cut {
			if r.sent == 0 || uint64(r.failed) != r.stats.QueueWaitTimeouts {
				t.Errorf("sent %d, failed %d, QueueWaitTimeouts %d", r.sent, r.failed, r.stats.QueueWaitTimeouts)
			}
			return
		}
		if r.longestPause < writeTimeout/4 {
			t.Fatalf("the peer never paused more than %v between reads, yet its connection was closed (failed sends=%d; QueueOverflows=%d Dialed=%d OpenOutbound=%d)",
				r.longestPause, r.failed, r.stats.QueueOverflows, r.stats.Dialed, r.stats.OpenOutbound)
		}
		t.Logf("attempt %d: the peer paused %v between reads; the host kept it from reading, trying again", attempt, r.longestPause)
	}
	t.Skip("the host kept the peer from reading in every attempt")
}

type burstResult struct {
	// cut reports that the connection to the peer was closed, or that a
	// second one was dialed.
	cut          bool
	sent, failed int64
	stats        Stats
	// longestPause is the longest the peer went between two reads, until it
	// saw the cut.
	longestPause time.Duration
}

func slowReaderBurst(t *testing.T, writeTimeout time.Duration) burstResult {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pauses := make(chan time.Duration, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			pauses <- 0
			return
		}
		defer c.Close()
		buf := make([]byte, 16<<10)
		var longest time.Duration
		last := time.Now()
		for {
			_, err := c.Read(buf)
			longest = max(longest, time.Since(last))
			last = time.Now()
			if err != nil {
				pauses <- longest
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	tr, _ := newTransport(t, Config{WriteTimeout: writeTimeout})
	dst := Destination{Network: TCP, Addr: addrPortOf(ln.Addr())}
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
				if _, err := tr.SendRequest(req, dst); err != nil {
					failed.Add(1)
				} else {
					sent.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	r := burstResult{sent: sent.Load(), failed: failed.Load(), stats: tr.Stats()}
	r.cut = r.stats.QueueOverflows > 0 || r.stats.Dialed != 1 || r.stats.OpenOutbound != 1
	if r.cut {
		// The first connection is closed, so the peer sees the cut.
		select {
		case r.longestPause = <-pauses:
		case <-time.After(waitFor + writeTimeout):
			t.Fatal("the peer never saw its connection end")
		}
	}
	return r
}

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
