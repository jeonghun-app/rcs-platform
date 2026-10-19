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
// wide margin over the 50 ms the reader sleeps, even on a loaded host.
func TestSlowButReadingPeerKeepsItsConnectionUnderABurst(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 16<<10)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	tr, _ := newTransport(t, Config{WriteTimeout: 5 * time.Second})
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
	s := tr.Stats()
	if s.QueueOverflows > 0 || s.Dialed != 1 || s.OpenOutbound != 1 {
		t.Errorf("failed sends=%d; QueueOverflows=%d Dialed=%d OpenOutbound=%d: the connection to a reading peer was closed",
			failed.Load(), s.QueueOverflows, s.Dialed, s.OpenOutbound)
	}
	if sent.Load() == 0 || uint64(failed.Load()) != s.QueueWaitTimeouts {
		t.Errorf("sent %d, failed %d, QueueWaitTimeouts %d", sent.Load(), failed.Load(), s.QueueWaitTimeouts)
	}
}

func TestLargeMessageToASteadyReaderIsNotCutByTheWriteTimeout(t *testing.T) {
	// The whole message takes about 800 ms to drain, longer than WriteTimeout,
	// but the peer takes 32 KiB every 100 ms, so the writer never goes
	// WriteTimeout without progress.
	tr, peer := pipeTransport(t, Config{WriteTimeout: 300 * time.Millisecond})
	got := make(chan int, 1)
	go func() {
		buf := make([]byte, writeChunk)
		total := 0
		for {
			n, err := peer.Read(buf)
			total += n
			if err != nil || total >= 256<<10 {
				got <- total
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKbig")
	req.Body = make([]byte, 256<<10)
	if _, err := tr.SendRequest(req, pipeDst); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-got:
		if n < 256<<10 {
			t.Fatalf("peer read %d bytes", n)
		}
	case <-time.After(waitFor):
		t.Fatal("the message never arrived")
	}
	if s := tr.Stats(); s.WriteErrors != 0 || s.OpenOutbound != 1 {
		t.Fatalf("stats = %+v", s)
	}
}
