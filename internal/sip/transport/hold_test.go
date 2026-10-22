package transport

import (
	"net"
	"strings"
	"testing"
	"time"
)

// A held response stops being held once its SendResponse begins: from then
// on the send's own count stands for it, so a response that waits for room
// in a peer's full queue costs Flush the stall, as any waiting sender does,
// not the whole deadline (#469).
func TestAHeldResponseIsReleasedWhenItsSendBegins(t *testing.T) {
	server, peer := net.Pipe() // the peer never reads
	t.Cleanup(func() { peer.Close() })
	tr, _ := newTransport(t, Config{Dialer: pipeDialer{noWriteDeadline{server}}, SendQueueBytes: 64 << 10, WriteTimeout: time.Hour})
	listen(t, tr, ListenerConfig{Network: TCP})
	first := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKfill")
	first.Body = []byte(strings.Repeat("x", 4*writeChunk))
	if _, err := tr.SendRequest(first, pipeDst); err != nil {
		t.Fatal(err)
	}
	f := tr.flows.peer(reuseKey{network: TCP, remote: pipeDst.Addr})
	if f == nil {
		t.Fatal("no flow")
	}
	res := respond(t, newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKheld"), 200)
	res.Body = []byte(strings.Repeat("y", 4*writeChunk))
	release := tr.HoldResponse(res)
	defer release()
	go func() { _ = tr.SendResponse(res, Source{Network: TCP, Flow: f.id}) }()
	eventually(t, "the response to wait for room", func() bool {
		f.q.mu.Lock()
		defer f.q.mu.Unlock()
		return f.q.waiting > 0
	})
	tr.sendsMu.Lock()
	_, held := tr.holds[res]
	tr.sendsMu.Unlock()
	if held {
		t.Fatal("the response is still held while its send waits for room")
	}
	done := make(chan struct{})
	go func() {
		tr.Flush(time.Now().Add(time.Hour), 100*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second): // a hang guard; the deadline is an hour
		t.Fatal("Flush still waits on the hold of a response whose send began")
	}
}

// Until then, Flush waits for it as for a send under way.
func TestFlushWaitsForAHeldResponse(t *testing.T) {
	tr, _ := newTransport(t, Config{})
	res := respond(t, newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKheld"), 200)
	release := tr.HoldResponse(res)
	done := make(chan struct{})
	go func() {
		tr.Flush(time.Now().Add(time.Hour), 10*time.Millisecond)
		close(done)
	}()
	// A lower bound only: Flush gives up on nothing else here.
	select {
	case <-done:
		t.Fatal("Flush returned while a response was held")
	case <-time.After(200 * time.Millisecond):
	}
	release()
	tr.sendsMu.Lock()
	left := len(tr.sends)
	tr.sendsMu.Unlock()
	if left != 0 {
		t.Fatalf("%d sends still counted once the hold was released", left)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Flush did not return once the hold was released")
	}
}
