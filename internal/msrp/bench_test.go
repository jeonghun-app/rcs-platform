package msrp

import (
	"context"
	"net"
	"testing"
)

// benchBinder plays msrp-relay for the benchmark, as testRelay does for
// the tests: it bridges the client's session with one toward rcs-as.
type benchBinder struct {
	tb   testing.TB
	pool *Pool
}

func (r *benchBinder) Bind(_ *Conn, to URI) (*Session, error) {
	a, err := NewSession(SessionConfig{Local: to, Remote: []URI{mustURI(r.tb, clientURI)}})
	if err != nil {
		return nil, err
	}
	b, err := NewSession(SessionConfig{Local: mustURI(r.tb, relayInternalURI), Remote: []URI{mustURI(r.tb, asURI)}})
	if err != nil {
		return nil, err
	}
	if err := Bridge(a, b); err != nil {
		return nil, err
	}
	if err := r.pool.Open(context.Background(), b); err != nil {
		_ = a.Close()
		return nil, err
	}
	return a, nil
}

// counted is a Handler that signals each message it is given.
type counted struct{ got chan struct{} }

func (h counted) HandleMessage(*Session, *Message) error { h.got <- struct{}{}; return nil }
func (counted) HandleReport(*Session, Report)            {}

// BenchmarkRelayMessage relays one message per iteration from a client,
// through a relay, to rcs-as, over pipes: the path a chat message takes
// through msrp-relay, Message.Body included (#530). The client waits for
// each message to be delivered before it sends the next.
func BenchmarkRelayMessage(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 64 << 10} {
		b.Run(byteSize(size), func(b *testing.B) {
			reg := &Registry{}
			got := make(chan struct{}, 1)
			bob, err := NewSession(SessionConfig{Local: mustURI(b, asURI), Remote: []URI{mustURI(b, relayInternalURI)}, Handler: counted{got}})
			if err != nil {
				b.Fatal(err)
			}
			if err := reg.Add(bob); err != nil {
				b.Fatal(err)
			}
			pool := &Pool{Dial: func(context.Context, URI) (net.Conn, error) {
				ours, theirs := net.Pipe()
				c, err := NewPassiveConn(theirs, reg, Config{})
				if err != nil {
					return nil, err
				}
				b.Cleanup(func() { _ = c.Close() })
				return ours, nil
			}}
			b.Cleanup(func() { _ = pool.Close() })
			clientEnd, relayEnd := net.Pipe()
			rc, err := NewPassiveConn(relayEnd, &benchBinder{tb: b, pool: pool}, Config{})
			if err != nil {
				b.Fatal(err)
			}
			cc, err := NewActiveConn(clientEnd, Config{})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = rc.Close(); _ = cc.Close() })
			alice, err := NewSession(SessionConfig{Local: mustURI(b, clientURI), Remote: []URI{mustURI(b, relayPublicURI)}, Handler: counted{make(chan struct{}, 1)}})
			if err != nil {
				b.Fatal(err)
			}
			if err := cc.Open(context.Background(), alice); err != nil {
				b.Fatal(err)
			}
			body := bodyOf(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := alice.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf(body), FailureReport: ReportNo}); err != nil {
					b.Fatal(err)
				}
				<-got
			}
		})
	}
}

func byteSize(n int) string {
	switch {
	case n >= 1<<10 && n%(1<<10) == 0:
		return itoa(n>>10) + "KiB"
	}
	return itoa(n) + "B"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
