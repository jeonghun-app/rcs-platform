package msrp

import (
	"errors"
	"io"
	"sync"
)

var bridgeMu sync.Mutex

// maxRejected bounds how many refused Message-IDs a bridged session
// remembers. Forgetting one only costs a second refusal from the next hop
// if the sender keeps going after a 413.
const maxRejected = 64

// Bridge joins two sessions so that what arrives on one is forwarded on the
// other: msrp-relay bridges the session a client connected to with the one
// it opened toward rcs-as (ADR 0004). Neither session may have a Handler.
// Call Bridge before either session is bound, so no request can arrive
// unbridged; when one session ends, so does the other.
//
// The relay is a hop of its own on each side, so it follows the relay rules
// of RFC 4976 §6.4 without the AUTH part:
//
//   - Every forwarded request gets a new transaction id (§6.4) and the
//     paths of the outgoing side: To-Path is that side's remote path,
//     From-Path the relay's own URI there.
//   - A SEND body is streamed in pieces of at most the outgoing
//     connection's ChunkSize, each sent as soon as it is read and labelled
//     with its own Byte-Range (§6.4.1 allows re-chunking). So no message,
//     and no large chunk, is ever held whole, and a slow sender never
//     blocks the shared connection to rcs-as mid-chunk.
//   - The relay answers each SEND itself, after forwarding it. A failure
//     response or a timeout on the next hop goes back to the sender as a
//     failure REPORT when Failure-Report allows (§6.4.1, §6.4.3), and after
//     a 413 the relay forwards nothing more of that message (RFC 4975
//     §10.5).
//   - Bodiless SENDs bind or keep alive one hop and are answered without
//     being forwarded; each side keeps itself alive.
//   - REPORTs are forwarded and never answered. Other methods, such as
//     NICKNAME, are forwarded and their response is carried back.
func Bridge(a, b *Session) error {
	if a == b {
		return errors.New("msrp: cannot bridge a session to itself")
	}
	if a.handler != nil || b.handler != nil {
		return errors.New("msrp: a bridged session must not have a Handler")
	}
	// Bridge is the only place that holds two session locks; serialising
	// it rules out two calls taking them in opposite orders.
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	a.mu.Lock()
	b.mu.Lock()
	defer a.mu.Unlock()
	defer b.mu.Unlock()
	if a.peer != nil || b.peer != nil || a.conn != nil || b.conn != nil {
		return errors.New("msrp: sessions must be unbound and unbridged")
	}
	a.peer, b.peer = b, a
	return nil
}

// forwardConn waits for the outgoing session to be bound. Within a
// bridge the other side is normally bound a moment later, but a request
// must not wait on it for longer than a transaction may take.
func (s *Session) forwardConn(c *Conn) (*Conn, int) {
	select {
	case <-s.bound:
	default:
		// Only the first requests of a bridge can get here, so arming a
		// timer is the exception rather than a cost on every piece.
		timeout := make(chan struct{})
		t := c.cfg.Clock.AfterFunc(c.cfg.TransactionTimeout, func() { close(timeout) })
		defer t.Stop()
		select {
		case <-s.bound:
		case <-s.done:
			return nil, StatusNoSession
		case <-timeout:
			return nil, StatusRequestTimeout
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, StatusNoSession
	}
	return s.conn, 0
}

func (s *Session) isRejected(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rejected {
		if r == id {
			return true
		}
	}
	return false
}

func (s *Session) reject(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rejected {
		if r == id {
			return
		}
	}
	if len(s.rejected) == maxRejected {
		s.rejected = s.rejected[1:]
	}
	s.rejected = append(s.rejected, id)
}

// relaySend streams the body of the SEND m, which arrived on c for s, to
// the peer session in pieces.
func (s *Session) relaySend(c *Conn, peer *Session, m *Message) error {
	out, code := peer.forwardConn(c)
	if code != 0 {
		return c.respond(m, code)
	}
	id := m.MessageID
	br := m.Range()
	maxSize := c.cfg.MaxMessageSize
	if s.isRejected(id) || (br.Total != Unknown && br.Total > maxSize) {
		s.reject(id)
		return c.respond(m, StatusMessageTooLarge)
	}

	body := c.r.Body()
	size := out.cfg.ChunkSize
	cur, next := make([]byte, size), make([]byte, size)
	n, eof, err := readPiece(body, cur)
	pos := br.Start
	for {
		if err != nil {
			return err
		}
		// One octet of look-ahead tells whether this piece is the last,
		// which carries the sender's flag while every other one gets "+".
		// It is all the relay waits for before forwarding a full piece.
		last := eof
		if !eof {
			k, end, err := readPiece(body, next[:1])
			if err != nil {
				return err
			}
			last = k == 0 && end
		}
		if pos-1 > maxSize-int64(n) {
			s.reject(id)
			_ = peer.forwardPiece(out, c, s, m, pos, nil, FlagAbort)
			return c.respond(m, StatusMessageTooLarge)
		}
		if s.isRejected(id) {
			// The next hop refused an earlier piece; the failure REPORT
			// for it is already on its way.
			return c.respond(m, StatusMessageTooLarge)
		}
		flag := FlagMore
		if last {
			flag = m.flag()
		}
		if err := peer.forwardPiece(out, c, s, m, pos, cur[:n], flag); err != nil {
			return c.respond(m, StatusNoSession)
		}
		pos += int64(n)
		if last {
			return c.respond(m, StatusOK)
		}
		k, end, err2 := readPiece(body, next[1:])
		cur, next = next, cur
		n, eof, err = 1+k, end, err2
	}
}

// readPiece fills buf from the body, reporting whether the body ended.
func readPiece(body io.Reader, buf []byte) (int, bool, error) {
	n, err := io.ReadFull(body, buf)
	switch {
	case err == nil:
		return n, false, nil
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return n, true, nil
	}
	return n, false, err
}

// forwardPiece sends bytes of the SEND m, starting at message position
// pos, on out for p. Failures on that hop go back on in to the sender of
// m, which arrived for from.
func (p *Session) forwardPiece(out, in *Conn, from *Session, m *Message, pos int64, data []byte, flag byte) error {
	if data == nil {
		data = []byte{}
	}
	r := ByteRange{Start: pos, End: pos + int64(len(data)) - 1, Total: m.Range().Total}
	fwd := &Message{
		Method:        MethodSend,
		ToPath:        p.remote,
		FromPath:      []URI{p.local},
		MessageID:     m.MessageID,
		ByteRange:     &r,
		SuccessReport: m.SuccessReport,
		FailureReport: m.FailureReport,
		ContentType:   m.ContentType,
		Header:        m.Header,
		Body:          data,
		Continuation:  flag,
	}
	p.touch(out)
	return out.sendRequest(fwd, func(code int, _ string) {
		if code == StatusOK {
			return
		}
		if code == StatusMessageTooLarge {
			from.reject(m.MessageID)
		}
		if ShouldReport(m, code) {
			_ = in.sendRequest(NewReport(m, from.local, r, code), nil)
		}
	})
}

// relayBuffered forwards a request whose body, if any, has been read:
// REPORT and methods other than SEND. Bodiless SENDs stay on this hop.
func (s *Session) relayBuffered(c *Conn, peer *Session, m *Message) error {
	if m.Method == MethodSend {
		return c.respond(m, StatusOK)
	}
	out, code := peer.forwardConn(c)
	if code != 0 {
		return c.respond(m, code)
	}
	fwd := *m
	fwd.ToPath = peer.remote
	fwd.FromPath = []URI{peer.local}
	peer.touch(out)
	if m.Method == MethodReport {
		// Nothing can be answered if this fails; the failing connection
		// takes the bridge down with it.
		_ = out.sendRequest(&fwd, nil)
		return nil
	}
	err := out.sendRequest(&fwd, func(code int, comment string) {
		if !ShouldRespond(m, code) {
			return
		}
		if resp, err := NewResponse(m, code, comment); err == nil {
			_ = c.postMessage(resp)
		}
	})
	if err != nil {
		return c.respond(m, StatusNoSession)
	}
	return nil
}
