package msrp

import (
	"context"
	"errors"
	"io"
	"sync"
)

var bridgeMu sync.Mutex

// maxHeldBytes bounds what a relay holds for a client side that is not
// bound yet. It is above one SendWindow of chunks, so a sender that
// windows never reaches it; one that does not is refused (413) for that
// session alone.
const maxHeldBytes = 256 << 10

// maxHeldEntries bounds the same by count, so that many tiny forwards
// cannot each cost a closure for little data.
const maxHeldEntries = 256

// errHeldFull refuses a forward toward an unbound client side whose
// holding queue is full.
var errHeldFull = errors.New("msrp: too much held for an unbound session")

// held is a forward waiting for its client side to be bound: send runs
// it on the connection once there is one, drop answers for it if there
// never is.
type held struct {
	messageID string
	send      func(out *Conn) error
	drop      func(code int)
	octets    int64
}

// maxRejected bounds how many refused Message-IDs a bridged session
// remembers. Forgetting one only costs a second refusal from the next hop
// if the sender keeps going after a 413.
const maxRejected = 64

// Bridge joins two sessions so that what arrives on one is forwarded on the
// other: msrp-relay bridges edge, the session a client connected to, with
// core, the one it opened toward rcs-as (ADR 0004). Neither session may
// have a Handler. Call Bridge before either session is bound, so no
// request can arrive unbridged; when one session ends, so does the other.
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
//   - The relay answers each SEND itself. A failure response or a timeout
//     on the next hop goes back to the sender as a failure REPORT when
//     Failure-Report allows (§6.4.1, §6.4.3), and after a 413 the relay
//     forwards nothing more of that message (RFC 4975 §10.5).
//   - Bodiless SENDs bind or keep alive one hop and are answered without
//     being forwarded; each side keeps itself alive.
//   - REPORTs are forwarded and never answered. Other methods, such as
//     NICKNAME, are forwarded and their response is carried back.
//
// The two sides are not treated alike, because the connection toward
// rcs-as is shared by many clients and a client connection is not:
//
//   - Toward core, forwarding waits for the write. A client sending faster
//     than rcs-as reads simply stops being read; its own connection is the
//     only one that waits.
//   - Toward edge, forwarding never waits: what goes to a client is
//     queued, and the reading of the shared connection never stops for one
//     client. Flow control is per session instead: a chunk from core is
//     answered when its last piece has been written toward the client, not
//     when it was read, so rcs-as, whose Send keeps a window of unanswered
//     chunks per session (Config.SendWindow), slows down for that session
//     alone. This defers the answer that RFC 4976 §6.4.1 asks to be
//     immediate, for the slow session only. A client that stops reading
//     altogether is cut off by the write deadline, and one whose backlog
//     passes Config.MaxRelayBacklog anyway (a sender that does not window,
//     for example with Failure-Report no) is cut off then
//     (ErrPeerNotReading).
//
// The relay service opens core from edge's Bind, that is, it connects to
// rcs-as when the client connects (ADR 0004), so normally neither side
// has to wait for the other. Should rcs-as send on core before the client
// has bound edge, what it sends is held, up to a small bound per session,
// and forwarded once edge is bound; beyond the bound it is refused with
// 413 and after TransactionTimeout without a client it is answered 408.
// Either way only that session is affected: the shared connection is never
// made to wait for a client to arrive.
func Bridge(edge, core *Session) error {
	if edge == core {
		return errors.New("msrp: cannot bridge a session to itself")
	}
	if edge.handler != nil || core.handler != nil {
		return errors.New("msrp: a bridged session must not have a Handler")
	}
	// Bridge is the only place that holds two session locks; serialising
	// it rules out two calls taking them in opposite orders.
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	edge.mu.Lock()
	core.mu.Lock()
	defer edge.mu.Unlock()
	defer core.mu.Unlock()
	if edge.peer != nil || core.peer != nil || edge.conn != nil || core.conn != nil {
		return errors.New("msrp: sessions must be unbound and unbridged")
	}
	edge.peer, core.peer = core, edge
	edge.edge = true
	return nil
}

// towards returns how to send to s within a bridge: queued toward the edge
// and counted against its backlog, waiting toward the core.
func (s *Session) towards() sendMode {
	if s.edge {
		return sendMode{queue: true, owner: s}
	}
	return sendWait
}

// forwardConn waits for the core session s to be bound. It is used only
// toward core, on the reading goroutine of the client's own connection, so
// only that client waits; and since the relay opens core from the client's
// Bind (ADR 0004), core is normally bound already. The wait is capped at a
// transaction's time all the same.
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

// dispatch runs send for the edge session s on its connection, or holds
// it while s is not bound; in, the connection the request came on, gives
// the clock and the timeout. Held forwards keep their order: until the
// flush on binding is through, new ones queue behind them.
func (s *Session) dispatch(in *Conn, messageID string, octets int64, send func(out *Conn) error, drop func(code int)) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	if out := s.conn; out != nil && !s.flushing {
		s.mu.Unlock()
		return send(out)
	}
	if s.heldOctets+octets > maxHeldBytes || len(s.held) >= maxHeldEntries {
		s.mu.Unlock()
		return errHeldFull
	}
	first := len(s.held) == 0 && s.conn == nil
	s.held = append(s.held, held{messageID: messageID, send: send, drop: drop, octets: octets})
	s.heldOctets += octets
	s.mu.Unlock()
	if first {
		in.cfg.Clock.AfterFunc(in.cfg.TransactionTimeout, func() { s.dropHeld(StatusRequestTimeout, true) })
	}
	return nil
}

// flushHeld sends what was held for s once it is bound to out.
func (s *Session) flushHeld(out *Conn) {
	for {
		s.mu.Lock()
		batch := s.held
		s.held, s.heldOctets = nil, 0
		if len(batch) == 0 {
			s.flushing = false
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		for i, h := range batch {
			if err := h.send(out); err != nil {
				for _, rest := range batch[i:] {
					rest.drop(StatusNoSession)
				}
				break
			}
		}
	}
}

// dropHeldMessage drops what is held of one message, answering for it
// with code, so that a client binding later does not get a message that
// was cut off part-way.
func (s *Session) dropHeldMessage(id string, code int) {
	s.mu.Lock()
	var drop []held
	kept := s.held[:0]
	for _, h := range s.held {
		if h.messageID == id {
			drop = append(drop, h)
			s.heldOctets -= h.octets
		} else {
			kept = append(kept, h)
		}
	}
	s.held = kept
	s.mu.Unlock()
	for _, h := range drop {
		h.drop(code)
	}
}

// dropHeld answers for everything held with code; onlyUnbound keeps a
// timer that fires after binding from dropping anything.
func (s *Session) dropHeld(code int, onlyUnbound bool) {
	s.mu.Lock()
	if onlyUnbound && s.conn != nil {
		s.mu.Unlock()
		return
	}
	batch := s.held
	s.held, s.heldOctets = nil, 0
	s.mu.Unlock()
	for _, h := range batch {
		h.drop(code)
	}
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
	// Toward the client nothing waits (see Bridge); toward rcs-as the
	// client's own connection may wait for core to be bound.
	var out *Conn
	size := c.cfg.ChunkSize
	if !peer.edge {
		var code int
		if out, code = peer.forwardConn(c); code != 0 {
			return c.respond(m, code)
		}
		size = out.cfg.ChunkSize
	}
	id := m.MessageID
	br := m.Range()
	maxSize := c.cfg.MaxMessageSize
	if s.isRejected(id) || (br.Total != Unknown && br.Total > maxSize) {
		s.reject(id)
		return c.respond(m, StatusMessageTooLarge)
	}

	body := c.r.Body()
	// The two piece buffers are kept with the session; only the goroutine
	// reading c uses them.
	if len(s.pieces[0]) != size {
		s.pieces = [2][]byte{make([]byte, size), make([]byte, size)}
	}
	cur, next := s.pieces[0], s.pieces[1]
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
			_ = peer.forwardPiece(out, c, s, m, pos, nil, FlagAbort, nil)
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
		var answer func(error)
		if last && peer.edge {
			// Toward a client the chunk is answered once its last piece has
			// been written, so a sender that windows its chunks (Send does)
			// goes at the client's pace without the shared connection
			// waiting.
			answer = func(err error) {
				code := StatusOK
				if err != nil {
					code = StatusNoSession
				}
				_ = c.respond(m, code)
			}
		}
		if err := peer.forwardPiece(out, c, s, m, pos, cur[:n], flag, answer); err != nil {
			if errors.Is(err, errHeldFull) {
				s.reject(id)
				peer.dropHeldMessage(id, StatusMessageTooLarge)
				return c.respond(m, StatusMessageTooLarge)
			}
			return c.respond(m, StatusNoSession)
		}
		pos += int64(n)
		if last {
			if answer != nil {
				return nil
			}
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
// pos, for p: on out toward core, or through dispatch toward the edge, in
// which case out is nil. Failures on that hop go back on in to the sender
// of m, which arrived for from.
func (p *Session) forwardPiece(out, in *Conn, from *Session, m *Message, pos int64, data []byte, flag byte, written func(error)) error {
	if data == nil {
		data = []byte{}
	}
	r := ByteRange{Start: pos, End: pos + int64(len(data)) - 1, Total: m.Range().Total}
	send := func(out *Conn, data []byte) error {
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
		mode := p.towards()
		mode.written = written
		return out.sendRequest(context.Background(), fwd, mode, func(code int, _ string) {
			if code == StatusOK {
				return
			}
			if code == StatusMessageTooLarge {
				from.reject(m.MessageID)
			}
			if ShouldReport(m, code) {
				_ = in.sendRequest(context.Background(), NewReport(m, from.local, r, code), from.towards(), nil)
			}
		})
	}
	if out != nil {
		return send(out, data)
	}
	// The piece buffer is reused once this returns, so a held piece keeps
	// a copy.
	kept := append([]byte(nil), data...)
	return p.dispatch(in, m.MessageID, int64(len(kept)), func(out *Conn) error { return send(out, kept) }, func(code int) {
		if written != nil {
			_ = in.respond(m, code)
		}
	})
}

// relayBuffered forwards a request whose body, if any, has been read:
// REPORT and methods other than SEND. Bodiless SENDs stay on this hop.
func (s *Session) relayBuffered(c *Conn, peer *Session, m *Message) error {
	if m.Method == MethodSend {
		return c.respond(m, StatusOK)
	}
	send := func(out *Conn) error {
		fwd := *m
		fwd.ToPath = peer.remote
		fwd.FromPath = []URI{peer.local}
		peer.touch(out)
		if m.Method == MethodReport {
			// Nothing can be answered if this fails; the failing
			// connection takes the bridge down with it.
			_ = out.sendRequest(context.Background(), &fwd, peer.towards(), nil)
			return nil
		}
		return out.sendRequest(context.Background(), &fwd, peer.towards(), func(code int, comment string) {
			if !ShouldRespond(m, code) {
				return
			}
			if resp, err := NewResponse(m, code, comment); err == nil {
				_ = c.sendMessage(context.Background(), resp, s.towards())
			}
		})
	}
	var err error
	if peer.edge {
		// The body was read into a buffer of its own, so m can be held.
		err = peer.dispatch(c, m.MessageID, int64(len(m.Body)), send, func(code int) { _ = c.respond(m, code) })
	} else {
		out, code := peer.forwardConn(c)
		if code != 0 {
			return c.respond(m, code)
		}
		err = send(out)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errHeldFull):
		return c.respond(m, StatusMessageTooLarge)
	}
	return c.respond(m, StatusNoSession)
}
