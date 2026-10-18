package msrp

import "fmt"

// DefaultChunkSize is the chunk size this package sends with. RFC 4975
// §7.1.1 lets a sender cut messages into 2048-octet chunks instead of
// interrupting larger ones, and RCS clients do the same.
const DefaultChunkSize = 2048

// maxPlainChunk is the largest chunk that need not be interruptible
// (§5.1, §7.1.1). This package writes every chunk in one go and never
// interrupts one, so it never sends larger chunks.
const maxPlainChunk = 2048

// Defaults for receiving.
const (
	// DefaultMaxMessageSize bounds a reassembled message. It is a service
	// setting (the SDP max-size), not a protocol constant.
	DefaultMaxMessageSize int64 = 1 << 20
	// DefaultMaxPending bounds the incomplete messages one session may
	// have in flight, so a peer cannot pin memory with many half-sent
	// messages.
	DefaultMaxPending = 16
)

// Chunk is one piece of an outgoing message: its place in the message, its
// octets and the end-line flag it is sent with.
type Chunk struct {
	Range ByteRange
	Data  []byte
	Flag  byte
}

// Split cuts body into chunks of at most size octets (§7.1.1). Every chunk
// states its range-end and the total, since both are known. An empty body
// is one empty chunk, "1-0/0". Data slices share body's memory.
func Split(body []byte, size int) ([]Chunk, error) {
	if size < 1 || size > maxPlainChunk {
		return nil, fmt.Errorf("msrp: chunk size %d outside 1..%d", size, maxPlainChunk)
	}
	total := int64(len(body))
	if total == 0 {
		return []Chunk{{Range: ByteRange{Start: 1, End: 0, Total: 0}, Data: body, Flag: FlagEnd}}, nil
	}
	chunks := make([]Chunk, 0, (len(body)+size-1)/size)
	for off := 0; off < len(body); off += size {
		end := min(off+size, len(body))
		flag := FlagMore
		if end == len(body) {
			flag = FlagEnd
		}
		chunks = append(chunks, Chunk{
			Range: ByteRange{Start: int64(off) + 1, End: int64(end), Total: total},
			Data:  body[off:end],
			Flag:  flag,
		})
	}
	return chunks, nil
}

// Reassembler puts SEND chunks back together by Message-ID and Byte-Range
// (§7.3.1). Chunks may arrive in any order and may overlap, in which case
// the later chunk wins; the chunk flagged "$" fixes the message length, and
// a chunk flagged "#" abandons the message. The zero value uses the
// defaults. A Reassembler is not safe for concurrent use.
type Reassembler struct {
	// MaxSize bounds a message; chunks that reach past it are refused with
	// 413 (§10.5). Zero means DefaultMaxMessageSize.
	MaxSize int64
	// MaxPending bounds incomplete messages; a chunk that would start one
	// more is refused with 413. Zero means DefaultMaxPending.
	MaxPending int

	pending map[string]*partial
}

type partial struct {
	buf   []byte
	have  []span
	end   int64 // message length once the "$" chunk arrived, else Unknown
	total int64 // declared Byte-Range total, else Unknown
}

// span is an inclusive range of received positions.
type span struct{ lo, hi int64 }

// Add takes one SEND chunk whose body has been read. It returns the whole
// message once this chunk completes it, with the headers of this chunk, the
// full body and a Byte-Range of 1-N/N. It returns nil while chunks are
// missing and after an abort. A *StatusError (400 or 413) means the chunk is
// refused and anything held for its message is dropped.
func (r *Reassembler) Add(m *Message) (*Message, error) {
	id := m.MessageID
	br := m.Range()
	n := int64(len(m.Body))
	maxSize := r.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}

	// Written so that a range-start near the int64 limit cannot overflow.
	if br.Start-1 > maxSize-n || (br.Total != Unknown && br.Total > maxSize) {
		r.Drop(id)
		return nil, statusError(StatusMessageTooLarge)
	}
	last := br.Start + n - 1
	if err := checkBody(m, n); err != nil {
		r.Drop(id)
		return nil, &StatusError{Code: StatusBadRequest, Comment: err.Error()}
	}
	if m.flag() == FlagAbort {
		r.Drop(id)
		return nil, nil
	}

	p := r.pending[id]
	if p == nil && br.Start == 1 && m.flag() == FlagEnd {
		// The whole message in one chunk, the common case: nothing to hold.
		if br.Total != Unknown && br.Total != n {
			return nil, &StatusError{Code: StatusBadRequest, Comment: "message shorter than its total"}
		}
		return assembled(m, m.Body), nil
	}
	if p == nil {
		maxPending := r.MaxPending
		if maxPending <= 0 {
			maxPending = DefaultMaxPending
		}
		if len(r.pending) >= maxPending {
			return nil, &StatusError{Code: StatusMessageTooLarge, Comment: "too many incomplete messages"}
		}
		if r.pending == nil {
			r.pending = map[string]*partial{}
		}
		p = &partial{end: Unknown, total: Unknown}
		r.pending[id] = p
	}

	if br.Total != Unknown {
		if p.total != Unknown && p.total != br.Total {
			r.Drop(id)
			return nil, &StatusError{Code: StatusBadRequest, Comment: "chunks disagree on the total"}
		}
		p.total = br.Total
	}
	if m.flag() == FlagEnd {
		if p.end != Unknown && p.end != last {
			r.Drop(id)
			return nil, &StatusError{Code: StatusBadRequest, Comment: "two different last chunks"}
		}
		p.end = last
	}
	if n > 0 {
		p.store(br.Start, m.Body, maxSize)
	}

	if p.end != Unknown {
		if (p.total != Unknown && p.total != p.end) || (len(p.have) > 0 && p.have[len(p.have)-1].hi > p.end) {
			r.Drop(id)
			return nil, &StatusError{Code: StatusBadRequest, Comment: "data beyond the last chunk"}
		}
		if p.end == 0 || (len(p.have) == 1 && p.have[0].lo == 1 && p.have[0].hi == p.end) {
			delete(r.pending, id)
			return assembled(m, p.buf[:p.end]), nil
		}
	}
	return nil, nil
}

// Pending returns the number of incomplete messages held.
func (r *Reassembler) Pending() int { return len(r.pending) }

// Drop forgets the incomplete message id, if any.
func (r *Reassembler) Drop(id string) { delete(r.pending, id) }

func (p *partial) store(start int64, data []byte, maxSize int64) {
	last := start + int64(len(data)) - 1
	if int64(len(p.buf)) < last {
		if int64(cap(p.buf)) < last {
			// Grow with what has arrived rather than with the declared
			// total, so a one-octet chunk claiming a huge total costs one
			// octet.
			nb := make([]byte, last, min(max(last, 2*int64(cap(p.buf))), maxSize))
			copy(nb, p.buf)
			p.buf = nb
		} else {
			p.buf = p.buf[:last]
		}
	}
	copy(p.buf[start-1:], data)
	p.have = addSpan(p.have, span{lo: start, hi: last})
}

// addSpan inserts s into the sorted, disjoint list have, merging spans that
// overlap or touch.
func addSpan(have []span, s span) []span {
	out := make([]span, 0, len(have)+1)
	placed := false
	for _, h := range have {
		switch {
		case h.hi+1 < s.lo:
			out = append(out, h)
		case s.hi+1 < h.lo:
			if !placed {
				out = append(out, s)
				placed = true
			}
			out = append(out, h)
		default:
			s = span{lo: min(s.lo, h.lo), hi: max(s.hi, h.hi)}
		}
	}
	if !placed {
		out = append(out, s)
	}
	return out
}

func assembled(last *Message, body []byte) *Message {
	whole := *last
	n := int64(len(body))
	whole.Body = body
	whole.ByteRange = &ByteRange{Start: 1, End: n, Total: n}
	whole.Continuation = FlagEnd
	return &whole
}
