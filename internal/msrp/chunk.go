package msrp

import (
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"
)

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
	// DefaultMaxFragments bounds the separate runs of octets one
	// incomplete message may consist of. Chunks that arrive in order extend
	// one run, so only gaps cost a fragment; the bound keeps the work per
	// chunk independent of the message size.
	DefaultMaxFragments = 64
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

// Budget is an allowance of buffered octets that several holders draw on
// together. A Conn gives every session a Budget of its own whose Parent is
// the connection's, with a Reserve: what a session holds up to its Reserve
// is guaranteed to it, and only what it holds beyond is drawn from the
// shared Parent. So sessions crowding the shared part cannot leave another
// session without room for a message of its own. A Budget is safe for
// concurrent use.
type Budget struct {
	// Limit bounds what is drawn from this Budget; zero or less means no
	// bound of its own.
	Limit int64
	// Reserve is the part not drawn from Parent.
	Reserve int64
	Parent  *Budget

	mu      sync.Mutex
	used    int64
	spilled int64 // drawn from Parent
}

// Used returns the octets currently drawn.
func (b *Budget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

func (b *Budget) take(n int64) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Limit > 0 && b.used+n > b.Limit {
		return false
	}
	if b.Parent != nil {
		if spill := max(0, b.used+n-b.Reserve) - b.spilled; spill > 0 {
			if !b.Parent.take(spill) {
				return false
			}
			b.spilled += spill
		}
	}
	b.used += n
	return true
}

func (b *Budget) release(n int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
	if b.Parent != nil {
		if keep := max(0, b.used-b.Reserve); b.spilled > keep {
			b.Parent.release(b.spilled - keep)
			b.spilled = keep
		}
	}
}

// Reassembler puts SEND chunks back together by Message-ID and Byte-Range
// (§7.3.1). Chunks may arrive in any order and may overlap, in which case
// the later chunk wins; the chunk flagged "$" fixes the message length, and
// a chunk flagged "#" abandons the message.
//
// Memory follows the octets that have arrived, never the Byte-Range
// total a peer declares: a message is held as runs of received octets, a
// chunk that continues a run is appended to it, and a chunk that overlaps
// is copied over what is there. So adding a chunk costs time in proportion
// to the chunk (plus a search over at most MaxFragments runs), and the
// message is copied whole only once, when it completes. Every octet held
// is charged to MaxBuffered and to Budget; a chunk that would go over
// either is refused with 413 and its message is dropped.
//
// The zero value uses the defaults. A Reassembler is safe for concurrent
// use.
type Reassembler struct {
	// MaxSize bounds a message; chunks that reach past it are refused with
	// 413 (§10.5). Zero means DefaultMaxMessageSize.
	MaxSize int64
	// MaxPending bounds incomplete messages; a chunk that would start one
	// more is refused with 413. Zero means DefaultMaxPending.
	MaxPending int
	// MaxBuffered bounds the octets held for all incomplete messages
	// together. Zero means twice MaxSize.
	MaxBuffered int64
	// MaxFragments bounds the runs one incomplete message may be held in.
	// Zero means DefaultMaxFragments.
	MaxFragments int
	// Budget, if set, is shared with other Reassemblers.
	Budget *Budget

	mu      sync.Mutex
	pending map[string]*partial
	held    int64
	closed  bool
}

type partial struct {
	started time.Time // when the first chunk came
	runs    []run     // sorted and disjoint
	have    int64     // octets received
	cost    int64     // octets of capacity charged
	end     int64     // message length once the "$" chunk arrived, else Unknown
	total   int64     // declared Byte-Range total, else Unknown
	touched time.Time
}

// run is a stretch of received octets starting at message position start.
type run struct {
	start int64
	data  []byte
}

func (r run) last() int64 { return r.start + int64(len(r.data)) - 1 }

func (r *Reassembler) maxSize() int64 {
	if r.MaxSize > 0 {
		return r.MaxSize
	}
	return DefaultMaxMessageSize
}

// Add takes one SEND chunk whose body has been read; now marks when, for
// Expire. It returns the whole message once this chunk completes it, with
// the headers of this chunk, the full body and a Byte-Range of 1-N/N. It
// returns nil while chunks are missing and after an abort. A *StatusError
// (400 or 413, or 481 after Close) means the chunk is refused and anything
// held for its message is dropped.
func (r *Reassembler) Add(m *Message, now time.Time) (*Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, statusError(StatusNoSession)
	}
	id := m.MessageID
	br := m.Range()
	n := int64(len(m.Body))
	maxSize := r.maxSize()

	// Written so that a range-start near the int64 limit cannot overflow.
	if br.Start-1 > maxSize-n || (br.Total != Unknown && br.Total > maxSize) {
		r.dropLocked(id)
		return nil, statusError(StatusMessageTooLarge)
	}
	if err := checkBody(m, n); err != nil {
		r.dropLocked(id)
		return nil, &StatusError{Code: StatusBadRequest, Comment: err.Error()}
	}
	if m.flag() == FlagAbort {
		r.dropLocked(id)
		return nil, nil
	}
	last := br.Start + n - 1

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
		p = &partial{end: Unknown, total: Unknown, started: now}
		r.pending[id] = p
	}
	p.touched = now

	fail := func(code int, why string) (*Message, error) {
		r.dropLocked(id)
		return nil, &StatusError{Code: code, Comment: why}
	}
	if br.Total != Unknown {
		if p.total != Unknown && p.total != br.Total {
			return fail(StatusBadRequest, "chunks disagree on the total")
		}
		p.total = br.Total
	}
	if m.flag() == FlagEnd {
		if p.end != Unknown && p.end != last {
			return fail(StatusBadRequest, "two different last chunks")
		}
		p.end = last
	}
	if p.end != Unknown {
		if (p.total != Unknown && p.total != p.end) || last > p.end ||
			(len(p.runs) > 0 && p.runs[len(p.runs)-1].last() > p.end) {
			return fail(StatusBadRequest, "data beyond the last chunk")
		}
	}
	if n > 0 {
		if code := r.store(p, br.Start, m.Body); code != 0 {
			return fail(code, "message cannot be held")
		}
	}
	if p.end != Unknown && p.have == p.end {
		// The runs are disjoint and lie within 1..end, so holding end octets
		// means holding all of them.
		body := p.join()
		r.dropLocked(id)
		return assembled(m, body), nil
	}
	return nil, nil
}

// store puts data, which starts at message position start, into p: octets
// already held are overwritten, the rest extend the run before them or
// start a new one. It returns a status code when a limit is reached.
func (r *Reassembler) store(p *partial, start int64, data []byte) int {
	end := start + int64(len(data)) - 1
	// No run can usefully grow past the known end of the message, so growth
	// is capped there instead of doubling beyond it.
	ceiling := r.maxSize()
	if p.total != Unknown {
		ceiling = p.total
	}
	maxFragments := r.MaxFragments
	if maxFragments <= 0 {
		maxFragments = DefaultMaxFragments
	}

	i := sort.Search(len(p.runs), func(k int) bool { return p.runs[k].last() >= start })
	pos := start
	for pos <= end {
		if i < len(p.runs) && p.runs[i].start <= pos {
			rn := p.runs[i]
			to := min(end, rn.last())
			copy(rn.data[pos-rn.start:], data[pos-start:to-start+1])
			pos = to + 1
			i++
			continue
		}
		gapEnd := end
		if i < len(p.runs) {
			gapEnd = min(end, p.runs[i].start-1)
		}
		piece := data[pos-start : gapEnd-start+1]
		if i > 0 && p.runs[i-1].last() == pos-1 {
			grown, ok := r.grow(p, p.runs[i-1].data, piece, ceiling-p.runs[i-1].start+1)
			if !ok {
				return StatusMessageTooLarge
			}
			p.runs[i-1].data = grown
		} else {
			if len(p.runs) >= maxFragments {
				return StatusMessageTooLarge
			}
			fresh, ok := r.grow(p, nil, piece, int64(len(piece)))
			if !ok {
				return StatusMessageTooLarge
			}
			p.runs = slices.Insert(p.runs, i, run{start: pos, data: fresh})
			i++
		}
		p.have += int64(len(piece))
		pos = gapEnd + 1
	}
	return 0
}

// grow appends piece to b, charging any new capacity. Capacity at most
// doubles and never exceeds limit, the most octets b can ever hold.
func (r *Reassembler) grow(p *partial, b, piece []byte, limit int64) ([]byte, bool) {
	need := len(b) + len(piece)
	if need <= cap(b) {
		return append(b, piece...), true
	}
	newCap := max(need, min(2*cap(b), int(limit)))
	if !r.charge(p, int64(newCap-cap(b))) {
		return nil, false
	}
	nb := make([]byte, need, newCap)
	copy(nb, b)
	copy(nb[len(b):], piece)
	return nb, true
}

func (r *Reassembler) charge(p *partial, n int64) bool {
	maxBuffered := r.MaxBuffered
	if maxBuffered <= 0 {
		maxBuffered = 2 * r.maxSize()
	}
	if r.held+n > maxBuffered || !r.Budget.take(n) {
		return false
	}
	r.held += n
	p.cost += n
	return true
}

func (p *partial) join() []byte {
	if len(p.runs) == 1 {
		return p.runs[0].data
	}
	body := make([]byte, p.end)
	for _, rn := range p.runs {
		copy(body[rn.start-1:], rn.data)
	}
	return body
}

// Pending returns the number of incomplete messages held.
func (r *Reassembler) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// Buffered returns the octets held for incomplete messages.
func (r *Reassembler) Buffered() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.held
}

// Drop forgets the incomplete message id, if any.
func (r *Reassembler) Drop(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropLocked(id)
}

func (r *Reassembler) dropLocked(id string) {
	p := r.pending[id]
	if p == nil {
		return
	}
	delete(r.pending, id)
	r.held -= p.cost
	r.Budget.release(p.cost)
}

// Expire drops every incomplete message whose last chunk came at or
// before idleCutoff, or whose first chunk came at or before startCutoff,
// and returns how many it dropped. The first rule frees what a sender
// abandoned; the second bounds how long any message may take, so a sender
// trickling chunks cannot hold memory for ever.
func (r *Reassembler) Expire(idleCutoff, startCutoff time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	dropped := 0
	for id, p := range r.pending {
		if !p.touched.After(idleCutoff) || !p.started.After(startCutoff) {
			r.dropLocked(id)
			dropped++
		}
	}
	return dropped
}

// NextExpiry returns when Expire, with these limits, would next drop
// something; ok is false when nothing is held.
func (r *Reassembler) NextExpiry(idle, lifetime time.Duration) (t time.Time, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.pending {
		due := p.touched.Add(idle)
		if end := p.started.Add(lifetime); end.Before(due) {
			due = end
		}
		if !ok || due.Before(t) {
			t, ok = due, true
		}
	}
	return t, ok
}

// Close drops everything held, returning it to the Budget, and refuses
// later chunks with 481.
func (r *Reassembler) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.pending {
		r.dropLocked(id)
	}
	r.closed = true
}

func assembled(last *Message, body []byte) *Message {
	whole := *last
	n := int64(len(body))
	whole.Body = body
	whole.ByteRange = &ByteRange{Start: 1, End: n, Total: n}
	whole.Continuation = FlagEnd
	return &whole
}
