package msrp

import (
	"errors"
	"math"
	"testing"
	"time"
)

// t0 is when test chunks arrive unless a test says otherwise.
var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestSplitCutsBodiesIntoChunksOfAtMostTheSize(t *testing.T) {
	tests := []struct {
		size, length int
		ranges       []ByteRange
	}{
		{2048, 0, []ByteRange{{1, 0, 0}}},
		{2048, 1, []ByteRange{{1, 1, 1}}},
		{2048, 2048, []ByteRange{{1, 2048, 2048}}},
		{2048, 2049, []ByteRange{{1, 2048, 2049}, {2049, 2049, 2049}}},
		{2048, 5000, []ByteRange{{1, 2048, 5000}, {2049, 4096, 5000}, {4097, 5000, 5000}}},
		{4, 8, []ByteRange{{1, 4, 8}, {5, 8, 8}}},
	}
	for _, tt := range tests {
		body := bodyOf(tt.length)
		chunks, err := Split(body, tt.size)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunks) != len(tt.ranges) {
			t.Fatalf("%d octets in %d: %d chunks, want %d", tt.length, tt.size, len(chunks), len(tt.ranges))
		}
		var joined []byte
		for i, c := range chunks {
			if c.Range != tt.ranges[i] {
				t.Errorf("%d octets: chunk %d range %v, want %v", tt.length, i, c.Range, tt.ranges[i])
			}
			wantFlag := FlagMore
			if i == len(chunks)-1 {
				wantFlag = FlagEnd
			}
			if c.Flag != wantFlag {
				t.Errorf("%d octets: chunk %d flag %q", tt.length, i, c.Flag)
			}
			joined = append(joined, c.Data...)
		}
		if !equalBodies(joined, body) {
			t.Errorf("%d octets: chunks do not add up to the body", tt.length)
		}
	}
}

func TestSplitRefusesChunksThatWouldHaveToBeInterruptible(t *testing.T) {
	for _, size := range []int{0, -1, 2049} {
		if _, err := Split([]byte("x"), size); err == nil {
			t.Errorf("Split accepted size %d", size)
		}
	}
}

func chunkMsg(id string, r ByteRange, body string, flag byte) *Message {
	return &Message{Method: MethodSend, MessageID: id, ByteRange: &r, ContentType: "text/plain",
		Body: BodyOf([]byte(body)), Continuation: flag}
}

func TestReassemblerPassesAWholeMessageStraightThrough(t *testing.T) {
	var r Reassembler
	for _, m := range []*Message{
		chunkMsg("msg1", ByteRange{1, 5, 5}, "hello", FlagEnd),
		chunkMsg("msg2", ByteRange{1, Unknown, Unknown}, "hello", FlagEnd),
		{Method: MethodSend, MessageID: "msg3", ContentType: "text/plain", Body: BodyOf([]byte("hello"))}, // no Byte-Range
	} {
		got, err := r.Add(m, t0)
		if err != nil || got == nil || string(got.Body.Bytes()) != "hello" || *got.ByteRange != (ByteRange{1, 5, 5}) {
			t.Fatalf("%s: got %+v, %v", m.MessageID, got, err)
		}
	}
	if r.Pending() != 0 {
		t.Fatal("a whole message left state behind")
	}
}

func TestReassemblerJoinsChunksInAnyOrder(t *testing.T) {
	parts := []*Message{
		chunkMsg("msg1", ByteRange{1, 4, 12}, "abcd", FlagMore),
		chunkMsg("msg1", ByteRange{5, 8, 12}, "EFGH", FlagMore),
		chunkMsg("msg1", ByteRange{9, 12, 12}, "ijkl", FlagEnd),
	}
	orders := [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}, {2, 0, 1}, {0, 2, 1}, {1, 0, 2}}
	for _, order := range orders {
		var r Reassembler
		var got *Message
		for i, idx := range order {
			m, err := r.Add(parts[idx], t0)
			if err != nil {
				t.Fatalf("order %v: %v", order, err)
			}
			if i < len(order)-1 && m != nil {
				t.Fatalf("order %v: complete too early", order)
			}
			got = m
		}
		if got == nil || string(got.Body.Bytes()) != "abcdEFGHijkl" || r.Pending() != 0 {
			t.Fatalf("order %v: got %+v", order, got)
		}
	}
}

func TestReassemblerTakesTheLaterOfOverlappingChunks(t *testing.T) {
	var r Reassembler
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{1, 6, 8}, "abcdef", FlagMore))
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{4, 6, 8}, "DEF", FlagMore))
	got := mustAdd(t, &r, chunkMsg("msg1", ByteRange{7, 8, 8}, "gh", FlagEnd))
	if got == nil || string(got.Body.Bytes()) != "abcDEFgh" {
		t.Fatalf("got %+v", got)
	}
}

func TestReassemblerHandlesUnknownTotalsAndInterruptedChunks(t *testing.T) {
	var r Reassembler
	// An interrupted chunk is shorter than its range says (§7.3.1); the
	// sender resumes after the last octet it actually sent.
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{1, 10, Unknown}, "abc", FlagMore))
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{4, Unknown, Unknown}, "de", FlagMore))
	got := mustAdd(t, &r, chunkMsg("msg1", ByteRange{6, 7, Unknown}, "fg", FlagEnd))
	if got == nil || string(got.Body.Bytes()) != "abcdefg" {
		t.Fatalf("got %+v", got)
	}
}

func TestReassemblerWaitsForEveryGap(t *testing.T) {
	var r Reassembler
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{7, 8, 8}, "gh", FlagEnd))
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{1, 2, 8}, "ab", FlagMore))
	if got := mustAdd(t, &r, chunkMsg("msg1", ByteRange{5, 6, 8}, "ef", FlagMore)); got != nil {
		t.Fatal("completed with a gap at 3-4")
	}
	if got := mustAdd(t, &r, chunkMsg("msg1", ByteRange{3, 4, 8}, "cd", FlagMore)); got == nil || string(got.Body.Bytes()) != "abcdefgh" {
		t.Fatalf("got %+v", got)
	}
}

func TestReassemblerCompletesAnEmptyMessageSentInChunks(t *testing.T) {
	var r Reassembler
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{1, Unknown, Unknown}, "", FlagMore))
	got := mustAdd(t, &r, chunkMsg("msg1", ByteRange{1, 0, 0}, "", FlagEnd))
	if got == nil || got.Body.Len() != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestReassemblerDropsAnAbortedMessage(t *testing.T) {
	var r Reassembler
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{1, 4, 8}, "abcd", FlagMore))
	if got := mustAdd(t, &r, chunkMsg("msg1", ByteRange{5, Unknown, 8}, "EF", FlagAbort)); got != nil {
		t.Fatal("an aborted message was delivered")
	}
	if r.Pending() != 0 {
		t.Fatal("an aborted message is still held")
	}
}

func TestReassemblerRefusesMessagesOverTheSizeLimitWith413(t *testing.T) {
	r := Reassembler{MaxSize: 10}
	for name, m := range map[string]*Message{
		"declared total":   chunkMsg("msg1", ByteRange{1, 2, 11}, "ab", FlagMore),
		"position":         chunkMsg("msg2", ByteRange{10, Unknown, Unknown}, "ab", FlagMore),
		"huge range-start": chunkMsg("msg3", ByteRange{math.MaxInt64, Unknown, Unknown}, "ab", FlagMore),
	} {
		if _, err := r.Add(m, t0); statusCode(err) != StatusMessageTooLarge {
			t.Errorf("%s: err = %v, want 413", name, err)
		}
	}
	mustAdd(t, &r, chunkMsg("msg4", ByteRange{1, 5, Unknown}, "abcde", FlagMore))
	if _, err := r.Add(chunkMsg("msg4", ByteRange{6, Unknown, Unknown}, "fghijk", FlagMore), t0); statusCode(err) != StatusMessageTooLarge {
		t.Fatalf("err = %v, want 413", err)
	}
	if r.Pending() != 0 {
		t.Fatal("a refused message is still held")
	}
}

func TestReassemblerBoundsIncompleteMessages(t *testing.T) {
	r := Reassembler{MaxPending: 2}
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{1, 1, 2}, "a", FlagMore))
	mustAdd(t, &r, chunkMsg("msg2", ByteRange{1, 1, 2}, "a", FlagMore))
	if _, err := r.Add(chunkMsg("msg3", ByteRange{1, 1, 2}, "a", FlagMore), t0); statusCode(err) != StatusMessageTooLarge {
		t.Fatalf("err = %v, want 413", err)
	}
	// A whole message needs no slot.
	if got := mustAdd(t, &r, chunkMsg("msg4", ByteRange{1, 1, 1}, "a", FlagEnd)); got == nil {
		t.Fatal("whole message refused")
	}
	r.Drop("msg1")
	mustAdd(t, &r, chunkMsg("msg3", ByteRange{1, 1, 2}, "a", FlagMore))
}

func TestReassemblerRefusesChunksThatContradictEachOtherWith400(t *testing.T) {
	tests := map[string][]*Message{
		"totals differ": {
			chunkMsg("msg1", ByteRange{1, 2, 8}, "ab", FlagMore),
			chunkMsg("msg1", ByteRange{3, 4, 9}, "cd", FlagMore),
		},
		"two last chunks": {
			chunkMsg("msg1", ByteRange{5, 6, Unknown}, "ef", FlagEnd),
			chunkMsg("msg1", ByteRange{3, 4, Unknown}, "cd", FlagEnd),
		},
		"data after the last chunk": {
			chunkMsg("msg1", ByteRange{3, 4, Unknown}, "cd", FlagEnd),
			chunkMsg("msg1", ByteRange{5, 6, Unknown}, "ef", FlagMore),
		},
		"last chunk short of the total": {
			chunkMsg("msg1", ByteRange{1, 2, 8}, "ab", FlagMore),
			chunkMsg("msg1", ByteRange{3, 4, 8}, "cd", FlagEnd),
		},
		"whole message short of its total": {
			chunkMsg("msg1", ByteRange{1, Unknown, 8}, "ab", FlagEnd),
		},
		"body longer than its range": {
			chunkMsg("msg1", ByteRange{1, 1, 8}, "ab", FlagMore),
		},
	}
	for name, msgs := range tests {
		var r Reassembler
		var err error
		for _, m := range msgs {
			if _, err = r.Add(m, t0); err != nil {
				break
			}
		}
		if statusCode(err) != StatusBadRequest {
			t.Errorf("%s: err = %v, want 400", name, err)
		}
		if r.Pending() != 0 {
			t.Errorf("%s: contradicting message still held", name)
		}
	}
}

func TestReassemblerKeepsMessagesApartByMessageID(t *testing.T) {
	var r Reassembler
	mustAdd(t, &r, chunkMsg("msg1", ByteRange{1, 2, 4}, "ab", FlagMore))
	mustAdd(t, &r, chunkMsg("msg2", ByteRange{1, 2, 4}, "AB", FlagMore))
	one := mustAdd(t, &r, chunkMsg("msg1", ByteRange{3, 4, 4}, "cd", FlagEnd))
	two := mustAdd(t, &r, chunkMsg("msg2", ByteRange{3, 4, 4}, "CD", FlagEnd))
	if string(one.Body.Bytes()) != "abcd" || string(two.Body.Bytes()) != "ABCD" {
		t.Fatalf("got %q and %q", one.Body, two.Body)
	}
}

func mustAdd(t *testing.T, r *Reassembler, m *Message) *Message {
	t.Helper()
	got, err := r.Add(m, t0)
	if err != nil {
		t.Fatalf("Add(%s %v): %v", m.MessageID, m.ByteRange, err)
	}
	return got
}

func statusCode(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}
