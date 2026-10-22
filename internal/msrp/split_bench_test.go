package msrp

import (
	"bytes"
	"testing"
)

// splitSink keeps BenchmarkSplit's chunks alive.
var splitSink []Chunk

// BenchmarkSplit cuts a 1 MiB body into DefaultChunkSize chunks, as the
// relay does for each outgoing message (#547: each chunk's Data is a Body
// over the body's array, as the []byte was).
func BenchmarkSplit(b *testing.B) {
	body := bytes.Repeat([]byte("x"), 1<<20)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		chunks, err := Split(body, DefaultChunkSize)
		if err != nil {
			b.Fatal(err)
		}
		splitSink = chunks
	}
}
