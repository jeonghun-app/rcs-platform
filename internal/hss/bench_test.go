package hss

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

// The profile work of one SAR: reading the stored profile and writing the
// User-Data. Run with go test -bench SAR -cpu 1 ./internal/hss/.
func BenchmarkSARProfileWork(b *testing.B) {
	doc, err := store.EncodeProfile(DefaultRCSProfile(DefaultProfileID, asURI))
	if err != nil {
		b.Fatal(err)
	}
	s := &store.Subscription{IMPI: impi1, Profile: DefaultProfileID, PublicIdentities: []store.PublicIdentity{{IMPU: impu1}, {IMPU: tel1}}}
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := store.DecodeProfile(doc, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("decode+userdata", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p, err := store.DecodeProfile(doc, 1)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := userData(s, 0, p); err != nil {
				b.Fatal(err)
			}
		}
	})
}
