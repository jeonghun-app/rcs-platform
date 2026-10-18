package store_test

import (
	"reflect"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// FuzzDecodeSubscription reads arbitrary stored documents: nothing may
// panic, and what decodes encodes back to a document that decodes the same.
func FuzzDecodeSubscription(f *testing.F) {
	s := storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1, storetest.TEL1)
	s.AKA = &store.AKA{K: store.Sealed{1}, OPc: store.Sealed{2}, AMF: [2]byte{0x80}, SQN: 33}
	s.Digest = []store.DigestCredential{{Realm: storetest.Domain, HA1MD5: store.Sealed{3}, HA1SHA256: store.Sealed{4}}}
	s.Charging = &store.ChargingInformation{PrimaryEventChargingFunctionName: "aaa://ecf"}
	doc, err := store.EncodeSubscription(s)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(doc)
	f.Add([]byte(`{"schema":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := store.DecodeSubscription(data, 1)
		if err != nil {
			return
		}
		again, err := store.EncodeSubscription(got)
		if err != nil {
			t.Fatalf("decoded subscription does not encode: %v", err)
		}
		back, err := store.DecodeSubscription(again, 1)
		if err != nil || !reflect.DeepEqual(back, got) {
			t.Fatalf("round trip changed the subscription: %v\n%+v\n%+v", err, got, back)
		}
	})
}

// FuzzDecodeProfile does the same for stored service profiles.
func FuzzDecodeProfile(f *testing.F) {
	doc, err := store.EncodeProfile(storetest.Profile("p"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(doc)
	f.Add([]byte(`{"schema":1,"id":"p","criteria":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := store.DecodeProfile(data, 1)
		if err != nil {
			return
		}
		again, err := store.EncodeProfile(got)
		if err != nil {
			// Decoding checks structure only; writing also compiles, which
			// a document that was never written by EncodeProfile may fail.
			if _, cerr := ifc.Compile(got.Criteria); cerr != nil {
				return
			}
			t.Fatalf("decoded profile does not encode: %v", err)
		}
		if _, err := store.DecodeProfile(again, 1); err != nil {
			t.Fatalf("encoded profile does not decode: %v", err)
		}
	})
}
