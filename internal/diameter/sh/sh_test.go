package sh

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// Test identities use the reserved test network (MCC 001, MNC 01) and the
// fictional +1 555 01xx numbers on .github/allowed-test-identifiers.txt.
const (
	realm   = "ims.mnc001.mcc001.3gppnetwork.org"
	hssHost = "hss.ims.mnc001.mcc001.3gppnetwork.org"
	asHost  = "rcs-as-1.ims.mnc001.mcc001.3gppnetwork.org"
	impu    = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	impi    = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
	msisdn  = "15550100001"
	asName  = "sip:rcs-as.ims.mnc001.mcc001.3gppnetwork.org"
)

func testDictionary(tb testing.TB) *diameter.Dictionary {
	tb.Helper()
	// A node serving Cx and Sh merges both lists; that must work.
	d, err := diameter.NewDictionary(slices.Concat(cx.AVPs, AVPs)...)
	if err != nil {
		tb.Fatal(err)
	}
	return d
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }

func (fixedClock) AfterFunc(time.Duration, func()) diameter.Timer { return stoppedTimer{} }

type stoppedTimer struct{}

func (stoppedTimer) Stop() bool { return false }

func newNode(tb testing.TB, host string) *diameter.Node {
	tb.Helper()
	n, err := diameter.NewNode(diameter.Config{
		OriginHost:   host,
		OriginRealm:  realm,
		Applications: []diameter.Application{Application},
		Random:       func() uint64 { return 7 },
		Clock:        fixedClock{},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return n
}

func transmit(tb testing.TB, m *diameter.Message) *diameter.Message {
	tb.Helper()
	b, err := m.Encode()
	if err != nil {
		tb.Fatalf("Encode: %v", err)
	}
	got, err := diameter.DecodeMessage(b, testDictionary(tb), diameter.Limits{})
	if err != nil {
		tb.Fatalf("DecodeMessage: %v", err)
	}
	return got
}

// must unwraps a result the test expects to succeed; it panics so that it
// can wrap a call directly.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func check[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s after the round trip:\n got %+v\nwant %+v", what, got, want)
	}
}

func asRequest(sid string) cx.Request {
	return cx.Request{SessionID: sid, DestinationRealm: realm,
		SupportedFeatures: []cx.SupportedFeatures{{VendorID: cx.Vendor3GPP, FeatureListID: 1, FeatureList: 1}}}
}

func received(r cx.Request, origin string) cx.Request {
	r.OriginHost, r.OriginRealm = origin, realm
	return r
}

func answered(sid, origin string, result cx.Result) cx.Answer {
	return cx.Answer{SessionID: sid, OriginHost: origin, OriginRealm: realm, Result: result}
}
