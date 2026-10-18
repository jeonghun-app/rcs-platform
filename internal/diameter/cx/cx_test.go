package cx

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

// Test identities use the reserved test network (MCC 001, MNC 01) and the
// fictional +1 555 01xx numbers on .github/allowed-test-identifiers.txt.
const (
	realm      = "ims.mnc001.mcc001.3gppnetwork.org"
	hssHost    = "hss.ims.mnc001.mcc001.3gppnetwork.org"
	scscfHost  = "scscf-1.ims.mnc001.mcc001.3gppnetwork.org"
	icscfHost  = "icscf-1.ims.mnc001.mcc001.3gppnetwork.org"
	impi       = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
	impu       = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	telURI     = "tel:+15550100001"
	scscfName  = "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org:5060"
	visitedNet = "ims.mnc001.mcc001.3gppnetwork.org"
)

func testDictionary(tb testing.TB) *diameter.Dictionary {
	tb.Helper()
	d, err := diameter.NewDictionary(AVPs...)
	if err != nil {
		tb.Fatal(err)
	}
	return d
}

// newNode returns a node that is never connected: building messages needs
// only its identity and Session-Id generator.
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

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }

func (fixedClock) AfterFunc(time.Duration, func()) diameter.Timer { return stoppedTimer{} }

type stoppedTimer struct{}

func (stoppedTimer) Stop() bool { return false }

// transmit encodes m and decodes it as a peer with the Cx dictionary would,
// so tests see exactly what crosses the wire.
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

// must unwraps a result that the test expects to succeed. It panics rather
// than taking a testing.TB so that it can wrap a call directly.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// request is the routing a S-CSCF or I-CSCF fills in; requestAsReceived is
// what the HSS reads back.
func request(sid string) Request {
	return Request{
		SessionID:         sid,
		DestinationHost:   hssHost,
		DestinationRealm:  realm,
		SupportedFeatures: []SupportedFeatures{{VendorID: Vendor3GPP, FeatureListID: 1, FeatureList: FeatureAliasIndication}},
	}
}

func requestAsReceived(sid, origin string) Request {
	r := request(sid)
	r.OriginHost, r.OriginRealm = origin, realm
	return r
}

func answerAsReceived(sid string, result Result) Answer {
	return Answer{
		SessionID: sid, OriginHost: hssHost, OriginRealm: realm, Result: result,
		SupportedFeatures: []SupportedFeatures{{VendorID: Vendor3GPP, FeatureListID: 1, FeatureList: FeatureSharedIFCSets | FeatureAliasIndication}},
	}
}

func answer(result Result) Answer {
	a := answerAsReceived("", result)
	a.SessionID, a.OriginHost, a.OriginRealm = "", "", ""
	return a
}

// avp builds a raw AVP for malformed-message tests.
func avp(s AVPSpec, data []byte) *diameter.AVP {
	return diameter.NewAVP(s.Code, s.Flags, s.VendorID, data)
}
