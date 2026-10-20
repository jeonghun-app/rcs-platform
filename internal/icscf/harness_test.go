package icscf

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Test identities: MCC 001 / MNC 01 and the fictional +1 555 0100 range
// (.github/allowed-test-identifiers.txt).
const (
	home     = "ims.mnc001.mcc001.3gppnetwork.org"
	impu1    = "sip:+15550100001@" + home
	impi1    = "001010000000001@" + home
	tel1     = "tel:+15550100001"
	scscfURI = "sip:scscf.rcs.local:5060;transport=tcp"
)

// stubHSS answers UAR and LIR with whatever its fields say and records the
// requests.
type stubHSS struct {
	mu   sync.Mutex
	uars []*cx.UAR
	lirs []*cx.LIR

	uaa *cx.UAA
	lia *cx.LIA
	err error
	// block, if set, makes a call wait for its ctx and fail with its error,
	// as cxclient does when the request is cancelled.
	block bool
	// entered, if set, is closed when a call starts.
	entered chan struct{}
}

func (h *stubHSS) UAR(ctx context.Context, r *cx.UAR) (*cx.UAA, error) {
	h.mu.Lock()
	h.uars = append(h.uars, r)
	a, err := h.uaa, h.err
	h.mu.Unlock()
	if err := h.wait(ctx); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if a == nil {
		return &cx.UAA{Answer: cx.Answer{Result: cx.ExperimentalResult(cx.FirstRegistration)}}, nil
	}
	return a, nil
}

func (h *stubHSS) LIR(ctx context.Context, r *cx.LIR) (*cx.LIA, error) {
	h.mu.Lock()
	h.lirs = append(h.lirs, r)
	a, err := h.lia, h.err
	h.mu.Unlock()
	if err := h.wait(ctx); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if a == nil {
		return &cx.LIA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultSuccess)}}, nil
	}
	return a, nil
}

func (h *stubHSS) wait(ctx context.Context) error {
	h.mu.Lock()
	if h.entered != nil {
		close(h.entered)
		h.entered = nil
	}
	block := h.block
	h.mu.Unlock()
	if !block {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (h *stubHSS) lastUAR(t *testing.T) *cx.UAR {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.uars) != 1 {
		t.Fatalf("the HSS got %d UARs, want 1", len(h.uars))
	}
	return h.uars[0]
}

func (h *stubHSS) lastLIR(t *testing.T) *cx.LIR {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.lirs) != 1 {
		t.Fatalf("the HSS got %d LIRs, want 1", len(h.lirs))
	}
	return h.lirs[0]
}

func (h *stubHSS) calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.uars) + len(h.lirs)
}

// countingMetrics records counters.
type countingMetrics struct {
	mu     sync.Mutex
	counts map[string]int64
}

func (m *countingMetrics) Count(name string, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = map[string]int64{}
	}
	m.counts[name] += n
}

func (m *countingMetrics) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Sorted(maps.Keys(m.counts))
}

// rig is a Router with a stub HSS and recorded metrics.
type rig struct {
	t       *testing.T
	hss     *stubHSS
	metrics *countingMetrics
	r       *Router
}

func newRig(t *testing.T, mutate ...func(*Config)) *rig {
	t.Helper()
	g := &rig{t: t, hss: &stubHSS{}, metrics: &countingMetrics{}}
	cfg := Config{
		HSS:        g.hss,
		SCSCFs:     []SCSCF{{URI: mustURI(scscfURI)}},
		HomeDomain: home,
		IDs:        sip.IDGenerator{Rand: constantBytes(0xab)},
		Metrics:    g.metrics,
	}
	for _, f := range mutate {
		f(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.r = r
	return g
}

// route runs the Router on m as the proxy hands it over: from the core
// listener, with this I-CSCF's own Route values already removed.
func (g *rig) route(m *sip.Request) proxy.Decision {
	return g.r.Route(context.Background(), &proxy.Request{
		Message: m,
		Source:  transport.Source{Flow: "f1", Network: transport.TCP, Listener: "core"},
	})
}

// constantBytes is a Rand that never runs out, for deterministic tags.
type constantBytes byte

func (c constantBytes) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(c)
	}
	return len(b), nil
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

func mustURI(s string) sip.URI {
	u, err := sip.ParseURI(s)
	if err != nil {
		panic(err)
	}
	return u
}

// request builds a request in wire form and parses it, as the transport would
// deliver it. extra lines replace the default field of the same name; a line
// "Name:" with nothing after it only removes the default.
func request(t *testing.T, method, uri string, extra ...string) *sip.Request {
	t.Helper()
	fields := []string{
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKpcscf-" + method,
		"Max-Forwards: 70",
		"To: <" + impu1 + ">",
		"From: <sip:+15550100002@" + home + ">;tag=f1",
		"Call-ID: call-1@192.0.2.10",
		"CSeq: 1 " + method,
	}
	name := func(f string) string { return strings.ToLower(f[:strings.IndexByte(f, ':')]) }
	fields = slices.DeleteFunc(fields, func(f string) bool {
		return slices.ContainsFunc(extra, func(e string) bool { return name(e) == name(f) })
	})
	for _, e := range extra {
		if strings.TrimSpace(e[strings.IndexByte(e, ':')+1:]) != "" {
			fields = append(fields, e)
		}
	}
	lines := append([]string{method + " " + uri + " SIP/2.0"}, fields...)
	lines = append(lines, "Content-Length: 0")
	m, err := sip.ParseMessage([]byte(strings.Join(lines, "\r\n") + "\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

// register is a REGISTER for impu1 with a binding of an hour.
func register(t *testing.T, extra ...string) *sip.Request {
	t.Helper()
	base := []string{"Contact: <sip:192.0.2.10:5060;transport=tcp>;expires=3600"}
	return request(t, "REGISTER", "sip:"+home, append(base, extra...)...)
}

// invite is an initial INVITE for the user named by uri.
func invite(t *testing.T, uri string, extra ...string) *sip.Request {
	t.Helper()
	return request(t, "INVITE", uri, append([]string{"To: <" + uri + ">"}, extra...)...)
}

// answer describes a Decision in a way tests can compare: the status the
// Router answered with, or "forward" with the target.
type outcome struct {
	status     int
	retryAfter string
	uri        string
	route      string
	timeout    bool
}

func describe(t *testing.T, d proxy.Decision) outcome {
	t.Helper()
	switch {
	case d.Response != nil:
		return outcome{status: d.Response.StatusCode, retryAfter: d.Response.Header.Get("Retry-After")}
	case d.Status != 0:
		return outcome{status: d.Status}
	case len(d.Targets) == 1:
		tg := d.Targets[0]
		o := outcome{uri: tg.URI.String(), timeout: tg.Timeout != 0}
		if len(tg.Routes) > 1 {
			t.Fatalf("target has %d routes, want at most 1", len(tg.Routes))
		}
		if len(tg.Routes) == 1 {
			o.route = tg.Routes[0].URI.String()
		}
		return o
	}
	t.Fatalf("unexpected decision %+v", d)
	return outcome{}
}

func experimental(code uint32) cx.Result { return cx.ExperimentalResult(code) }

func base(code uint32) cx.Result { return cx.ResultCode(code) }
